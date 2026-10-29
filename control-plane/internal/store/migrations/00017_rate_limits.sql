-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and the gateway policy path.
-- Forward-only.
--
-- Per-key rate limits (FR-702): calls per rolling minute and model calls in flight, set at
-- issuance. They bound what budgets and the calls-without-usage cap cannot: calls already in
-- flight when a limit is reached. Failed calls (the gateway or provider answered 4xx/5xx) are
-- recorded so they are neither "in flight" nor "unaccounted" (which counted them against the
-- calls-without-usage cap, 00016); providers normally do not bill errors, so no cost is recorded.
--
-- The limits are checked under the key's row lock on every call, so their cost must not grow with
-- call history: open_calls holds only a key's unsettled model calls (inserted on authorization,
-- deleted when ingest settles the call), and throttle_marks lets only the first rate-limit
-- refusal per key per minute be signed, so a client ignoring retry-after cannot flood the chain.
-- +goose Up

-- Set at issuance through the existing INSERT grant. The server's UPDATE grant on virtual_keys
-- (00014) stays limited to revocation columns, so neither limit can be raised afterwards.
ALTER TABLE virtual_keys
  ADD COLUMN max_requests_per_minute integer NOT NULL DEFAULT 60
    CHECK (max_requests_per_minute BETWEEN 1 AND 6000),
  ADD COLUMN max_calls_in_flight integer NOT NULL DEFAULT 4
    CHECK (max_calls_in_flight BETWEEN 1 AND 100);

-- No person's identifier: a request id, a status and a time. The person is in gateway_calls.
CREATE TABLE failed_calls (
  tenant_id   uuid NOT NULL,
  request_id  uuid NOT NULL,
  status_code integer NOT NULL CHECK (status_code BETWEEN 400 AND 599),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES gateway_calls(tenant_id, request_id)
);
ALTER TABLE failed_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE failed_calls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON failed_calls
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
-- Append-only for the server, like the other call ledgers.
GRANT SELECT, INSERT ON failed_calls TO muistamo_app;
-- The database's time, never the caller's (gateway_stamp_now sets recorded_at for this table).
CREATE TRIGGER failed_calls_stamp BEFORE INSERT ON failed_calls
  FOR EACH ROW EXECUTE FUNCTION gateway_stamp_now();

-- Only model calls are settled by ingest; MCP calls are never recorded here.
-- +goose StatementBegin
CREATE FUNCTION failed_calls_are_model_calls() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM gateway_calls
                  WHERE tenant_id = NEW.tenant_id AND request_id = NEW.request_id AND kind = 'model') THEN
    RAISE EXCEPTION 'failed calls are model calls; % is not one', NEW.request_id;
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER failed_calls_are_model_calls BEFORE INSERT ON failed_calls
  FOR EACH ROW EXECUTE FUNCTION failed_calls_are_model_calls();

-- Unsettled model calls per key: what the in-flight limit and the unaccounted part of the
-- calls-without-usage cap count. The server deletes a row only when ingest settles the call
-- (usage, a missing-usage report or a failure). No person's identifier.
CREATE TABLE open_calls (
  tenant_id     uuid NOT NULL,
  request_id    uuid NOT NULL,
  key_id        uuid NOT NULL,
  authorized_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES gateway_calls(tenant_id, request_id)
);
CREATE INDEX open_calls_key_time ON open_calls(tenant_id, key_id, authorized_at);
-- Calls already unsettled when this migration runs (only the last day can still count). The
-- owner reads every tenant's ledgers with FORCE lifted for these statements, inside this
-- migration's transaction, as in 00011 and 00012; RLS on open_calls is enabled afterwards.
ALTER TABLE gateway_calls NO FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_records NO FORCE ROW LEVEL SECURITY;
ALTER TABLE calls_without_usage NO FORCE ROW LEVEL SECURITY;
INSERT INTO open_calls (tenant_id, request_id, key_id, authorized_at)
  SELECT c.tenant_id, c.request_id, c.key_id, c.authorized_at FROM gateway_calls c
   WHERE c.kind = 'model' AND c.authorized_at > now() - interval '24 hours'
     AND NOT EXISTS (SELECT 1 FROM usage_records u WHERE u.tenant_id = c.tenant_id AND u.request_id = c.request_id)
     AND NOT EXISTS (SELECT 1 FROM calls_without_usage w WHERE w.tenant_id = c.tenant_id AND w.request_id = c.request_id);
ALTER TABLE gateway_calls FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_records FORCE ROW LEVEL SECURITY;
ALTER TABLE calls_without_usage FORCE ROW LEVEL SECURITY;
ALTER TABLE open_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE open_calls FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON open_calls
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, DELETE ON open_calls TO muistamo_app;

-- The calls-without-usage cap counts a key's reports of the last 24 hours.
CREATE INDEX calls_without_usage_time ON calls_without_usage(tenant_id, recorded_at);

-- The first rate-limit refusal of a key in a minute is signed; later ones that minute are logged.
-- No person's identifier.
CREATE TABLE throttle_marks (
  tenant_id    uuid NOT NULL,
  key_id       uuid NOT NULL,
  window_start timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, key_id, window_start)
);
ALTER TABLE throttle_marks ENABLE ROW LEVEL SECURITY;
ALTER TABLE throttle_marks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON throttle_marks
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT ON throttle_marks TO muistamo_app;

-- Recorded spend per key and UTC month of authorization, kept by the database as usage arrives,
-- so the budget check reads one row instead of summing a month of usage under the key lock.
-- Only the trigger writes it (SECURITY DEFINER; the server role can read it), so spend grows
-- only with real usage rows. No person's identifier.
CREATE TABLE key_spend (
  tenant_id uuid NOT NULL,
  key_id    uuid NOT NULL,
  month     date NOT NULL,
  currency  text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  amount    numeric(30,12) NOT NULL CHECK (amount >= 0),
  PRIMARY KEY (tenant_id, key_id, month, currency)
);
-- Spend already recorded when this migration runs, read with FORCE lifted as above.
ALTER TABLE gateway_calls NO FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_records NO FORCE ROW LEVEL SECURITY;
INSERT INTO key_spend (tenant_id, key_id, month, currency, amount)
  SELECT c.tenant_id, c.key_id, (date_trunc('month', c.authorized_at AT TIME ZONE 'UTC'))::date, u.cost_currency, sum(u.cost_amount)
    FROM usage_records u JOIN gateway_calls c USING (tenant_id, request_id)
   GROUP BY 1, 2, 3, 4;
ALTER TABLE gateway_calls FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_records FORCE ROW LEVEL SECURITY;
ALTER TABLE key_spend ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_spend FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON key_spend
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
GRANT SELECT ON key_spend TO muistamo_app;

-- +goose StatementBegin
CREATE FUNCTION key_spend_from_usage() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  INSERT INTO key_spend (tenant_id, key_id, month, currency, amount)
  SELECT c.tenant_id, c.key_id, (date_trunc('month', c.authorized_at AT TIME ZONE 'UTC'))::date, NEW.cost_currency, NEW.cost_amount
    FROM gateway_calls c WHERE c.tenant_id = NEW.tenant_id AND c.request_id = NEW.request_id
  ON CONFLICT (tenant_id, key_id, month, currency) DO UPDATE SET amount = key_spend.amount + EXCLUDED.amount;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION key_spend_from_usage() FROM PUBLIC;
CREATE TRIGGER usage_records_key_spend AFTER INSERT ON usage_records
  FOR EACH ROW EXECUTE FUNCTION key_spend_from_usage();

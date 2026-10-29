-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and the gateway policy path.
-- Forward-only.
--
-- Per-key rate limits (FR-702): calls per rolling minute and model calls in flight, set at
-- issuance. They bound what budgets and the calls-without-usage cap cannot: calls already in
-- flight when a limit is reached. Failed calls (the gateway or provider answered 4xx/5xx) are
-- recorded so they are neither "in flight" nor "unaccounted" (which counted them against the
-- calls-without-usage cap, 00016); providers normally do not bill errors, so no cost is recorded.
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

-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and the gateway policy path.
-- Forward-only.
--
-- When a client aborts a stream, the gateway exports the call (status 200, its request id) but no
-- usage, although the provider bills it (docs/agentgateway-validation-2026-10-28.md, addendum
-- 2026-10-29 (2)). Budgets count recorded usage only, so such calls are recorded here as "ran,
-- usage missing", and a key is refused once it has more than max_calls_without_usage of them in
-- the UTC month (0: refused after the first). No cost is estimated (invariant 8); the cap fails
-- closed (invariant 3).
-- +goose Up

-- Set at issuance through the existing INSERT grant. The server's UPDATE grant on virtual_keys
-- (00014) stays limited to revocation columns, so a key's cap can never be raised afterwards.
ALTER TABLE virtual_keys ADD COLUMN max_calls_without_usage integer NOT NULL DEFAULT 3
  CHECK (max_calls_without_usage BETWEEN 0 AND 1000);

-- No person's identifier: a request id and a time. The person is in gateway_calls.
CREATE TABLE calls_without_usage (
  tenant_id   uuid NOT NULL,
  request_id  uuid NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES gateway_calls(tenant_id, request_id)
);
ALTER TABLE calls_without_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE calls_without_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON calls_without_usage
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
-- Append-only for the server, like the call and usage ledgers.
GRANT SELECT, INSERT ON calls_without_usage TO muistamo_app;
-- The database's time, never the caller's (gateway_stamp_now sets recorded_at for this table).
CREATE TRIGGER calls_without_usage_stamp BEFORE INSERT ON calls_without_usage
  FOR EACH ROW EXECUTE FUNCTION gateway_stamp_now();

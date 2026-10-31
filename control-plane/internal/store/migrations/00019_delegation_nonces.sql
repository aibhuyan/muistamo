-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and token handling.
-- Forward-only.
--
-- Single-use nonces of the knowledge service's signed delegation requests
-- (docs/obo-retrieval-plan.md, PR B). A signature is accepted for five minutes; a nonce seen
-- once is refused for longer than that, so a captured request cannot be replayed inside its
-- window. Rows older than ten minutes are pruned as new ones arrive (registry.UseDelegationNonce);
-- they hold no personal data.
-- +goose Up
CREATE TABLE delegation_nonces (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  nonce     text NOT NULL CHECK (nonce ~ '^[0-9a-f]{32}$'),
  seen_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, nonce)
);
CREATE INDEX delegation_nonces_seen ON delegation_nonces (tenant_id, seen_at);
ALTER TABLE delegation_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE delegation_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON delegation_nonces
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
-- No UPDATE: a nonce is recorded once and only pruning removes it.
GRANT SELECT, INSERT, DELETE ON delegation_nonces TO muistamo_app;

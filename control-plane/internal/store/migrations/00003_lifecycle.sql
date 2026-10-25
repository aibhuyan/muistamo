-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security, and token handling.
-- Forward-only: there is deliberately no Down section.
--
-- HR event intake for joiner and leaver workflows.
--
-- hr_webhook_secrets holds each tenant's HMAC secret as is, because verifying a signature needs
-- the secret itself. Encrypting it under a tenant KMS key is still to do.

-- +goose Up

CREATE TABLE hr_webhook_secrets (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants (id),
  secret     bytea NOT NULL CHECK (length(secret) >= 32),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One row per accepted HR event. The unique key makes re-delivery safe.
CREATE TABLE hr_events (
  tenant_id   uuid NOT NULL REFERENCES tenants (id),
  event_id    text NOT NULL,
  type        text NOT NULL CHECK (type IN ('joiner', 'leaver')),
  person_id   text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  workflow_id text NOT NULL,
  payload     jsonb NOT NULL,
  PRIMARY KEY (tenant_id, event_id)
);

ALTER TABLE hr_webhook_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE hr_webhook_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE hr_events          ENABLE ROW LEVEL SECURITY;
ALTER TABLE hr_events          FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON hr_webhook_secrets
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON hr_events
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The server can read a secret to verify a signature, but never write one.
GRANT SELECT ON hr_webhook_secrets TO muistamo_app;
GRANT SELECT, INSERT ON hr_events TO muistamo_app;

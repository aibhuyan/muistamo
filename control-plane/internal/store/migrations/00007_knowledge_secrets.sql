-- HUMAN REVIEW REQUIRED (CLAUDE.md): a service credential, with row-level security.
-- Forward-only.
--
-- The secret the leaver workflow signs knowledge-service calls with, per tenant (E4.2). The
-- knowledge service holds the same secret; an operator sets both.

-- +goose Up

CREATE TABLE knowledge_service_secrets (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants (id),
  secret     bytea NOT NULL CHECK (length(secret) >= 32),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE knowledge_service_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_service_secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON knowledge_service_secrets
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The worker reads the secret; only an operator command, as owner, writes it.
GRANT SELECT ON knowledge_service_secrets TO muistamo_app;

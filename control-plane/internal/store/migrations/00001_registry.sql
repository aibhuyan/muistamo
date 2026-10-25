-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and row-level security.
-- Forward-only: there is deliberately no Down section.
--
-- Roles: the migrating connection owns every table. muistamo_app is the only role the server
-- uses; it cannot bypass RLS, cannot alter or delete template versions, and can only append to
-- the evidence outbox.

-- +goose Up

-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muistamo_app') THEN
    CREATE ROLE muistamo_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE tenants (
  id         uuid PRIMARY KEY,
  name       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_templates (
  tenant_id      uuid NOT NULL REFERENCES tenants (id),
  name           text NOT NULL,
  latest_version integer NOT NULL CHECK (latest_version >= 1),
  PRIMARY KEY (tenant_id, name)
);

CREATE TABLE agent_template_versions (
  tenant_id  uuid NOT NULL,
  name       text NOT NULL,
  version    integer NOT NULL CHECK (version >= 1),
  digest     text NOT NULL,
  document   jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL,
  PRIMARY KEY (tenant_id, name, version),
  FOREIGN KEY (tenant_id, name) REFERENCES agent_templates (tenant_id, name)
);

CREATE TABLE agent_instances (
  tenant_id        uuid NOT NULL,
  name             text NOT NULL,
  template_name    text NOT NULL,
  template_version integer NOT NULL,
  state            text NOT NULL CHECK (state IN
                     ('requested', 'active', 'under-review', 'suspended', 'retired', 'quarantined')),
  revision         integer NOT NULL CHECK (revision >= 1),
  document         jsonb NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name),
  FOREIGN KEY (tenant_id, template_name, template_version)
    REFERENCES agent_template_versions (tenant_id, name, version)
);

-- Pending evidence. The evidence-log task chains and signs these; nothing here is hashed yet.
CREATE TABLE evidence_outbox (
  id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  actor        text NOT NULL,
  action       text NOT NULL,
  subject_kind text NOT NULL,
  subject_name text NOT NULL,
  before       jsonb,
  after        jsonb,
  request_id   text NOT NULL
);

ALTER TABLE agent_templates         ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_templates         FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_template_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_template_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE agent_instances         ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_instances         FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_outbox         ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_outbox         FORCE ROW LEVEL SECURITY;

-- current_setting(..., true) is NULL when unset, so a connection without a tenant matches no rows.
CREATE POLICY tenant_isolation ON agent_templates
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON agent_template_versions
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON agent_instances
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON evidence_outbox
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- tenants carries no RLS: the app role can only check that a tenant id exists.
GRANT SELECT (id) ON tenants TO muistamo_app;
GRANT SELECT, INSERT, UPDATE ON agent_templates TO muistamo_app;
GRANT SELECT, INSERT ON agent_template_versions TO muistamo_app;
GRANT SELECT, INSERT, UPDATE ON agent_instances TO muistamo_app;
GRANT INSERT ON evidence_outbox TO muistamo_app;

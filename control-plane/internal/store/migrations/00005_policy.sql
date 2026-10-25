-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and row-level security for the gateway's
-- policy path. Forward-only.
--
-- Agent links and action policies (FR-1003, FR-1004). Both kinds live in one table: the policy
-- engine always loads a tenant's whole set and compiles it to Cedar. Every change is evidenced in
-- the same transaction, so the stored rules never differ from the recorded history.

-- +goose Up

CREATE TABLE policy_documents (
  tenant_id  uuid NOT NULL REFERENCES tenants (id),
  kind       text NOT NULL CHECK (kind IN ('AgentLink', 'ActionPolicy')),
  name       text NOT NULL,
  -- ActionPolicy: spec.appliesTo.template. NULL for links.
  template   text,
  revision   integer NOT NULL CHECK (revision >= 1),
  digest     text NOT NULL,
  document   jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL,
  PRIMARY KEY (tenant_id, kind, name),
  CHECK ((kind = 'ActionPolicy') = (template IS NOT NULL))
);

-- At most one action policy applies to a template, so its default and mode are unambiguous.
CREATE UNIQUE INDEX policy_documents_one_policy_per_template
  ON policy_documents (tenant_id, template) WHERE kind = 'ActionPolicy';

ALTER TABLE policy_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_documents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON policy_documents
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON policy_documents TO muistamo_app;

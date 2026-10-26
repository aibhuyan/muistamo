-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and row-level security. Forward-only.
--
-- Clones (FR-103): template variants with their own instances. A clone's template never
-- changes; which template version it uses is resolved from its sync policy (follow the published
-- version, pin one, or a manually synced one stored here).

-- +goose Up

CREATE TABLE agent_clones (
  tenant_id      uuid NOT NULL,
  name           text NOT NULL,
  template       text NOT NULL,
  sync           text NOT NULL CHECK (sync IN ('follow', 'pin', 'manual')),
  -- manual clones only: the template version last synced to.
  synced_version integer CHECK (synced_version >= 1),
  revision       integer NOT NULL CHECK (revision >= 1),
  digest         text NOT NULL,
  document       jsonb NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  updated_by     text NOT NULL,
  PRIMARY KEY (tenant_id, name),
  FOREIGN KEY (tenant_id, template) REFERENCES agent_templates (tenant_id, name),
  CHECK ((sync = 'manual') = (synced_version IS NOT NULL))
);

ALTER TABLE agent_clones ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_clones FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON agent_clones
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON agent_clones TO muistamo_app;

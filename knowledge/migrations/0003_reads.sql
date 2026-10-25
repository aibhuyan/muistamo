-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and row-level security.
-- Forward-only.
--
-- Knowledge reads per person (PRD section 8.3): when an assistant's model calls bypass the
-- gateway, these rows keep value metrics measurable. A read records what was cited, never the
-- query text, which can contain personal data (invariant 5).

CREATE TABLE knowledge.reads (
  tenant_id    uuid NOT NULL REFERENCES knowledge.tenants (id),
  id           uuid NOT NULL,
  person       text NOT NULL,
  at           timestamptz NOT NULL DEFAULT now(),
  tool         text NOT NULL CHECK (tool IN ('rest.retrieve', 'mcp.search_knowledge')),
  result_count integer NOT NULL CHECK (result_count >= 0),
  citations    jsonb NOT NULL,
  PRIMARY KEY (tenant_id, id)
);
CREATE INDEX reads_person ON knowledge.reads (tenant_id, person, at DESC);

ALTER TABLE knowledge.reads ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.reads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON knowledge.reads
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT, INSERT ON knowledge.reads TO muistamo_knowledge_app;

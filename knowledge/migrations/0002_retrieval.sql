-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and row-level security.
-- Forward-only.
--
-- Document sources attached to packs, and the index of their documents. The index is only a
-- candidate list: nothing in it is returned to anyone without a live, per-person authorisation
-- call to the source's connector (invariant 1).
--
-- Residency gap (FR-308, flagged): indexed document text is stored here, not yet in
-- customer-bound storage.

CREATE TABLE knowledge.sources (
  tenant_id      uuid NOT NULL REFERENCES knowledge.tenants (id),
  name           text NOT NULL,
  pack           text NOT NULL,
  connector      text NOT NULL CHECK (connector IN ('sharepoint', 'test')),
  document       jsonb NOT NULL,
  last_synced_at timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name),
  FOREIGN KEY (tenant_id, pack) REFERENCES knowledge.packs (tenant_id, name)
);

CREATE TABLE knowledge.documents (
  tenant_id   uuid NOT NULL,
  source      text NOT NULL,
  external_id text NOT NULL,
  title       text NOT NULL,
  url         text,
  body        text NOT NULL,
  modified_at timestamptz,
  indexed_at  timestamptz NOT NULL DEFAULT now(),
  tsv         tsvector GENERATED ALWAYS AS (to_tsvector('simple', title || ' ' || body)) STORED,
  PRIMARY KEY (tenant_id, source, external_id),
  FOREIGN KEY (tenant_id, source) REFERENCES knowledge.sources (tenant_id, name)
);
CREATE INDEX documents_tsv ON knowledge.documents USING gin (tsv);

ALTER TABLE knowledge.sources   ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.sources   FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.documents FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON knowledge.sources
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON knowledge.documents
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT, INSERT, UPDATE ON knowledge.sources TO muistamo_knowledge_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON knowledge.documents TO muistamo_knowledge_app;

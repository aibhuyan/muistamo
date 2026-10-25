-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security, and the evidence chain.
-- Forward-only. Applied by `python -m muistamo_knowledge migrate` as the schema owner.
--
-- The knowledge service owns the `knowledge` schema and nothing else. Its server role
-- (muistamo_knowledge_app) has no privileges outside it, and the control plane's role has none
-- inside it.
--
-- Residency gap (FR-308, flagged): entry bodies are stored here, not yet in customer-bound
-- object storage.

CREATE SCHEMA knowledge;

-- Tenants this service accepts requests for. Registered by an operator; later fed by the
-- control plane. An unregistered tenant is refused, never given an empty space.
CREATE TABLE knowledge.tenants (
  id         uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge.packs (
  tenant_id      uuid NOT NULL REFERENCES knowledge.tenants (id),
  name           text NOT NULL,
  layer          text NOT NULL CHECK (layer IN ('company', 'role', 'team')),
  mandatory      boolean NOT NULL DEFAULT false,
  reviewers      text[] NOT NULL CHECK (cardinality(reviewers) >= 1),
  requires_eval  boolean NOT NULL DEFAULT false,
  document       jsonb NOT NULL,
  latest_version text NOT NULL DEFAULT '0.0.0',
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name)
);

-- Immutable entry revisions. An edit at review time creates a new revision.
CREATE TABLE knowledge.entries (
  tenant_id   uuid NOT NULL REFERENCES knowledge.tenants (id),
  id          uuid NOT NULL,
  key         text NOT NULL,
  type        text NOT NULL CHECK (type IN ('skill', 'fact', 'example')),
  title       text NOT NULL,
  body        text NOT NULL,
  source      text,
  data_class  text NOT NULL CHECK (data_class IN ('public', 'internal', 'confidential')),
  contributor text NOT NULL,
  derived_from uuid,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

-- Each person's personal layer: visible to that person only (enforced in the service and tested
-- adversarially; RLS isolates tenants).
CREATE TABLE knowledge.personal_entries (
  tenant_id uuid NOT NULL,
  owner     text NOT NULL,
  entry_id  uuid NOT NULL,
  PRIMARY KEY (tenant_id, entry_id),
  FOREIGN KEY (tenant_id, entry_id) REFERENCES knowledge.entries (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX personal_entries_owner ON knowledge.personal_entries (tenant_id, owner);

CREATE TABLE knowledge.pack_versions (
  tenant_id  uuid NOT NULL,
  pack       text NOT NULL,
  version    text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
  parent     text,
  reason     text NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, pack, version),
  FOREIGN KEY (tenant_id, pack) REFERENCES knowledge.packs (tenant_id, name)
);

CREATE TABLE knowledge.proposals (
  tenant_id     uuid NOT NULL,
  id            uuid NOT NULL,
  pack          text NOT NULL,
  contributor   text NOT NULL,
  summary       text NOT NULL,
  status        text NOT NULL CHECK (status IN ('checks-failed', 'in-review', 'approved', 'rejected')),
  checks        jsonb NOT NULL,
  reviewer      text,
  decision      text CHECK (decision IN ('approve', 'reject')),
  reason        text,
  decided_at    timestamptz,
  merged_version text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, pack) REFERENCES knowledge.packs (tenant_id, name)
);

CREATE TABLE knowledge.proposal_entries (
  tenant_id   uuid NOT NULL,
  proposal_id uuid NOT NULL,
  entry_id    uuid NOT NULL,
  PRIMARY KEY (tenant_id, proposal_id, entry_id),
  FOREIGN KEY (tenant_id, proposal_id) REFERENCES knowledge.proposals (tenant_id, id),
  FOREIGN KEY (tenant_id, entry_id) REFERENCES knowledge.entries (tenant_id, id)
);

-- A version's content: which entry revision holds each key, and its lineage.
CREATE TABLE knowledge.pack_version_entries (
  tenant_id   uuid NOT NULL,
  pack        text NOT NULL,
  version     text NOT NULL,
  key         text NOT NULL,
  entry_id    uuid NOT NULL,
  proposal_id uuid NOT NULL,
  reviewer    text NOT NULL,
  PRIMARY KEY (tenant_id, pack, version, key),
  FOREIGN KEY (tenant_id, pack, version) REFERENCES knowledge.pack_versions (tenant_id, pack, version),
  FOREIGN KEY (tenant_id, entry_id) REFERENCES knowledge.entries (tenant_id, id),
  FOREIGN KEY (tenant_id, proposal_id) REFERENCES knowledge.proposals (tenant_id, id)
);

-- Evidence: same shape and append-only rule as the control plane's chain.
CREATE TABLE knowledge.evidence_signing_keys (
  key_id     text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{32}$'),
  algorithm  text NOT NULL CHECK (algorithm = 'ed25519'),
  public_key bytea NOT NULL UNIQUE CHECK (length(public_key) = 32),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge.evidence_heads (
  tenant_id uuid PRIMARY KEY REFERENCES knowledge.tenants (id),
  seq       bigint NOT NULL CHECK (seq >= 0),
  hash      text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE knowledge.evidence_events (
  tenant_id    uuid NOT NULL REFERENCES knowledge.tenants (id),
  seq          bigint NOT NULL CHECK (seq >= 1),
  occurred_at  timestamptz NOT NULL,
  actor        text NOT NULL,
  action       text NOT NULL,
  subject_kind text NOT NULL,
  subject_name text NOT NULL,
  before       jsonb,
  after        jsonb,
  request_id   text NOT NULL,
  prev_hash    text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash         text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  key_id       text NOT NULL REFERENCES knowledge.evidence_signing_keys (key_id),
  signature    text NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

CREATE FUNCTION knowledge.evidence_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'evidence_events is append-only';
END
$$;
CREATE TRIGGER evidence_events_append_only BEFORE UPDATE OR DELETE ON knowledge.evidence_events
  FOR EACH ROW EXECUTE FUNCTION knowledge.evidence_events_append_only();
CREATE TRIGGER evidence_events_no_truncate BEFORE TRUNCATE ON knowledge.evidence_events
  FOR EACH STATEMENT EXECUTE FUNCTION knowledge.evidence_events_append_only();

-- Row-level security on every tenant table.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['tenants', 'packs', 'entries', 'personal_entries', 'pack_versions',
                           'proposals', 'proposal_entries', 'pack_version_entries',
                           'evidence_heads', 'evidence_events'] LOOP
    EXECUTE format('ALTER TABLE knowledge.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE knowledge.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON knowledge.%I USING (%s = current_setting(''muistamo.tenant_id'', true)::uuid)'
      ' WITH CHECK (%s = current_setting(''muistamo.tenant_id'', true)::uuid)',
      t, CASE WHEN t = 'tenants' THEN 'id' ELSE 'tenant_id' END,
         CASE WHEN t = 'tenants' THEN 'id' ELSE 'tenant_id' END);
  END LOOP;
END
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'muistamo_knowledge_app') THEN
    CREATE ROLE muistamo_knowledge_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA knowledge TO muistamo_knowledge_app;
GRANT SELECT ON knowledge.tenants, knowledge.evidence_signing_keys TO muistamo_knowledge_app;
GRANT SELECT, INSERT, UPDATE ON knowledge.packs, knowledge.proposals, knowledge.evidence_heads TO muistamo_knowledge_app;
GRANT SELECT, INSERT, DELETE ON knowledge.entries, knowledge.personal_entries TO muistamo_knowledge_app;
GRANT SELECT, INSERT ON knowledge.pack_versions, knowledge.pack_version_entries,
  knowledge.proposal_entries, knowledge.evidence_events TO muistamo_knowledge_app;

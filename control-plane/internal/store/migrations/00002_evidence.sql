-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and the evidence chain.
-- Forward-only: there is deliberately no Down section.
--
-- Replaces the unsigned evidence_outbox with a signed, hash-chained log: one chain per tenant,
-- format defined in control-plane/evidencechain. evidence_outbox was never deployed and holds
-- no data anywhere, so it is dropped rather than migrated. (Destructive statement, flagged.)

-- +goose Up

DROP TABLE evidence_outbox;

-- Platform signing keys. Public halves only; private keys never enter the database.
CREATE TABLE evidence_signing_keys (
  key_id     text PRIMARY KEY CHECK (key_id ~ '^[0-9a-f]{32}$'),
  algorithm  text NOT NULL CHECK (algorithm = 'ed25519'),
  public_key bytea NOT NULL UNIQUE CHECK (length(public_key) = 32),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- The latest event of each tenant's chain. Locked by every append, which keeps seq gap-free.
CREATE TABLE evidence_heads (
  tenant_id uuid PRIMARY KEY REFERENCES tenants (id),
  seq       bigint NOT NULL CHECK (seq >= 0),
  hash      text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE evidence_events (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
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
  key_id       text NOT NULL REFERENCES evidence_signing_keys (key_id),
  signature    text NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

-- Append-only for every role, the owner included. An owner can still drop this trigger, which is
-- why the chain is verifiable offline: tampering is detected even when it cannot be prevented.
-- +goose StatementBegin
CREATE FUNCTION evidence_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'evidence_events is append-only';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER evidence_events_append_only
  BEFORE UPDATE OR DELETE ON evidence_events
  FOR EACH ROW EXECUTE FUNCTION evidence_events_append_only();
CREATE TRIGGER evidence_events_no_truncate
  BEFORE TRUNCATE ON evidence_events
  FOR EACH STATEMENT EXECUTE FUNCTION evidence_events_append_only();

ALTER TABLE evidence_heads  ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_heads  FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_events FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON evidence_heads
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON evidence_events
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT ON evidence_signing_keys TO muistamo_app;
GRANT SELECT, INSERT, UPDATE ON evidence_heads TO muistamo_app;
GRANT SELECT, INSERT ON evidence_events TO muistamo_app;

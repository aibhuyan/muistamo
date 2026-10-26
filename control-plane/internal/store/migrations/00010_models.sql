-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and row-level security, and the approval
-- state that decides which models agents may run on. Forward-only.
--
-- The model catalogue (FR-601), aliases (FR-602) and rollouts (E5.1). A catalogue model is
-- usable only once a privacy officer approves it; any change to it resets approval. An alias
-- targets one catalogue model and changes target only through a rollout, which records that no
-- evaluation was run until the gateway exists (FR-603).

-- +goose Up

CREATE TABLE model_catalogue (
  tenant_id       uuid NOT NULL REFERENCES tenants (id),
  name            text NOT NULL,
  revision        integer NOT NULL CHECK (revision >= 1),
  digest          text NOT NULL,
  document        jsonb NOT NULL,
  approval_status text NOT NULL CHECK (approval_status IN ('pending', 'approved', 'rejected', 'revoked')),
  decided_by      text,
  decision_reason text,
  decided_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  updated_by      text NOT NULL,
  PRIMARY KEY (tenant_id, name),
  CHECK ((approval_status = 'pending') = (decided_by IS NULL)),
  -- Nobody approves their own change. Erasure maps all of a subject's identities to one
  -- pseudonym, so two erased identities may coincide; refusing that would make erasure fail.
  CHECK (decided_by IS DISTINCT FROM updated_by OR decided_by LIKE 'erased:%')
);

CREATE TABLE model_aliases (
  tenant_id  uuid NOT NULL,
  name       text NOT NULL,
  target     text NOT NULL,
  revision   integer NOT NULL CHECK (revision >= 1),
  digest     text NOT NULL,
  document   jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL,
  PRIMARY KEY (tenant_id, name),
  FOREIGN KEY (tenant_id, target) REFERENCES model_catalogue (tenant_id, name)
);

CREATE TABLE rollouts (
  tenant_id       uuid NOT NULL,
  id              uuid NOT NULL,
  alias           text NOT NULL,
  from_model      text NOT NULL,
  to_model        text NOT NULL,
  strategy        text NOT NULL CHECK (strategy = 'immediate'),
  evaluation      jsonb NOT NULL,
  status          text NOT NULL CHECK (status IN ('completed', 'rolled-back')),
  reason          text NOT NULL,
  created_by      text NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  rolled_back_by  text,
  rolled_back_at  timestamptz,
  rollback_reason text,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, alias) REFERENCES model_aliases (tenant_id, name),
  FOREIGN KEY (tenant_id, from_model) REFERENCES model_catalogue (tenant_id, name),
  FOREIGN KEY (tenant_id, to_model) REFERENCES model_catalogue (tenant_id, name),
  CHECK ((status = 'rolled-back') = (rolled_back_at IS NOT NULL))
);

ALTER TABLE model_catalogue ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_catalogue FORCE ROW LEVEL SECURITY;
ALTER TABLE model_aliases ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_aliases FORCE ROW LEVEL SECURITY;
ALTER TABLE rollouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE rollouts FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON model_catalogue
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON model_aliases
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON rollouts
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- No DELETE: models, aliases and rollouts are history the evidence refers to.
GRANT SELECT, INSERT, UPDATE ON model_catalogue, model_aliases, rollouts TO muistamo_app;

-- Erasure (00006) must reach these tables and agent_clones (00008) too: redefine erase_subject.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION erase_subject(subject_values text[], pseudonym text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  t      uuid := nullif(current_setting('muistamo.tenant_id', true), '')::uuid;
  counts jsonb := '{}'::jsonb;
  n      bigint;
  total  bigint;
  v      text;
  needle text;
  repl   text := to_jsonb(pseudonym)::text;
BEGIN
  IF t IS NULL THEN
    RAISE EXCEPTION 'erase_subject: no tenant is set';
  END IF;
  IF pseudonym IS NULL OR pseudonym !~ '^erased:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'erase_subject: pseudonym must be erased:<uuid>';
  END IF;
  IF subject_values IS NULL OR cardinality(subject_values) = 0
     OR EXISTS (SELECT 1 FROM unnest(subject_values) s WHERE s IS NULL OR length(s) < 3) THEN
    RAISE EXCEPTION 'erase_subject: subject values must be non-empty strings of at least 3 characters';
  END IF;

  -- Identity columns.
  UPDATE agent_template_versions SET created_by = pseudonym WHERE tenant_id = t AND created_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('agent_template_versions.created_by', n);
  UPDATE catalogue_requests SET requested_by = pseudonym WHERE tenant_id = t AND requested_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('catalogue_requests.requested_by', n);
  UPDATE catalogue_approvals SET approver = pseudonym WHERE tenant_id = t AND approver = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('catalogue_approvals.approver', n);
  UPDATE policy_documents SET updated_by = pseudonym WHERE tenant_id = t AND updated_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('policy_documents.updated_by', n);
  UPDATE agent_clones SET updated_by = pseudonym WHERE tenant_id = t AND updated_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('agent_clones.updated_by', n);
  -- decided_by first: the row check forbids decided_by = updated_by, and the person is never both.
  UPDATE model_catalogue SET decided_by = pseudonym WHERE tenant_id = t AND decided_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('model_catalogue.decided_by', n);
  UPDATE model_catalogue SET updated_by = pseudonym WHERE tenant_id = t AND updated_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('model_catalogue.updated_by', n);
  UPDATE model_aliases SET updated_by = pseudonym WHERE tenant_id = t AND updated_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('model_aliases.updated_by', n);
  UPDATE rollouts SET created_by = pseudonym WHERE tenant_id = t AND created_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('rollouts.created_by', n);
  UPDATE rollouts SET rolled_back_by = pseudonym WHERE tenant_id = t AND rolled_back_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('rollouts.rolled_back_by', n);
  UPDATE erasure_requests SET requested_by = pseudonym WHERE tenant_id = t AND requested_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('erasure_requests.requested_by', n);

  -- Roles the person held.
  DELETE FROM catalogue_approvers WHERE tenant_id = t AND approver = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('catalogue_approvers', n);
  DELETE FROM privacy_officers WHERE tenant_id = t AND officer = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('privacy_officers', n);

  -- Documents: every JSON string value equal to an identifier. Matching the quoted JSON form
  -- replaces whole values only, never part of a longer string.
  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE agent_instances SET document = replace(document::text, needle, repl)::jsonb,
      revision = revision + 1, updated_at = now()
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('agent_instances.document', total);

  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE hr_events SET payload = replace(payload::text, needle, repl)::jsonb
      WHERE tenant_id = t AND strpos(payload::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('hr_events.payload', total);

  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE agent_template_versions SET document = replace(document::text, needle, repl)::jsonb
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('agent_template_versions.document', total);

  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE policy_documents SET document = replace(document::text, needle, repl)::jsonb,
      revision = revision + 1, updated_at = now()
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('policy_documents.document', total);

  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE agent_clones SET document = replace(document::text, needle, repl)::jsonb,
      revision = revision + 1, updated_at = now()
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    UPDATE model_catalogue SET document = replace(document::text, needle, repl)::jsonb,
      revision = revision + 1, updated_at = now()
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
    UPDATE model_aliases SET document = replace(document::text, needle, repl)::jsonb,
      revision = revision + 1, updated_at = now()
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('clone_and_model_documents', total);

  RETURN counts;
END
$$;
-- +goose StatementEnd

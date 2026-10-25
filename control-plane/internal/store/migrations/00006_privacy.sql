-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and a deletion path.
-- Forward-only.
--
-- Erasure and access requests (FR-309, GDPR Arts 15-17). The server's role still cannot rewrite
-- history columns such as template authorship: the only way it can is erase_subject below,
-- which replaces exact values with a pseudonym of a fixed form, in the caller's tenant only.
-- Evidence events are never touched (retained under Art 17(3); the proof says so).

-- +goose Up

CREATE TABLE privacy_officers (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  officer   text NOT NULL,
  PRIMARY KEY (tenant_id, officer)
);

-- One row per completed erasure. It never holds the person's identifiers: subject_digest lets
-- someone who knows them confirm which person a proof is about.
CREATE TABLE erasure_requests (
  tenant_id      uuid NOT NULL REFERENCES tenants (id),
  id             uuid NOT NULL,
  subject_digest text NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
  requested_by   text NOT NULL,
  reason         text NOT NULL,
  proof          jsonb NOT NULL,
  completed_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

ALTER TABLE privacy_officers ENABLE ROW LEVEL SECURITY;
ALTER TABLE privacy_officers FORCE ROW LEVEL SECURITY;
ALTER TABLE erasure_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE erasure_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON privacy_officers
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON erasure_requests
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The server reads officers but never edits them (an operator command does, as owner).
GRANT SELECT ON privacy_officers TO muistamo_app;
GRANT SELECT, INSERT ON erasure_requests TO muistamo_app;

-- erase_subject replaces every exact occurrence of the person's identifiers in the caller's
-- tenant with pseudonym, and removes them from approver and officer lists. It runs as the table
-- owner, who may bypass row-level security (a superuser in development), so every statement
-- names the tenant explicitly and the function refuses to run without one. It returns the
-- number of rows changed per location.
-- +goose StatementBegin
CREATE FUNCTION erase_subject(subject_values text[], pseudonym text) RETURNS jsonb
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

  RETURN counts;
END
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION erase_subject(text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_subject(text[], text) TO muistamo_app;

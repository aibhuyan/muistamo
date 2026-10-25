-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and a deletion path.
-- Forward-only.
--
-- Erasure and access requests (FR-309, GDPR Arts 15-17). The server's role still cannot update
-- entries, pack versions or their lineage: the only way it can is knowledge.erase_subject
-- below, which deletes the person's own layer and reads, replaces their identifiers with a
-- pseudonym of a fixed form, and redacts named entries, in the caller's tenant only. Evidence
-- events are never touched (retained under Art 17(3); the proof says so).

CREATE TABLE knowledge.privacy_officers (
  tenant_id uuid NOT NULL REFERENCES knowledge.tenants (id),
  officer   text NOT NULL,
  PRIMARY KEY (tenant_id, officer)
);

-- One row per completed erasure. It never holds the person's identifiers.
CREATE TABLE knowledge.erasure_requests (
  tenant_id      uuid NOT NULL REFERENCES knowledge.tenants (id),
  id             uuid NOT NULL,
  subject_digest text NOT NULL CHECK (subject_digest ~ '^[0-9a-f]{64}$'),
  requested_by   text NOT NULL,
  reason         text NOT NULL,
  proof          jsonb NOT NULL,
  completed_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

ALTER TABLE knowledge.privacy_officers ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.privacy_officers FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.erasure_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.erasure_requests FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON knowledge.privacy_officers
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON knowledge.erasure_requests
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT ON knowledge.privacy_officers TO muistamo_knowledge_app;
GRANT SELECT, INSERT ON knowledge.erasure_requests TO muistamo_knowledge_app;

-- erase_subject runs as the schema owner, who may bypass row-level security (a superuser in
-- development), so every statement names the tenant explicitly and the function refuses to run
-- without one. Redaction runs first, so a named personal entry still redacts the proposal copies
-- derived from it before the personal layer is deleted. It returns rows changed per location.
CREATE FUNCTION knowledge.erase_subject(subject_values text[], pseudonym text, redact uuid[])
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = knowledge, pg_temp AS $$
DECLARE
  t      uuid := nullif(current_setting('muistamo.tenant_id', true), '')::uuid;
  counts jsonb := '{}'::jsonb;
  n      bigint;
  total  bigint;
  v      text;
  needle text;
  repl   text := to_jsonb(pseudonym)::text;
  personal uuid[];
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

  -- Redaction of named entries and every revision derived from them.
  IF redact IS NOT NULL AND cardinality(redact) > 0 THEN
    IF EXISTS (SELECT 1 FROM unnest(redact) r
               WHERE NOT EXISTS (SELECT 1 FROM entries e WHERE e.tenant_id = t AND e.id = r)) THEN
      RAISE EXCEPTION 'erase_subject: an entry named for redaction does not exist';
    END IF;
    WITH RECURSIVE lineage AS (
      SELECT id FROM entries WHERE tenant_id = t AND id = ANY (redact)
      UNION
      SELECT e.id FROM entries e JOIN lineage l ON e.derived_from = l.id WHERE e.tenant_id = t
    )
    UPDATE entries SET title = '[erased]', body = '[erased]', source = NULL
      WHERE tenant_id = t AND id IN (SELECT id FROM lineage);
    GET DIAGNOSTICS n = ROW_COUNT;
  ELSE
    n := 0;
  END IF;
  counts := counts || jsonb_build_object('entries.redacted', n);

  -- The person's own layer and their reads.
  WITH gone AS (
    DELETE FROM personal_entries WHERE tenant_id = t AND owner = ANY (subject_values) RETURNING entry_id
  )
  SELECT coalesce(array_agg(entry_id), '{}') INTO personal FROM gone;
  counts := counts || jsonb_build_object('personal_entries', cardinality(personal));
  -- Proposals hold their own copies, so nothing else should reference a personal entry; the
  -- checks keep a lineage reference from blocking the erasure if one ever does.
  DELETE FROM entries WHERE tenant_id = t AND id = ANY (personal)
    AND NOT EXISTS (SELECT 1 FROM proposal_entries p WHERE p.tenant_id = t AND p.entry_id = entries.id)
    AND NOT EXISTS (SELECT 1 FROM pack_version_entries v WHERE v.tenant_id = t AND v.entry_id = entries.id);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('entries.personal', n);
  DELETE FROM reads WHERE tenant_id = t AND person = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('reads', n);

  -- Attribution kept for lineage, under the pseudonym.
  UPDATE entries SET contributor = pseudonym WHERE tenant_id = t AND contributor = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('entries.contributor', n);
  UPDATE proposals SET contributor = pseudonym WHERE tenant_id = t AND contributor = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('proposals.contributor', n);
  UPDATE proposals SET reviewer = pseudonym WHERE tenant_id = t AND reviewer = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('proposals.reviewer', n);
  UPDATE pack_versions SET created_by = pseudonym WHERE tenant_id = t AND created_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('pack_versions.created_by', n);
  UPDATE pack_version_entries SET reviewer = pseudonym WHERE tenant_id = t AND reviewer = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('pack_version_entries.reviewer', n);
  UPDATE erasure_requests SET requested_by = pseudonym WHERE tenant_id = t AND requested_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('erasure_requests.requested_by', n);
  DELETE FROM privacy_officers WHERE tenant_id = t AND officer = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('privacy_officers', n);

  -- Reviewer lists and documents: whole values only.
  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE packs SET reviewers = array_replace(reviewers, v, pseudonym),
      document = replace(document::text, needle, repl)::jsonb, updated_at = now()
      WHERE tenant_id = t AND (v = ANY (reviewers) OR strpos(document::text, needle) > 0);
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('packs', total);

  total := 0;
  FOREACH v IN ARRAY subject_values LOOP
    needle := to_jsonb(v)::text;
    UPDATE sources SET document = replace(document::text, needle, repl)::jsonb, updated_at = now()
      WHERE tenant_id = t AND strpos(document::text, needle) > 0;
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END LOOP;
  counts := counts || jsonb_build_object('sources.document', total);

  RETURN counts;
END
$$;

REVOKE ALL ON FUNCTION knowledge.erase_subject(text[], text, uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION knowledge.erase_subject(text[], text, uuid[]) TO muistamo_knowledge_app;

-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and the erasure path.
-- Forward-only.
--
-- Live leaver reviews ordered by HR generation (docs/live-review-plan.md). The fence is the
-- highest HR generation the control plane has sent for a person. A review call from an earlier
-- generation is refused and changes nothing, so a late call from a leaving cannot freeze, expose
-- or purge the layer of a person who has since been rehired. The fence outlives the reviews it
-- orders; only erasure of the person removes it.

CREATE TABLE knowledge.leaver_review_fences (
  tenant_id  uuid NOT NULL REFERENCES knowledge.tenants (id),
  person     text NOT NULL CHECK (person ~ '^entra:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
  generation bigint NOT NULL CHECK (generation > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, person)
);

-- A fence only moves forward, and always for the same person.
CREATE FUNCTION knowledge.leaver_review_fence_forward() RETURNS trigger
LANGUAGE plpgsql SET search_path = knowledge, pg_temp AS $$
BEGIN
  IF NEW.tenant_id <> OLD.tenant_id OR NEW.person <> OLD.person THEN
    RAISE EXCEPTION 'leaver_review_fences: a fence belongs to one person';
  END IF;
  IF NEW.generation < OLD.generation THEN
    RAISE EXCEPTION 'leaver_review_fences: a fence never moves back (% to %)', OLD.generation, NEW.generation;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER leaver_review_fence_forward BEFORE UPDATE ON knowledge.leaver_review_fences
  FOR EACH ROW EXECUTE FUNCTION knowledge.leaver_review_fence_forward();

ALTER TABLE knowledge.leaver_review_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.leaver_review_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON knowledge.leaver_review_fences
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- No DELETE: the server cannot remove a fence. Erasure does, through erase_subject.
GRANT SELECT, INSERT, UPDATE ON knowledge.leaver_review_fences TO muistamo_knowledge_app;

-- The generation a live review was opened at; NULL for a legacy (simulated-mode) review.
ALTER TABLE knowledge.leaver_reviews
  ADD COLUMN generation bigint CHECK (generation IS NULL OR generation > 0);

-- Erasure (0004, 0005, 0007) must reach the fence too: redefine erase_subject with it.
CREATE OR REPLACE FUNCTION knowledge.erase_subject(subject_values text[], pseudonym text, redact uuid[])
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
  UPDATE verifications SET verified_by = pseudonym WHERE tenant_id = t AND verified_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('verifications.verified_by', n);
  UPDATE proposals SET proposed_by = pseudonym WHERE tenant_id = t AND proposed_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('proposals.proposed_by', n);
  UPDATE leaver_reviews SET person = pseudonym WHERE tenant_id = t AND person = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('leaver_reviews.person', n);
  -- A decider who is erased leaves the review to the privacy officers.
  UPDATE leaver_reviews SET decider = NULL, decider_kind = 'privacy-officers'
    WHERE tenant_id = t AND decider = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('leaver_reviews.decider', n);
  UPDATE erasure_requests SET requested_by = pseudonym WHERE tenant_id = t AND requested_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('erasure_requests.requested_by', n);
  DELETE FROM privacy_officers WHERE tenant_id = t AND officer = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('privacy_officers', n);
  -- The person's leaver-review fence (0010): an ordering record, kept until the person is erased.
  DELETE FROM leaver_review_fences WHERE tenant_id = t AND person = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('leaver_review_fences', n);

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

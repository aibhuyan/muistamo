-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and the erasure path.
-- Forward-only.
--
-- Decay (FR-307). A pack entry is trusted for as long as a reviewer last confirmed it: approving
-- the proposal that merged it, confirming it again later, or rolling a pack back to bring it back.
-- Each confirmation is a row here, never updated or deleted by the server, so the history of who
-- vouched for an entry, and when, is kept.

CREATE TABLE knowledge.verifications (
  tenant_id   uuid NOT NULL REFERENCES knowledge.tenants (id),
  id          uuid NOT NULL,
  pack        text NOT NULL,
  entry_id    uuid NOT NULL,
  verified_at timestamptz NOT NULL,
  verified_by text NOT NULL,
  reason      text NOT NULL,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, pack) REFERENCES knowledge.packs (tenant_id, name),
  FOREIGN KEY (tenant_id, entry_id) REFERENCES knowledge.entries (tenant_id, id)
);
CREATE INDEX verifications_latest ON knowledge.verifications (tenant_id, pack, entry_id, verified_at DESC);

ALTER TABLE knowledge.verifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.verifications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON knowledge.verifications
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

GRANT SELECT, INSERT ON knowledge.verifications TO muistamo_knowledge_app;

-- Every published revision, including historical versions, was verified by its approving reviewer.
-- Backfill each revision once, even if it appears in several versions.
--
-- Every source table forces row-level security, and no tenant is set here. Filtering would turn
-- this into a silent no-op, after which every published entry would count as unverified and be
-- withheld. Turning row security off makes a role that may not bypass it fail loudly instead;
-- the count check below catches anything else.
SET LOCAL row_security = off;

-- Nothing expires the moment decay is switched on: an entry approved longer ago than its pack's
-- review interval starts the clock as due, so its reviewers get the whole grace period.
INSERT INTO knowledge.verifications (tenant_id, id, pack, entry_id, verified_at, verified_by, reason)
SELECT DISTINCT ON (v.tenant_id, v.pack, v.entry_id)
       v.tenant_id, gen_random_uuid(), v.pack, v.entry_id,
       greatest(p.decided_at, now() - make_interval(days => coalesce((k.document -> 'spec' -> 'decay' ->> 'reviewEveryDays')::int, 365))),
       p.reviewer,
       CASE WHEN p.decided_at >= now() - make_interval(days => coalesce((k.document -> 'spec' -> 'decay' ->> 'reviewEveryDays')::int, 365))
            THEN 'merged (backfilled)'
            ELSE 'merged before decay existed (backfilled; due when decay began)' END
  FROM knowledge.packs k
  JOIN knowledge.pack_version_entries v
    ON v.tenant_id = k.tenant_id AND v.pack = k.name
  JOIN knowledge.proposals p ON p.tenant_id = v.tenant_id AND p.id = v.proposal_id
 WHERE p.decided_at IS NOT NULL AND p.reviewer IS NOT NULL;

DO $$
DECLARE
  published bigint;
  verified  bigint;
BEGIN
  SELECT count(*) INTO published FROM (
    SELECT DISTINCT tenant_id, pack, entry_id FROM knowledge.pack_version_entries
  ) revisions;
  SELECT count(*) INTO verified FROM knowledge.verifications;
  IF verified <> published THEN
    RAISE EXCEPTION 'decay backfill verified % of % published entries', verified, published;
  END IF;
END
$$;

SET LOCAL row_security = on;

-- Erasure (0004, 0005) must reach the verifier too: redefine erase_subject with it.
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

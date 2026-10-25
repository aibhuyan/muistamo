-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security, a service credential
-- and a deletion path. Forward-only.
--
-- Leaver personal-layer reviews (E4.2, J2). The control plane's leaver workflow opens a review
-- with a call signed by the tenant's service secret; while it is open the leaver's personal layer
-- is frozen. The decider merges chosen entries as a proposal, keeps the layer for one more
-- period, or purges it; at the deadline an undecided layer is purged.

-- The HMAC key the control plane signs service calls with, per tenant. Set by an operator.
CREATE TABLE knowledge.service_secrets (
  tenant_id  uuid PRIMARY KEY REFERENCES knowledge.tenants (id),
  secret     bytea NOT NULL CHECK (length(secret) >= 32),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE knowledge.leaver_reviews (
  tenant_id    uuid NOT NULL REFERENCES knowledge.tenants (id),
  id           text NOT NULL,
  person       text NOT NULL,
  decider_kind text NOT NULL CHECK (decider_kind IN ('manager', 'sponsor', 'privacy-officers')),
  -- NULL when any privacy officer decides.
  decider      text,
  status       text NOT NULL CHECK (status IN ('open', 'closed')),
  outcome      text CHECK (outcome IN ('merged', 'purged', 'expired', 'cancelled', 'empty')),
  deadline     timestamptz NOT NULL,
  kept         boolean NOT NULL DEFAULT false,
  entry_count  integer NOT NULL CHECK (entry_count >= 0),
  proposal_id  uuid,
  opened_at    timestamptz NOT NULL DEFAULT now(),
  closed_at    timestamptz,
  PRIMARY KEY (tenant_id, id),
  CHECK ((status = 'open') = (outcome IS NULL)),
  CHECK ((decider_kind = 'privacy-officers') = (decider IS NULL)),
  CHECK (decider IS DISTINCT FROM person)
);

-- At most one open review per person: that is what freezes their layer.
CREATE UNIQUE INDEX leaver_reviews_one_open_per_person
  ON knowledge.leaver_reviews (tenant_id, person) WHERE status = 'open';

-- A proposal made on a leaver's behalf: contributor is the leaver (lineage), proposed_by the
-- decider, who may not approve it.
ALTER TABLE knowledge.proposals ADD COLUMN proposed_by text;

ALTER TABLE knowledge.service_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.service_secrets FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.leaver_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.leaver_reviews FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON knowledge.service_secrets
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON knowledge.leaver_reviews
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The server reads the secret but never writes it (an operator command does, as owner).
GRANT SELECT ON knowledge.service_secrets TO muistamo_knowledge_app;
GRANT SELECT, INSERT, UPDATE ON knowledge.leaver_reviews TO muistamo_knowledge_app;

-- Erasure (0004) must reach the new columns too: redefine erase_subject with them.
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

-- HUMAN REVIEW REQUIRED (AGENTS.md): schema, HR ordering, evidence and erasure.
-- Forward-only. Reuse the retained HR event ledger rather than duplicating personal data.
-- Existing events keep their legacy workflow interpretation and are never redispatched.
-- +goose Up

ALTER TABLE hr_events
  ADD COLUMN occurred_at timestamptz,
  ADD COLUMN generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
  ADD COLUMN decision text NOT NULL DEFAULT 'legacy'
    CHECK (decision IN ('legacy','accepted','ignored')),
  ADD COLUMN dispatch_state text NOT NULL DEFAULT 'legacy'
    CHECK (dispatch_state IN ('legacy','pending','dispatched','ignored','cancelled')),
  ADD COLUMN dispatched_at timestamptz,
  ADD COLUMN dispatch_attempted_at timestamptz,
  ADD COLUMN setup_completed_at timestamptz;

-- hr_events forces row-level security, so a table owner that is neither superuser nor BYPASSRLS
-- (as on managed PostgreSQL) would update no rows, and SET NOT NULL below would fail. Lift FORCE
-- for this one statement, inside this migration's transaction (a failure rolls it back).
-- Corrected in place before release 1; the resulting schema is identical.
ALTER TABLE hr_events NO FORCE ROW LEVEL SECURITY;
UPDATE hr_events SET occurred_at = coalesce((payload ->> 'occurredAt')::timestamptz, received_at);
ALTER TABLE hr_events FORCE ROW LEVEL SECURITY;
ALTER TABLE hr_events ALTER COLUMN occurred_at SET NOT NULL;
ALTER TABLE hr_events ADD CONSTRAINT hr_dispatch_decision CHECK (
  (decision = 'legacy' AND generation = 0 AND dispatch_state = 'legacy') OR
  (decision = 'accepted' AND generation > 0 AND dispatch_state IN ('pending','dispatched','cancelled')) OR
  (decision = 'ignored' AND dispatch_state = 'ignored')
);
CREATE UNIQUE INDEX hr_generation_unique ON hr_events (tenant_id, person_id, generation)
  WHERE decision = 'accepted';
CREATE INDEX hr_person_decision ON hr_events (tenant_id, person_id, generation DESC, occurred_at DESC);
CREATE INDEX hr_pending_dispatch ON hr_events (tenant_id, received_at) WHERE dispatch_state = 'pending';

-- Decision, source time, generation and payload stay immutable to the application role.
-- The existing forced RLS and tenant policy cover all new columns.
GRANT UPDATE (workflow_id, dispatch_state, dispatched_at, dispatch_attempted_at, setup_completed_at) ON hr_events TO muistamo_app;

-- A retry must never turn an uncertain external attempt back into permission to start again.
-- +goose StatementBegin
CREATE FUNCTION preserve_hr_attempt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.dispatch_attempted_at IS NOT NULL AND NEW.dispatch_attempted_at IS DISTINCT FROM OLD.dispatch_attempted_at THEN
    RAISE EXCEPTION 'HR handoff attempt is immutable';
  END IF;
  IF OLD.setup_completed_at IS NOT NULL AND NEW.setup_completed_at IS DISTINCT FROM OLD.setup_completed_at THEN
    RAISE EXCEPTION 'HR setup completion is immutable';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER preserve_hr_attempt BEFORE UPDATE ON hr_events FOR EACH ROW EXECUTE FUNCTION preserve_hr_attempt();

-- Preserve the audited erasure implementation, then cancel newly introduced deferred work
-- whose payload it pseudonymised. A pending job must not recreate erased personal data.
ALTER FUNCTION erase_subject(text[], text) RENAME TO erase_subject_v10;
REVOKE ALL ON FUNCTION erase_subject_v10(text[], text) FROM PUBLIC, muistamo_app;
-- +goose StatementBegin
CREATE FUNCTION erase_subject(subject_values text[], pseudonym text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  t uuid := nullif(current_setting('muistamo.tenant_id', true), '')::uuid;
  counts jsonb;
  n bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('hr-privacy/' || t::text,0));
  -- A dispatched child may still hold the original email/manager in its activity input.
  -- Check before redaction, including references to another employee's manager.
  IF EXISTS (SELECT 1 FROM hr_events WHERE tenant_id=t
    AND (dispatch_state='legacy' OR (dispatch_attempted_at IS NOT NULL
      AND (dispatch_state='pending' OR (dispatch_state='dispatched' AND setup_completed_at IS NULL))))
    AND EXISTS (SELECT 1 FROM unnest(subject_values) v WHERE strpos(payload::text,to_jsonb(v)::text)>0)) THEN
    RAISE EXCEPTION 'erase_subject: unresolved HR handoff requires reconciliation';
  END IF;
  -- The original function validates tenant, identifiers and pseudonym before mutation.
  counts := erase_subject_v10(subject_values, pseudonym);
  -- A removed manager is absent, rather than an invalid pseudonymous decider address.
  -- This keeps the leaver's sponsor/privacy-officer review fallback available on recovery.
  UPDATE hr_events SET payload = payload #- '{person,managerEmail}'
    WHERE tenant_id=t AND payload->'person'->>'managerEmail'=pseudonym;
  UPDATE hr_events SET dispatch_state = 'cancelled'
    WHERE tenant_id = t AND dispatch_state = 'pending' AND dispatch_attempted_at IS NULL
      AND (payload -> 'person' ->> 'email' = pseudonym
        OR payload -> 'person' ->> 'id' = pseudonym);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN counts || jsonb_build_object('hr_events.pending_dispatch', n);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION erase_subject(text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_subject(text[], text) TO muistamo_app;

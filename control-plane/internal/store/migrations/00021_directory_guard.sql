-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and the tenant boundary
-- of Entra authorisation. Forward-only.
--
-- One Entra directory is enrolled by at most one tenant (docs/entra-directory-guard-plan.md). A
-- person's Entra token names its directory; that directory must never name two tenants. The
-- knowledge service has refused a second tenant since its migration 0008; the control plane
-- allowed it until now.
--
-- The enrolled directory is copied onto the tenant's one enrollment row. The foreign key keeps it
-- equal to the enrolled binding's directory, and the unique constraint is checked across tenants
-- whatever row-level security shows the writer. A binding that is registered but not enrolled is
-- inert and is not restricted. The application role has no UPDATE on this table, so an enrolled
-- directory cannot be changed.
-- +goose Up
ALTER TABLE identity_enrollments ADD COLUMN entra_tenant_id uuid;

-- Both tables force row-level security, so a table owner that is neither superuser nor BYPASSRLS
-- (as on managed PostgreSQL) would backfill nothing and count no duplicates. Lift FORCE for these
-- statements and the constraint validation below, inside this migration's transaction; a failure
-- rolls the lift back.
ALTER TABLE identity_enrollments NO FORCE ROW LEVEL SECURITY;
ALTER TABLE entra_bindings NO FORCE ROW LEVEL SECURITY;
UPDATE identity_enrollments e SET entra_tenant_id = b.entra_tenant_id
  FROM entra_bindings b WHERE b.tenant_id = e.tenant_id AND b.binding_version = e.binding_version;
-- Tenants already enrolled in one directory: stop, and choose no winner. The message carries a
-- count only, never a tenant or directory identifier.
-- +goose StatementBegin
DO $$
DECLARE shared bigint;
BEGIN
  SELECT count(*) INTO shared FROM (
    SELECT entra_tenant_id FROM identity_enrollments GROUP BY entra_tenant_id HAVING count(*) > 1
  ) d;
  IF shared > 0 THEN
    RAISE EXCEPTION '% Entra directory(ies) are enrolled by more than one tenant; resolve this before upgrading', shared;
  END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE identity_enrollments ALTER COLUMN entra_tenant_id SET NOT NULL;
ALTER TABLE identity_enrollments ADD CONSTRAINT identity_enrollment_directory
  FOREIGN KEY (tenant_id, binding_version, entra_tenant_id)
  REFERENCES entra_bindings (tenant_id, binding_version, entra_tenant_id);
ALTER TABLE identity_enrollments ADD CONSTRAINT identity_enrollment_one_tenant_per_directory
  UNIQUE (entra_tenant_id);
-- FORCE returns only now, so the constraints above were validated against every tenant's rows.
ALTER TABLE identity_enrollments FORCE ROW LEVEL SECURITY;
ALTER TABLE entra_bindings FORCE ROW LEVEL SECURITY;

-- HUMAN REVIEW REQUIRED: tenant mode, HR routing and creation authorization.
-- Forward-only. Existing histories remain simulated; enrollment requires a fresh tenant.
-- +goose Up
CREATE TABLE identity_enrollments (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id),
  binding_version uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id,binding_version),
  FOREIGN KEY (tenant_id,binding_version) REFERENCES entra_bindings(tenant_id,binding_version)
);
ALTER TABLE identity_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity_enrollments USING (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON identity_enrollments TO muistamo_app;

ALTER TABLE hr_events ADD COLUMN identity_mode text NOT NULL DEFAULT 'simulated' CHECK (identity_mode IN ('simulated','entra'));
ALTER TABLE hr_events ADD COLUMN identity_binding_version uuid;
ALTER TABLE hr_events ADD CONSTRAINT hr_identity_route_shape CHECK ((identity_mode='simulated' AND identity_binding_version IS NULL) OR (identity_mode='entra' AND identity_binding_version IS NOT NULL));
ALTER TABLE hr_events ADD CONSTRAINT hr_identity_enrollment FOREIGN KEY (tenant_id,identity_binding_version) REFERENCES identity_enrollments(tenant_id,binding_version);
-- Existing grants permit only dispatch/setup columns to change. No UPDATE/DELETE grant is
-- added for enrollment or receipt routing. Binding/credential changes need explicit migration.

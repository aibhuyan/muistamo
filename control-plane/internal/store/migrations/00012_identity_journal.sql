-- HUMAN REVIEW REQUIRED (AGENTS.md): schema, identity ownership, evidence and retention.
-- Forward-only. No credentials, sponsor lists, email or raw HR payloads enter this journal.
-- +goose Up

ALTER TABLE hr_events ADD COLUMN receipt_id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE hr_events ADD CONSTRAINT hr_receipt_unique UNIQUE (tenant_id,receipt_id);
ALTER TABLE hr_events ADD CONSTRAINT hr_receipt_generation_unique UNIQUE (tenant_id,receipt_id,generation);

CREATE TABLE entra_bindings (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  binding_version uuid NOT NULL,
  config_digest text NOT NULL CHECK (config_digest ~ '^[0-9a-f]{64}$'),
  entra_tenant_id uuid NOT NULL,
  blueprint_app_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,binding_version),
  UNIQUE (tenant_id,binding_version,entra_tenant_id)
);

CREATE TABLE instance_identities (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  instance_name text NOT NULL,
  provider_mode text NOT NULL CHECK (provider_mode IN ('simulated','entra')),
  binding_version uuid,
  entra_tenant_id uuid,
  assignment_receipt_id uuid,
  provider_id uuid,
  creation_id uuid,
  observed_state text NOT NULL CHECK (observed_state IN ('simulated','unprovisioned','disabled','enabled','deleted','reconciliation_required')),
  enabled_generation bigint CHECK (enabled_generation>0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,id),
  UNIQUE (tenant_id,instance_name),
  UNIQUE (tenant_id,id,binding_version),
  FOREIGN KEY (tenant_id,instance_name) REFERENCES agent_instances(tenant_id,name),
  FOREIGN KEY (tenant_id,binding_version,entra_tenant_id) REFERENCES entra_bindings(tenant_id,binding_version,entra_tenant_id),
  FOREIGN KEY (tenant_id,assignment_receipt_id) REFERENCES hr_events(tenant_id,receipt_id),
  CHECK ((provider_mode='simulated' AND observed_state='simulated' AND binding_version IS NULL AND entra_tenant_id IS NULL AND assignment_receipt_id IS NULL AND provider_id IS NULL AND creation_id IS NULL AND enabled_generation IS NULL)
    OR (provider_mode='entra' AND observed_state<>'simulated' AND binding_version IS NOT NULL AND entra_tenant_id IS NOT NULL AND assignment_receipt_id IS NOT NULL)),
  CHECK (provider_id IS NULL OR creation_id IS NOT NULL)
);
-- Prevent a directory identity from being owned by two Muistamo instances or tenants.
CREATE UNIQUE INDEX identity_provider_owner ON instance_identities(entra_tenant_id,provider_id) WHERE provider_id IS NOT NULL;

CREATE TABLE identity_operations (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  id uuid NOT NULL,
  instance_identity_id uuid NOT NULL,
  binding_version uuid NOT NULL,
  hr_receipt_id uuid NOT NULL,
  hr_generation bigint NOT NULL CHECK (hr_generation>0),
  action text NOT NULL CHECK (action IN ('create','enable','disable','delete')),
  attempt bigint NOT NULL DEFAULT 1 CHECK (attempt>0),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','succeeded','indeterminate','failed')),
  creation_id uuid NOT NULL,
  provider_id uuid,
  candidate_id uuid,
  error_code text CHECK (error_code IN ('provider_refused','provider_unavailable','ownership_unproved','uncertain','generation_superseded')),
  -- Logical reference checked against the matching signed action by activation/retirement.
  -- Do not add an FK to evidence_events: its append-only TRUNCATE trigger must remain the
  -- enforcing guard, including for the table owner (an FK would mask that trigger).
  result_evidence_seq bigint CHECK (result_evidence_seq>0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,id),
  FOREIGN KEY (tenant_id,instance_identity_id,binding_version) REFERENCES instance_identities(tenant_id,id,binding_version),
  FOREIGN KEY (tenant_id,hr_receipt_id,hr_generation) REFERENCES hr_events(tenant_id,receipt_id,generation),
  UNIQUE (tenant_id,instance_identity_id,hr_generation,action,attempt),
  CHECK (state<>'succeeded' OR (provider_id IS NOT NULL AND result_evidence_seq IS NOT NULL))
);
-- Exclusion spans generations; a rehire cannot authorize another blind create.
CREATE UNIQUE INDEX identity_single_create ON identity_operations(tenant_id,instance_identity_id) WHERE action='create';
ALTER TABLE instance_identities ADD CONSTRAINT identity_original_creation
  FOREIGN KEY (tenant_id,creation_id) REFERENCES identity_operations(tenant_id,id) DEFERRABLE INITIALLY DEFERRED;

INSERT INTO instance_identities(tenant_id,instance_name,provider_mode,observed_state)
  SELECT tenant_id,name,'simulated','simulated' FROM agent_instances;

ALTER TABLE entra_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE entra_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE instance_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE instance_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON entra_bindings USING (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid);
CREATE POLICY tenant_isolation ON instance_identities USING (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid);
CREATE POLICY tenant_isolation ON identity_operations USING (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('muistamo.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT ON entra_bindings,instance_identities,identity_operations TO muistamo_app;
GRANT UPDATE (provider_id,creation_id,observed_state,enabled_generation,updated_at) ON instance_identities TO muistamo_app;
GRANT UPDATE (state,provider_id,candidate_id,error_code,result_evidence_seq,updated_at) ON identity_operations TO muistamo_app;

-- +goose StatementBegin
CREATE FUNCTION preserve_identity_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.provider_id IS NOT NULL AND NEW.provider_id IS DISTINCT FROM OLD.provider_id THEN
    RAISE EXCEPTION 'provider ownership is immutable';
  END IF;
  IF OLD.creation_id IS NOT NULL AND NEW.creation_id IS DISTINCT FROM OLD.creation_id THEN
    RAISE EXCEPTION 'original creation marker is immutable';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER preserve_identity_owner BEFORE UPDATE ON instance_identities FOR EACH ROW EXECUTE FUNCTION preserve_identity_owner();

-- +goose StatementBegin
CREATE FUNCTION preserve_identity_result() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.state IN ('succeeded','failed') AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'terminal identity operation is immutable';
  END IF;
  IF OLD.state='indeterminate' AND NEW.state='pending' THEN
    RAISE EXCEPTION 'uncertain identity attempt cannot be reset';
  END IF;
  IF OLD.candidate_id IS NOT NULL AND NEW.candidate_id IS DISTINCT FROM OLD.candidate_id THEN
    RAISE EXCEPTION 'identity candidate is immutable';
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER preserve_identity_result BEFORE UPDATE ON identity_operations FOR EACH ROW EXECUTE FUNCTION preserve_identity_result();

-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security, authorisation and the
-- erasure path. Forward-only.
--
-- Who may read the console's management screens (docs/console-management-plan.md, D70).
-- Administrators read agents, templates, people and HR events, and policies; auditors read the
-- evidence log. Like catalogue approvers (00004), privacy officers (00006) and gateway
-- administrators (00015), each list is set by an operator command with the owner's credentials
-- (registry.ConfigureConsoleRole, signed as evidence); the server role reads it and can never
-- change it. A person holds a role in one tenant only: the row is tenant-scoped.
-- +goose Up
CREATE TABLE console_roles (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  role      text NOT NULL CHECK (role IN ('administrator', 'auditor')),
  person    text NOT NULL CHECK (length(person) >= 3),
  PRIMARY KEY (tenant_id, role, person)
);
ALTER TABLE console_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE console_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON console_roles
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
GRANT SELECT ON console_roles TO muistamo_app;

-- An erased person holds no role, as for gateway administrators (00015). Keep the audited
-- function and wrap it.
ALTER FUNCTION erase_subject(text[], text) RENAME TO erase_subject_v15;
REVOKE ALL ON FUNCTION erase_subject_v15(text[], text) FROM PUBLIC, muistamo_app;
-- +goose StatementBegin
CREATE FUNCTION erase_subject(subject_values text[], pseudonym text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  t uuid := nullif(current_setting('muistamo.tenant_id', true), '')::uuid;
  counts jsonb;
  n bigint;
BEGIN
  -- The wrapped function validates tenant, identifiers and pseudonym before any mutation.
  counts := erase_subject_v15(subject_values, pseudonym);
  DELETE FROM console_roles WHERE tenant_id = t AND person = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN counts || jsonb_build_object('console_roles', n);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION erase_subject(text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_subject(text[], text) TO muistamo_app;

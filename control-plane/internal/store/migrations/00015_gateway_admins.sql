-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and the erasure path.
-- Forward-only.
--
-- Gateway administrators issue and revoke virtual keys (docs/agentgateway-plan.md, step 3a). Like
-- catalogue approvers (00004) and privacy officers, the list is set by an operator command with the
-- owner's credentials; the server role can read it but never change it. Configuration is signed
-- atomically and shares the exclusive erasure fence (registry.ConfigureGatewayAdmins).
-- +goose Up
CREATE TABLE gateway_admins (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  admin     text NOT NULL CHECK (length(admin) >= 3),
  PRIMARY KEY (tenant_id, admin)
);
ALTER TABLE gateway_admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_admins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gateway_admins
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
GRANT SELECT ON gateway_admins TO muistamo_app;

-- An erased person is no longer an administrator, as for catalogue approvers (00006). Keep the
-- audited function (00014) and wrap it.
ALTER FUNCTION erase_subject(text[], text) RENAME TO erase_subject_v14;
REVOKE ALL ON FUNCTION erase_subject_v14(text[], text) FROM PUBLIC, muistamo_app;
-- +goose StatementBegin
CREATE FUNCTION erase_subject(subject_values text[], pseudonym text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  t uuid := nullif(current_setting('muistamo.tenant_id', true), '')::uuid;
  counts jsonb;
  n bigint;
BEGIN
  -- The wrapped function validates tenant, identifiers and pseudonym before any mutation.
  counts := erase_subject_v14(subject_values, pseudonym);
  DELETE FROM gateway_admins WHERE tenant_id = t AND admin = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN counts || jsonb_build_object('gateway_admins', n);
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION erase_subject(text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_subject(text[], text) TO muistamo_app;

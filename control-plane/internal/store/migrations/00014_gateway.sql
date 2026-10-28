-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security, token handling and the
-- erasure path. Forward-only.
--
-- Gateway first slice (docs/agentgateway-plan.md, step 2). Virtual keys are Muistamo's own
-- credentials for the gateway; provider credentials are never stored here (NFR-08). Each call the
-- gateway's check allows is a gateway_calls row, carrying the price snapshot it will be billed at
-- (invariant 7); a usage record, when one arrives from the gateway's log export, attaches to it.
-- A call with no usage record is unmetered, and is reported as such rather than estimated.
-- +goose Up

-- A key is mvk_<id>_<secret>. Only SHA-256 of the 256-bit secret is kept, so a database read
-- never yields a usable key. Expiry is a time, not a status: an expired key needs no write.
CREATE TABLE virtual_keys (
  tenant_id      uuid NOT NULL REFERENCES tenants(id),
  id             uuid NOT NULL,
  instance       text NOT NULL,
  aliases        text[] NOT NULL CHECK (cardinality(aliases) >= 1),
  budget_amount  numeric(18,6) NOT NULL CHECK (budget_amount >= 0),
  budget_currency text NOT NULL CHECK (budget_currency ~ '^[A-Z]{3}$'),
  expires_at     timestamptz,
  secret_sha256  bytea NOT NULL CHECK (length(secret_sha256) = 32),
  status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  created_by     text NOT NULL,
  revoked_at     timestamptz,
  revoked_by     text,
  revoke_reason  text,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, instance) REFERENCES agent_instances(tenant_id, name),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revoke_reason IS NOT NULL)),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX virtual_keys_instance ON virtual_keys(tenant_id, instance) WHERE status = 'active';

-- One row per call the check allowed, written with its evidence before the gateway proceeds.
-- "authorized" is all it claims: the gateway may still reject the call afterwards (400/404/413).
CREATE TABLE gateway_calls (
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  request_id      uuid NOT NULL,
  key_id          uuid NOT NULL,
  instance        text NOT NULL,
  person          text NOT NULL,
  cost_centre     text,
  kind            text NOT NULL CHECK (kind IN ('model', 'mcp')),
  alias           text,
  provider        text,
  model           text,
  mcp_method      text,
  mcp_tool        text,
  price_currency  text CHECK (price_currency ~ '^[A-Z]{3}$'),
  input_per_mtok  numeric(18,9) CHECK (input_per_mtok >= 0),
  output_per_mtok numeric(18,9) CHECK (output_per_mtok >= 0),
  authorized_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, key_id) REFERENCES virtual_keys(tenant_id, id),
  -- A model call is priced from its snapshot; an MCP call names its method.
  CHECK (kind <> 'model' OR (alias IS NOT NULL AND provider IS NOT NULL AND model IS NOT NULL
    AND price_currency IS NOT NULL AND input_per_mtok IS NOT NULL AND output_per_mtok IS NOT NULL)),
  CHECK (kind <> 'mcp' OR mcp_method IS NOT NULL)
);
CREATE INDEX gateway_calls_key_time ON gateway_calls(tenant_id, key_id, authorized_at);

-- What the provider reported for an authorized call, priced from that call's snapshot at provider
-- cost: no markup (invariant 7). At most one per call.
CREATE TABLE usage_records (
  tenant_id      uuid NOT NULL,
  request_id     uuid NOT NULL,
  input_tokens   bigint NOT NULL CHECK (input_tokens >= 0),
  output_tokens  bigint NOT NULL CHECK (output_tokens >= 0),
  response_model text,
  cost_amount    numeric(24,12) NOT NULL CHECK (cost_amount >= 0),
  cost_currency  text NOT NULL CHECK (cost_currency ~ '^[A-Z]{3}$'),
  recorded_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, request_id),
  FOREIGN KEY (tenant_id, request_id) REFERENCES gateway_calls(tenant_id, request_id)
);

ALTER TABLE virtual_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE virtual_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE gateway_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_calls FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON virtual_keys
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON gateway_calls
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON usage_records
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);

-- The server issues and revokes keys. The column grant stops it rewriting a key's secret, owner,
-- scope or budget; the trigger below stops anyone un-revoking one. The call and usage ledgers are
-- append-only for the server.
GRANT SELECT, INSERT ON virtual_keys TO muistamo_app;
GRANT UPDATE (status, revoked_at, revoked_by, revoke_reason) ON virtual_keys TO muistamo_app;
GRANT SELECT, INSERT ON gateway_calls, usage_records TO muistamo_app;

-- +goose StatementBegin
-- Revocation is one-way: once revoked, a key never becomes active again, whoever writes.
CREATE FUNCTION virtual_key_revocation_is_final() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status = 'revoked' AND (NEW.status <> 'revoked' OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
    RAISE EXCEPTION 'virtual key % is revoked; revocation is final', OLD.id;
  END IF;
  RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER virtual_key_revocation_is_final BEFORE UPDATE ON virtual_keys
  FOR EACH ROW EXECUTE FUNCTION virtual_key_revocation_is_final();

-- Erasure must reach the new person references. Keep the audited function (00011) and wrap it,
-- as 00011 did with its predecessor. Key and call rows stay, attributed to the pseudonym: they are
-- the billing and audit trail (cost centres are not personal data).
ALTER FUNCTION erase_subject(text[], text) RENAME TO erase_subject_v11;
REVOKE ALL ON FUNCTION erase_subject_v11(text[], text) FROM PUBLIC, muistamo_app;
-- +goose StatementBegin
CREATE FUNCTION erase_subject(subject_values text[], pseudonym text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  t uuid := nullif(current_setting('muistamo.tenant_id', true), '')::uuid;
  counts jsonb;
  n bigint;
BEGIN
  -- The wrapped function validates tenant, identifiers and pseudonym before any mutation.
  counts := erase_subject_v11(subject_values, pseudonym);
  UPDATE virtual_keys SET created_by = pseudonym WHERE tenant_id = t AND created_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('virtual_keys.created_by', n);
  -- revoked_by is part of a revoked row; the revocation trigger allows it because status and
  -- revoked_at do not change.
  UPDATE virtual_keys SET revoked_by = pseudonym WHERE tenant_id = t AND revoked_by = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('virtual_keys.revoked_by', n);
  UPDATE gateway_calls SET person = pseudonym WHERE tenant_id = t AND person = ANY (subject_values);
  GET DIAGNOSTICS n = ROW_COUNT; counts := counts || jsonb_build_object('gateway_calls.person', n);
  RETURN counts;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION erase_subject(text[], text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION erase_subject(text[], text) TO muistamo_app;

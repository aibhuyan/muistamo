-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and authorisation.
-- Forward-only.
--
-- The console's identity at the control plane (docs/control-plane-console-plan.md). A person
-- signed in to the console calls the control plane with an access token from their own Entra
-- directory, obtained by the tenant's console app (azp = client_app) for the tenant's own
-- "Muistamo control plane" API app (aud = api_app), never the blueprint the knowledge service
-- accepts: a token the knowledge service receives can never act here. One row per tenant; without
-- one the tenant's console callers are refused. App ids are public; no personal data.
-- +goose Up
CREATE TABLE console_clients (
  tenant_id  uuid PRIMARY KEY REFERENCES tenants(id),
  client_app uuid NOT NULL,
  api_app    uuid NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (client_app <> api_app)
);
ALTER TABLE console_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE console_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON console_clients
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
-- The server reads it only; an operator sets it, as the schema owner.
GRANT SELECT ON console_clients TO muistamo_app;


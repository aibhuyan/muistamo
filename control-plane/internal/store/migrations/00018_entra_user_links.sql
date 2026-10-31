-- HUMAN REVIEW REQUIRED (AGENTS.md): database schema, row-level security and the erasure path.
-- Forward-only.
--
-- Which Entra user an HR person is (docs/obo-retrieval-plan.md, PR A). The live joiner looks up
-- the user whose employeeId equals the HR person id and records the user's immutable object id.
-- A request made with an Entra token is matched to a person only through a matched row here,
-- never by name or email, and so to the person's own agent for on-behalf-of retrieval.
--
-- One row per person, replaced by each later joiner (rehire). A lookup that fails or is refused
-- records 'unavailable', so an earlier link never survives a joiner that could not confirm it.
-- An Entra user belongs to at most one person, across every tenant bound to that directory (as
-- identity_provider_owner does for agent identities): when two people match the same user, both
-- rows become 'conflict' with no object id, so a token can never resolve to the wrong person.
-- Erasure deletes the row (registry.Erase); its history stays in the signed evidence, which names
-- the user only by a digest.
-- +goose Up
CREATE TABLE person_entra_links (
  tenant_id            uuid NOT NULL REFERENCES tenants(id),
  person_id            text NOT NULL CHECK (length(person_id) BETWEEN 1 AND 200),
  status               text NOT NULL CHECK (status IN ('matched', 'unmatched', 'ambiguous', 'conflict', 'unavailable')),
  binding_version      uuid NOT NULL,
  entra_tenant_id      uuid NOT NULL,
  entra_user_object_id uuid,
  receipt_id           uuid NOT NULL,
  matched_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, person_id),
  FOREIGN KEY (tenant_id, binding_version, entra_tenant_id) REFERENCES entra_bindings(tenant_id, binding_version, entra_tenant_id),
  CHECK ((status = 'matched') = (entra_user_object_id IS NOT NULL))
);
CREATE UNIQUE INDEX person_entra_links_user
  ON person_entra_links (entra_tenant_id, entra_user_object_id)
  WHERE entra_user_object_id IS NOT NULL;
ALTER TABLE person_entra_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE person_entra_links FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON person_entra_links
  USING (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('muistamo.tenant_id', true), '')::uuid);
-- The joiner writes the row (registry.RecordEntraUserLink) and erasure deletes it.
GRANT SELECT, INSERT, UPDATE, DELETE ON person_entra_links TO muistamo_app;

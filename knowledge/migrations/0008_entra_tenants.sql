-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and authentication.
-- Forward-only.
--
-- Which Muistamo tenant an Entra directory's people belong to (docs/obo-retrieval-plan.md, PR C).
-- A caller's Entra access token names its directory (tid); its tenant is found here, and the token
-- is then validated against this row: its audience must be the tenant's blueprint app id. The
-- scope a token must carry (Knowledge.Read) is fixed, as the control plane requires it. An
-- operator sets the row (`tenant entra`); re-pointing a tenant to another directory must be
-- explicit (`--replace`).
--
-- One directory belongs to at most one tenant: a token must never resolve to two. (The control
-- plane may still bind one directory to two tenants; here the second is refused.)

CREATE TABLE knowledge.entra_tenants (
  tenant_id       uuid PRIMARY KEY REFERENCES knowledge.tenants (id),
  entra_tenant_id uuid NOT NULL UNIQUE,
  audience        uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- Row-level security isolates tenants for the server's role, which is granted nothing on the table:
-- it reads one directory's row only through knowledge.entra_tenant(). RLS is enabled but not
-- forced, so that function, running as the owner, can find the row before any tenant is known.
ALTER TABLE knowledge.entra_tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON knowledge.entra_tenants
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The tenant and audience for one directory, or no row.
CREATE FUNCTION knowledge.entra_tenant(directory uuid)
RETURNS TABLE (tenant_id uuid, audience uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = knowledge, pg_temp AS $$
  SELECT tenant_id, audience FROM knowledge.entra_tenants WHERE entra_tenant_id = directory
$$;
REVOKE ALL ON FUNCTION knowledge.entra_tenant(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION knowledge.entra_tenant(uuid) TO muistamo_knowledge_app;

-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema. Forward-only.
--
-- A tenant's Entra registration, for the protected resource metadata (RFC 9728) of its MCP
-- endpoint (docs/assistants-plan.md): an assistant learns from it which directory signs the
-- person in, before any token is known. The server's role is granted nothing on
-- entra_tenants (0008) and reads one row only through these functions; this one is keyed by
-- tenant, as knowledge.entra_tenant() is by directory. It returns only what the metadata
-- publishes: the directory and the audience.

CREATE FUNCTION knowledge.entra_registration(tenant uuid)
RETURNS TABLE (entra_tenant_id uuid, audience uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = knowledge, pg_temp AS $$
  SELECT entra_tenant_id, audience FROM knowledge.entra_tenants WHERE tenant_id = tenant
$$;
REVOKE ALL ON FUNCTION knowledge.entra_registration(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION knowledge.entra_registration(uuid) TO muistamo_knowledge_app;

-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema and authorisation. Forward-only.
--
-- Assistants cannot act as reviewer (maintainer decision, 2026-11-07). The tenant's client-app
-- allowlist (0012) now says what each client app is:
-- - 'assistant': an AI assistant acting for a person. It reads within its agent's scope (D60) and
--   cannot make reviewer or admin calls.
-- - 'console': Muistamo's own console, through which a person acts as themselves (reviewing,
--   administering).
-- Rows from 0012 are assistants.

ALTER TABLE knowledge.assistants
  ADD COLUMN kind text NOT NULL DEFAULT 'assistant' CHECK (kind IN ('assistant', 'console'));

-- The client's name and kind for a tenant's client app, or no row. Replaces entra_assistant(),
-- which stays (expand, then contract) so servers still running the previous code keep working
-- during a rolling deploy; a later migration drops it once every server calls entra_client().
CREATE FUNCTION knowledge.entra_client(p_tenant uuid, p_client_app uuid)
RETURNS TABLE (name text, kind text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = knowledge, pg_temp AS $$
  SELECT name, kind FROM knowledge.assistants WHERE tenant_id = p_tenant AND client_app = p_client_app
$$;
REVOKE ALL ON FUNCTION knowledge.entra_client(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION knowledge.entra_client(uuid, uuid) TO muistamo_knowledge_app;

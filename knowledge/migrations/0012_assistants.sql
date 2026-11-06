-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security and token handling.
-- Forward-only.
--
-- Which assistants may reach a tenant's knowledge (docs/assistants-plan.md, PR 2). An Entra
-- caller's token names the client app that obtained it (azp): Claude's connector, a Copilot
-- Studio connector, ... Only an app the tenant's operator allowed, by its Entra application id,
-- is accepted; any other is refused even with a valid token and scope. The name is what the
-- retrieval log records ("answered in Claude").

CREATE TABLE knowledge.assistants (
  tenant_id  uuid NOT NULL REFERENCES knowledge.tenants (id),
  client_app uuid NOT NULL,
  name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100 AND name !~ '[[:cntrl:]]'),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, client_app),
  UNIQUE (tenant_id, name)
);

-- As entra_tenants (0008): the server's role is granted nothing on the table and reads one
-- assistant's name only through knowledge.entra_assistant(), while it resolves a caller.
ALTER TABLE knowledge.assistants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON knowledge.assistants
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The allowed assistant's name for a tenant's client app, or no row.
CREATE FUNCTION knowledge.entra_assistant(tenant uuid, client_app uuid)
RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = knowledge, pg_temp AS $$
  SELECT name FROM knowledge.assistants a WHERE a.tenant_id = tenant AND a.client_app = $2
$$;
REVOKE ALL ON FUNCTION knowledge.entra_assistant(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION knowledge.entra_assistant(uuid, uuid) TO muistamo_knowledge_app;

-- Which assistant a read was answered in; NULL for development callers. Erasure removes a
-- person's reads, this column with them.
ALTER TABLE knowledge.reads ADD COLUMN assistant text
  CHECK (assistant IS NULL OR length(assistant) BETWEEN 1 AND 100);

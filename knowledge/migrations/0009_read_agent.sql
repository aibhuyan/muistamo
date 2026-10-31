-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema. Forward-only.
--
-- Which agent a read was made through (PR D): for an Entra caller, the agent instance the
-- control plane delegated to for that request, matching its knowledge.delegation.issued
-- evidence. NULL for development callers, who read as themselves. Erasure removes a person's
-- reads, this column with them.
ALTER TABLE knowledge.reads ADD COLUMN agent text CHECK (agent IS NULL OR length(agent) BETWEEN 1 AND 253);

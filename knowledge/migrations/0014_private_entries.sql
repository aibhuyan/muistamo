-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, an authorisation exception and a deletion
-- path. Forward-only.
--
-- Private personal entries (D59, FR-1802, docs/d59-private-entries-plan.md). The flag is the
-- owner's choice about their own layer, so it lives on the personal row, never on the immutable
-- revision a proposal or pack copies. A private entry is never proposed, never shown or counted in
-- a leaver review, and purged when the leaver review opens. Existing entries stay shared.
--
-- Adding a column with a default keeps servers on the previous code working during a rolling
-- deploy; they ignore the flag, so no client sets it until the rollout is done.

ALTER TABLE knowledge.personal_entries ADD COLUMN private boolean NOT NULL DEFAULT false;

-- The server may change the flag and nothing else on an existing personal row.
GRANT UPDATE (private) ON knowledge.personal_entries TO muistamo_knowledge_app;

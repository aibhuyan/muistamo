-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema. Forward-only.
--
-- Mandatory packs (FR-1708) are company packs: they apply to everyone in the tenant, and their
-- entries win over every other layer, so a team or role pack must never be able to claim that.

ALTER TABLE knowledge.packs ADD CONSTRAINT packs_mandatory_is_company CHECK (NOT mandatory OR layer = 'company');

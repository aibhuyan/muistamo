-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema for the gateway's policy path.
-- Forward-only.
--
-- Action policies may now apply to a clone instead of a template. A clone keeps its template's
-- policy; its own may only narrow it (enforced by the contract and the compiler). At most one
-- policy applies to each template, and at most one to each clone.

-- +goose Up

ALTER TABLE policy_documents ADD COLUMN clone text;

ALTER TABLE policy_documents DROP CONSTRAINT policy_documents_check;
ALTER TABLE policy_documents ADD CONSTRAINT policy_documents_target CHECK (
  CASE kind
    WHEN 'ActionPolicy' THEN (template IS NULL) <> (clone IS NULL)
    ELSE template IS NULL AND clone IS NULL
  END
);

CREATE UNIQUE INDEX policy_documents_one_policy_per_clone
  ON policy_documents (tenant_id, clone) WHERE kind = 'ActionPolicy' AND clone IS NOT NULL;

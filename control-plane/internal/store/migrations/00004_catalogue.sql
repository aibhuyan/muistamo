-- HUMAN REVIEW REQUIRED (CLAUDE.md): database schema, row-level security, and the approval rules
-- they enforce. Forward-only.
--
-- The template catalogue (FR-102, E1.2). A template version can be assigned to joiners only while
-- it is published here, and publication needs approval by risk tier: low none, medium one, high
-- two distinct approvers; never the requester.

-- +goose Up

CREATE TABLE catalogue_approvers (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  approver  text NOT NULL,
  PRIMARY KEY (tenant_id, approver)
);

CREATE TABLE catalogue_requests (
  tenant_id        uuid NOT NULL REFERENCES tenants (id),
  id               uuid NOT NULL,
  template         text NOT NULL,
  version          integer NOT NULL,
  requested_by     text NOT NULL,
  risk_tier        text NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high')),
  needed_approvals integer NOT NULL CHECK (needed_approvals BETWEEN 0 AND 2),
  state            text NOT NULL CHECK (state IN ('pending', 'published', 'rejected', 'withdrawn', 'superseded')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  closed_at        timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, template, version) REFERENCES agent_template_versions (tenant_id, name, version)
);

CREATE TABLE catalogue_approvals (
  tenant_id  uuid NOT NULL,
  request_id uuid NOT NULL,
  approver   text NOT NULL,
  decision   text NOT NULL CHECK (decision IN ('approve', 'reject')),
  reason     text NOT NULL,
  decided_at timestamptz NOT NULL DEFAULT now(),
  -- One decision per approver per request: the same person can never count twice.
  PRIMARY KEY (tenant_id, request_id, approver),
  FOREIGN KEY (tenant_id, request_id) REFERENCES catalogue_requests (tenant_id, id)
);

-- At most one published version per template.
CREATE TABLE catalogue_published (
  tenant_id    uuid NOT NULL,
  template     text NOT NULL,
  version      integer NOT NULL,
  request_id   uuid NOT NULL,
  published_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, template),
  FOREIGN KEY (tenant_id, template, version) REFERENCES agent_template_versions (tenant_id, name, version),
  FOREIGN KEY (tenant_id, request_id) REFERENCES catalogue_requests (tenant_id, id)
);

ALTER TABLE catalogue_approvers ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalogue_approvers FORCE ROW LEVEL SECURITY;
ALTER TABLE catalogue_requests  ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalogue_requests  FORCE ROW LEVEL SECURITY;
ALTER TABLE catalogue_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalogue_approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE catalogue_published ENABLE ROW LEVEL SECURITY;
ALTER TABLE catalogue_published FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON catalogue_approvers
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON catalogue_requests
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON catalogue_approvals
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);
CREATE POLICY tenant_isolation ON catalogue_published
  USING (tenant_id = current_setting('muistamo.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('muistamo.tenant_id', true)::uuid);

-- The server reads approvers but never edits them (an operator command does, as owner).
GRANT SELECT ON catalogue_approvers TO muistamo_app;
GRANT SELECT, INSERT, UPDATE ON catalogue_requests TO muistamo_app;
GRANT SELECT, INSERT ON catalogue_approvals TO muistamo_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON catalogue_published TO muistamo_app;

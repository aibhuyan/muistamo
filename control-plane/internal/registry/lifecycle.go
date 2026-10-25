package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// PersonLabel links an instance to the HR person it was created for.
const PersonLabel = "muistamo.dev/hr-person-id"

// TemplateVersionRef names one template version.
type TemplateVersionRef struct {
	Name    string
	Version int
}

// MatchTemplatesByJobCode returns the catalogue-published version of every template whose
// published version lists jobCode in spec.assignment.hrJobCodes, ordered by name. Templates that
// are applied but not published (or pending, rejected, withdrawn) never match (FR-102).
func (s *Service) MatchTemplatesByJobCode(ctx context.Context, actor Actor, jobCode string) ([]TemplateVersionRef, error) {
	var refs []TemplateVersionRef
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT p.template, p.version
			FROM catalogue_published p
			JOIN agent_template_versions v ON v.tenant_id = p.tenant_id AND v.name = p.template AND v.version = p.version
			WHERE v.document -> 'spec' -> 'assignment' -> 'hrJobCodes' ? $1
			ORDER BY p.template`, jobCode)
		if err != nil {
			return fmt.Errorf("match templates for job code %q: %w", jobCode, err)
		}
		defer rows.Close()
		for rows.Next() {
			var ref TemplateVersionRef
			if err := rows.Scan(&ref.Name, &ref.Version); err != nil {
				return fmt.Errorf("scan template: %w", err)
			}
			refs = append(refs, ref)
		}
		return rows.Err()
	})
	return refs, err
}

// InstancesForPerson returns every instance labelled with the HR person id, ordered by name.
func (s *Service) InstancesForPerson(ctx context.Context, actor Actor, personID string) ([]muistamov1.AgentInstanceRecord, error) {
	var recs []muistamov1.AgentInstanceRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, instanceColumns+` WHERE document -> 'metadata' -> 'labels' ->> $1 = $2 ORDER BY name`,
			PersonLabel, personID)
		if err != nil {
			return fmt.Errorf("instances for person: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			rec, err := scanInstance(rows, "")
			if err != nil {
				return err
			}
			recs = append(recs, rec)
		}
		return rows.Err()
	})
	return recs, err
}

// SetIdentityRef records the identity provider's id for an instance. It is for lifecycle
// workflows only: the API keeps identityRef immutable. Setting the same value again is a no-op.
func (s *Service) SetIdentityRef(ctx context.Context, actor Actor, name, identityRef string) (muistamov1.AgentInstanceRecord, error) {
	var rec muistamov1.AgentInstanceRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		current, err := lockInstance(ctx, tx, name)
		if err != nil {
			return err
		}
		if current.Document.Spec.IdentityRef != nil && *current.Document.Spec.IdentityRef == identityRef {
			rec = current
			return nil
		}
		next := current.Document
		next.Spec.IdentityRef = &identityRef
		rec, err = updateInstance(ctx, tx, current, next)
		if err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "identity.provisioned", "AgentInstance", name,
			nil, map[string]any{"identityRef": identityRef, "revision": rec.Revision})
	})
	return rec, err
}

// RecordLifecycleEvent records evidence for a step that changes no registry row, such as a
// credential revocation performed elsewhere.
func (s *Service) RecordLifecycleEvent(ctx context.Context, actor Actor, action, name string, after any) error {
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		return recordEvidence(ctx, tx, s.signer, actor, action, "AgentInstance", name, nil, after)
	})
}

// TransitionTo moves an instance to state unless it is already there. It reads the current
// revision itself, so it is for lifecycle workflows, which act on the latest state.
func (s *Service) TransitionTo(ctx context.Context, actor Actor, name string, to muistamov1.InstanceState) (muistamov1.AgentInstanceRecord, error) {
	const attempts = 3
	for i := 0; ; i++ {
		current, err := s.GetInstance(ctx, actor, name)
		if err != nil {
			return current, err
		}
		if current.Document.Spec.State == to {
			return current, nil
		}
		rec, err := s.Transition(ctx, actor, name, to, ETag(current.Revision))
		// Another writer changed the instance between read and write; retry on the new revision.
		if errors.Is(err, ErrPrecondition) && i+1 < attempts {
			continue
		}
		return rec, err
	}
}

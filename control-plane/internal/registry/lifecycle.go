package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// PersonLabel links an instance to the HR person it was created for.
const PersonLabel = "muistamo.dev/hr-person-id"

// TemplateVersionRef names one template version, and the clone of it a joiner gets, if any.
type TemplateVersionRef struct {
	Name    string
	Version int
	Clone   string `json:",omitempty"`
}

// MatchTemplatesByJobCode returns what a joiner with jobCode gets, ordered by template name
// (FR-102, FR-103). For each template published to the catalogue:
//   - an assignable clone of it that lists jobCode wins, at the published version;
//   - with none, the template itself if its published version lists jobCode;
//   - two or more matching clones of one template are ambiguous: the joiner gets neither, and
//     the ambiguity is recorded, rather than one being picked silently.
//
// Templates that are not published, and clones that are not assignable, never match.
func (s *Service) MatchTemplatesByJobCode(ctx context.Context, actor Actor, jobCode string) ([]TemplateVersionRef, error) {
	var refs []TemplateVersionRef
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT p.template, p.version, coalesce(v.document -> 'spec' -> 'assignment' -> 'hrJobCodes' ? $1, false)
			FROM catalogue_published p
			JOIN agent_template_versions v ON v.tenant_id = p.tenant_id AND v.name = p.template AND v.version = p.version
			ORDER BY p.template`, jobCode)
		if err != nil {
			return fmt.Errorf("match templates for job code %q: %w", jobCode, err)
		}
		type published struct {
			ref     TemplateVersionRef
			matches bool
		}
		var candidates []published
		for rows.Next() {
			var c published
			if err := rows.Scan(&c.ref.Name, &c.ref.Version, &c.matches); err != nil {
				rows.Close()
				return fmt.Errorf("scan template: %w", err)
			}
			candidates = append(candidates, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, c := range candidates {
			clones, err := listClones(ctx, tx, c.ref.Name)
			if err != nil {
				return err
			}
			var matching []string
			for _, clone := range clones {
				overlay := clone.doc.Spec.Overlay
				if overlay == nil || overlay.Assignment == nil || overlay.Assignment.HrJobCodes == nil ||
					!slices.Contains(*overlay.Assignment.HrJobCodes, jobCode) {
					continue
				}
				r, err := resolveClone(ctx, tx, clone)
				if err != nil {
					return err
				}
				if r.assignable && r.version != nil && *r.version == c.ref.Version {
					matching = append(matching, clone.doc.Metadata.Name)
				}
			}
			switch {
			case len(matching) == 1:
				refs = append(refs, TemplateVersionRef{Name: c.ref.Name, Version: c.ref.Version, Clone: matching[0]})
			case len(matching) > 1:
				if err := recordEvidence(ctx, tx, s.signer, actor, "assignment.ambiguous", "AgentTemplate", c.ref.Name, nil,
					map[string]any{"jobCode": jobCode, "clones": matching,
						"reason": "more than one clone of this template lists the job code; the joiner gets none of them"}); err != nil {
					return err
				}
			case c.matches:
				refs = append(refs, c.ref)
			}
		}
		return nil
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

// RecordPersonEvent records evidence about an HR person rather than an instance, such as the
// review of their personal knowledge layer.
func (s *Service) RecordPersonEvent(ctx context.Context, actor Actor, action, personID string, after any) error {
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		return recordEvidence(ctx, tx, s.signer, actor, action, "HRPerson", personID, nil, after)
	})
}

// KnowledgeSecret returns the tenant's knowledge-service secret, or nil if none is set.
func (s *Service) KnowledgeSecret(ctx context.Context, actor Actor) ([]byte, error) {
	var secret []byte
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT secret FROM knowledge_service_secrets`).Scan(&secret)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return secret, err
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

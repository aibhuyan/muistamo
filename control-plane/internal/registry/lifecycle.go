package registry

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// SettleHRSetup records that a new handoff's activities no longer use its original email or
// manager. Leaver grace-period work uses retained HR/review IDs and current instance documents.
// This is not a claim that the whole workflow, provider cleanup or retention has completed.
func (s *Service) SettleHRSetup(ctx context.Context, actor Actor, eventID string, generation int64) error {
	if generation <= 0 {
		return fmt.Errorf("HR setup requires an accepted generation: %w", ErrInvalid)
	}
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
			return err
		}
		var complete bool
		err := tx.QueryRow(ctx, `SELECT setup_completed_at IS NOT NULL FROM hr_events WHERE event_id=$1 AND generation=$2 AND dispatch_attempted_at IS NOT NULL AND dispatch_state IN ('pending','dispatched') FOR UPDATE`, eventID, generation).Scan(&complete)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("HR setup does not match a committed handoff: %w", ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("read HR setup: %w", err)
		}
		if complete {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE hr_events SET setup_completed_at=now() WHERE event_id=$1`, eventID); err != nil {
			return fmt.Errorf("settle HR setup: %w", err)
		}
		return recordEvidence(ctx, tx, s.signer, actor, "hr.event.setup-completed", "HREvent", eventID, nil, map[string]any{"generation": generation})
	})
}

// PersonLabel links an instance to the HR person it was created for. Only the HR joiner sets it:
// CreateHRInstance here, CreateEntraHRInstance in Entra mode. ApplyInstance refuses it.
const PersonLabel = "muistamo.dev/hr-person-id"

// personLabel returns the document's HR person label, if it has one.
func personLabel(doc muistamov1.AgentInstance) (string, bool) {
	if doc.Metadata.Labels == nil {
		return "", false
	}
	value, ok := (*doc.Metadata.Labels)[PersonLabel]
	return value, ok
}

// CreateHRInstance creates the agent an HR joiner event gives a person, labelled with their HR
// person id. It is for the simulated joiner workflow only and has no HTTP route.
//
// HUMAN REVIEW REQUIRED (AGENTS.md): the label decides which agents the leaver suspends, which a
// privacy export and erasure include, and which the console lists for a person
// (docs/hr-person-label-plan.md). It is set only when the tenant holds an accepted (or legacy,
// pre-decision) joiner event with eventID for exactly this person. An instance that already exists
// is returned unchanged only if it is this person's agent of the same document.
func (s *Service) CreateHRInstance(ctx context.Context, actor Actor, doc muistamov1.AgentInstance, personID, eventID string) (muistamov1.AgentInstanceRecord, bool, error) {
	var rec muistamov1.AgentInstanceRecord
	var created bool
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
			return err
		}
		// The person's lock, as HR intake and the Entra path take it: a leaver for this person
		// cannot be recorded between the supersession check below and the agent's creation.
		if err := lockIdentityHRPerson(ctx, tx, actor.Tenant, personID); err != nil {
			return fmt.Errorf("lock HR person: %w", err)
		}
		var kind, person, decision string
		var generation, latest int64
		err := tx.QueryRow(ctx, `SELECT type, person_id, decision, generation,
				(SELECT coalesce(max(l.generation), 0) FROM hr_events l WHERE l.person_id = e.person_id AND l.decision = 'accepted')
			FROM hr_events e WHERE event_id = $1`, eventID).Scan(&kind, &person, &decision, &generation, &latest)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("HR event %q is not recorded: %w", eventID, ErrConflict)
		}
		if err != nil {
			return fmt.Errorf("read HR event %q: %w", eventID, err)
		}
		if kind != "joiner" || person != personID || (decision != "accepted" && decision != "legacy") {
			return fmt.Errorf("HR event %q is not an accepted joiner for this person: %w", eventID, ErrConflict)
		}
		// As on the Entra path: a joiner a later accepted event (a leaver) has overtaken creates
		// nothing, or the leaver, which may already have run, would never suspend it. Legacy
		// events predate generations and are left as they were.
		if decision == "accepted" && generation != latest {
			return fmt.Errorf("HR event %q is superseded by a later HR event for this person: %w", eventID, ErrConflict)
		}
		labels := map[string]string{}
		if doc.Metadata.Labels != nil {
			for key, value := range *doc.Metadata.Labels {
				labels[key] = value
			}
		}
		if label, ok := labels[PersonLabel]; ok && label != personID {
			return fmt.Errorf("HR person label conflicts with the HR event: %w", ErrConflict)
		}
		labels[PersonLabel] = personID
		doc.Metadata.Labels = &labels

		current, err := lockInstance(ctx, tx, doc.Metadata.Name)
		if err == nil {
			if !equalJSON(current.Document, doc) {
				return fmt.Errorf("instance %q already exists and is not this joiner's: %w", doc.Metadata.Name, ErrConflict)
			}
			rec = current
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		rec, err = createInstance(ctx, tx, s.signer, actor, doc)
		created = err == nil
		return err
	})
	return rec, created, err
}

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
//   - a template whose model alias is not on an approved model matches nothing (E5.4).
//
// Templates that are not published, and clones that are not assignable, never match.
func (s *Service) MatchTemplatesByJobCode(ctx context.Context, actor Actor, jobCode string) ([]TemplateVersionRef, error) {
	var refs []TemplateVersionRef
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT p.template, p.version, coalesce(v.document -> 'spec' -> 'assignment' -> 'hrJobCodes' ? $1, false),
			       v.document -> 'spec' ->> 'modelAlias'
			FROM catalogue_published p
			JOIN agent_template_versions v ON v.tenant_id = p.tenant_id AND v.name = p.template AND v.version = p.version
			ORDER BY p.template`, jobCode)
		if err != nil {
			return fmt.Errorf("match templates for job code %q: %w", jobCode, err)
		}
		type published struct {
			ref     TemplateVersionRef
			matches bool
			alias   string
		}
		var candidates []published
		for rows.Next() {
			var c published
			if err := rows.Scan(&c.ref.Name, &c.ref.Version, &c.matches, &c.alias); err != nil {
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
			compliant, why, err := aliasCompliance(ctx, tx, c.alias)
			if err != nil {
				return err
			}
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
			if !compliant {
				// A template whose model is not approved gets no new agents, clone or not (E5.4).
				// Say so when it would have matched, so a joiner without an agent is explained.
				if len(matching) > 0 || c.matches {
					if err := recordEvidence(ctx, tx, s.signer, actor, "assignment.skipped", "AgentTemplate", c.ref.Name, nil,
						map[string]any{"jobCode": jobCode, "alias": c.alias, "clones": matching,
							"reason": "the template's model alias is not compliant: " + why}); err != nil {
						return err
					}
				}
				continue
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
		owned, err := identityRow(ctx, tx, name)
		if err != nil {
			return err
		}
		if owned.ProviderMode != "simulated" {
			return fmt.Errorf("live identity references come only from verified journal results: %w", ErrConflict)
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
			if to == muistamov1.InstanceStateActive || to == muistamov1.InstanceStateRetired {
				return s.checkSameIdentityState(ctx, actor, name, to)
			}
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

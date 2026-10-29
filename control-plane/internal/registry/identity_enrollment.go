package registry

// HUMAN REVIEW REQUIRED: immutable provider selection and trusted live creation guards.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

func enrollmentRow(ctx context.Context, tx pgx.Tx) (muistamov1.IdentityEnrollmentStatus, error) {
	var out muistamov1.IdentityEnrollmentStatus
	err := tx.QueryRow(ctx, `SELECT tenant_id,binding_version,created_at FROM identity_enrollments`).Scan(&out.TenantId, &out.BindingVersion, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

// EnrollIdentityTenant selects Entra once for an empty development tenant. It shares the
// privacy boundary with HR intake and every instance creation, including public simulation.
func (s *Service) EnrollIdentityTenant(ctx context.Context, actor Actor, version uuid.UUID) (muistamov1.IdentityEnrollmentStatus, error) {
	var out muistamov1.IdentityEnrollmentStatus
	if version == uuid.Nil {
		return out, ErrInvalid
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, true); err != nil {
			return err
		}
		stored, err := enrollmentRow(ctx, tx)
		if err == nil {
			if stored.BindingVersion != version {
				return fmt.Errorf("identity enrollment is immutable: %w", ErrConflict)
			}
			out = stored
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if _, err := identityBindingRow(ctx, tx, version); err != nil {
			return err
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_instances) OR EXISTS(SELECT 1 FROM hr_events)`).Scan(&used); err != nil {
			return err
		}
		if used {
			return fmt.Errorf("live enrollment requires a fresh tenant: %w", ErrConflict)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_enrollments(tenant_id,binding_version) VALUES($1,$2)`, actor.Tenant, version); err != nil {
			return fmt.Errorf("enroll tenant identity mode: %w", err)
		}
		out, err = enrollmentRow(ctx, tx)
		if err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "identity.tenant-enrolled", "IdentityEnrollment", actor.Tenant.String(), nil, out)
	})
	return out, err
}

func (s *Service) IdentityEnrollment(ctx context.Context, actor Actor) (muistamov1.IdentityEnrollmentStatus, error) {
	var out muistamov1.IdentityEnrollmentStatus
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error { var err error; out, err = enrollmentRow(ctx, tx); return err })
	return out, err
}

func (s *Service) IdentityRoute(ctx context.Context, actor Actor, eventID string) (muistamov1.HRIdentityRoute, error) {
	var out muistamov1.HRIdentityRoute
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		out, err = store.HRIdentityRoute(ctx, tx, actor.Tenant, eventID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return out, err
}

// ResolveEntraReceipt is internal to activities. Raw HR fields stay in process and are never
// returned as live workflow input/result. Grace-period actions need only the retained IDs.
func (s *Service) ResolveEntraReceipt(ctx context.Context, actor Actor, id uuid.UUID, current bool) (muistamov1.HREvent, muistamov1.HRIdentityRoute, int64, error) {
	return s.withEntraReceipt(ctx, actor, id, current, nil)
}

// withEntraReceipt holds the privacy/person fence through local lifecycle writes only.
// Provider calls use the separately journaled RunIdentityMutation protocol.
func (s *Service) withEntraReceipt(ctx context.Context, actor Actor, id uuid.UUID, current bool, call func(context.Context, pgx.Tx, muistamov1.HREvent, muistamov1.HRIdentityRoute, int64) error) (muistamov1.HREvent, muistamov1.HRIdentityRoute, int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var event muistamov1.HREvent
	var route muistamov1.HRIdentityRoute
	var generation int64
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
			return err
		}
		var person, eventID, kind, decision, dispatch string
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT person_id,event_id,type,generation,decision,dispatch_state,payload FROM hr_events WHERE receipt_id=$1`, id).Scan(&person, &eventID, &kind, &generation, &decision, &dispatch, &raw); err != nil {
			return err
		}
		if err := lockIdentityHRPerson(ctx, tx, actor.Tenant, person); err != nil {
			return err
		}
		var err error
		route, err = store.HRIdentityRoute(ctx, tx, actor.Tenant, eventID)
		if err != nil {
			return err
		}
		if route.ProviderMode != "entra" || route.BindingVersion == nil || decision != "accepted" || dispatch == "cancelled" || generation <= 0 {
			return ErrConflict
		}
		version, err := store.IdentityEnrollmentVersion(ctx, tx)
		if err != nil {
			return err
		}
		if version == nil || *version != *route.BindingVersion {
			return ErrConflict
		}
		if err := requireIdentityHRReceipt(ctx, tx, id); err != nil {
			return err
		}
		if current {
			latest, gen, _, err := latestIdentityHR(ctx, tx, person)
			if err != nil {
				return err
			}
			if latest != eventID || gen != generation {
				return fmt.Errorf("live lifecycle receipt is superseded: %w", ErrConflict)
			}
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			return fmt.Errorf("decode retained HR fields: %w", err)
		}
		event.Id, event.Type, event.Person.Id = eventID, muistamov1.HREventType(kind), person
		if call != nil {
			return call(ctx, tx, event, route, generation)
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return event, route, generation, err
}

// SuspendEntraPerson enumerates immutable HR associations and commits every local suspension
// together, before a workflow may make any provider call. A signature failure rolls back all.
func (s *Service) SuspendEntraPerson(ctx context.Context, actor Actor, id uuid.UUID) ([]string, error) {
	var names []string
	_, _, _, err := s.withEntraReceipt(ctx, actor, id, true, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, _ muistamov1.HRIdentityRoute, _ int64) error {
		if event.Type != "leaver" {
			return ErrConflict
		}
		rows, err := tx.Query(ctx, `SELECT i.instance_name FROM instance_identities i JOIN hr_events h ON h.tenant_id=i.tenant_id AND h.receipt_id=i.assignment_receipt_id JOIN agent_instances a ON a.tenant_id=i.tenant_id AND a.name=i.instance_name WHERE i.provider_mode='entra' AND h.person_id=$1 AND a.state<>'retired' ORDER BY i.instance_name`, event.Person.Id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			names = append(names, name)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, name := range names {
			if _, err := s.setEntraState(ctx, tx, actor, event, name, "suspended"); err != nil {
				return err
			}
		}
		return nil
	})
	return names, err
}

func (s *Service) SetEntraState(ctx context.Context, actor Actor, id uuid.UUID, name string, to muistamov1.InstanceState) error {
	if to != "active" && to != "suspended" && to != "retired" {
		return ErrInvalid
	}
	_, _, _, err := s.withEntraReceipt(ctx, actor, id, to != "retired", func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, _ muistamov1.HRIdentityRoute, _ int64) error {
		if (to == "active" && event.Type != "joiner") || (to != "active" && event.Type != "leaver") {
			return ErrConflict
		}
		_, err := s.setEntraState(ctx, tx, actor, event, name, to)
		return err
	})
	return err
}

func (s *Service) setEntraState(ctx context.Context, tx pgx.Tx, actor Actor, event muistamov1.HREvent, name string, to muistamov1.InstanceState) (muistamov1.AgentInstanceRecord, error) {
	current, err := lockInstance(ctx, tx, name)
	if err != nil {
		return current, err
	}
	var person string
	var observed muistamov1.InstanceIdentityStatusObservedState
	if err := tx.QueryRow(ctx, `SELECT h.person_id,i.observed_state FROM instance_identities i JOIN hr_events h ON h.tenant_id=i.tenant_id AND h.receipt_id=i.assignment_receipt_id WHERE i.instance_name=$1 AND i.provider_mode='entra'`, name).Scan(&person, &observed); err != nil {
		return current, err
	}
	if person != event.Person.Id {
		return current, ErrConflict
	}
	// Historical work can finish a recorded deletion, but cannot borrow a newer
	// leaver's no-effect proof to retire a never-created instance under an old receipt.
	if to == "retired" && observed != "deleted" {
		latest, _, _, err := latestIdentityHR(ctx, tx, person)
		if err != nil {
			return current, err
		}
		if latest != event.Id {
			return current, ErrConflict
		}
	}
	if err := checkIdentityTransition(ctx, tx, current, to, person); err != nil {
		return current, err
	}
	if current.Document.Spec.State == to {
		return current, nil
	}
	if !CanTransition(current.Document.Spec.State, to) {
		return current, ErrConflict
	}
	if err := revokeBeforeReactivation(ctx, tx, s.signer, actor, current, to); err != nil {
		return current, err
	}
	next := current.Document
	next.Spec.State = to
	updated, err := updateInstance(ctx, tx, current, next)
	if err != nil {
		return current, err
	}
	err = recordEvidence(ctx, tx, s.signer, actor, "instance.transitioned", "AgentInstance", name, map[string]any{"state": current.Document.Spec.State}, map[string]any{"state": to, "revision": updated.Revision})
	return updated, err
}

func (s *Service) PriorEntraLeavers(ctx context.Context, actor Actor, id uuid.UUID) ([]string, error) {
	var ids []string
	_, _, _, err := s.withEntraReceipt(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, _ muistamov1.HRIdentityRoute, generation int64) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT workflow_id FROM hr_events WHERE person_id=$1 AND type='leaver' AND identity_mode='entra' AND generation<$2 AND dispatch_state='dispatched' AND workflow_id<>'' ORDER BY workflow_id`, event.Person.Id, generation)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				return err
			}
			ids = append(ids, value)
		}
		return rows.Err()
	})
	return ids, err
}

// ConfirmEntraNoIdentity proves only that Muistamo never committed a creation intent for this
// instance. A missing provider response/discovery match or any consumed create intent is not proof.
func (s *Service) ConfirmEntraNoIdentity(ctx context.Context, actor Actor, id uuid.UUID, name string) (bool, error) {
	confirmed := false
	_, _, _, err := s.withEntraReceipt(ctx, actor, id, true, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, _ muistamov1.HRIdentityRoute, generation int64) error {
		if event.Type != "leaver" {
			return ErrConflict
		}
		if _, err := lockInstance(ctx, tx, name); err != nil {
			return err
		}
		owned, err := identityRow(ctx, tx, name)
		if err != nil {
			return err
		}
		var person string
		if err := tx.QueryRow(ctx, `SELECT person_id FROM hr_events WHERE receipt_id=$1`, owned.AssignmentReceiptId).Scan(&person); err != nil {
			return err
		}
		if person != event.Person.Id || owned.ProviderMode != "entra" {
			return ErrConflict
		}
		if owned.ProviderId != nil || owned.CreationId != nil || owned.ObservedState != "unprovisioned" {
			return nil
		}
		var reserved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1)`, owned.Id).Scan(&reserved); err != nil {
			return err
		}
		if reserved {
			return nil
		}
		proof, err := noIdentityProof(ctx, tx, owned, id, generation)
		if err != nil {
			return err
		}
		if !proof {
			if err := recordEvidence(ctx, tx, s.signer, actor, "identity.no-effect-confirmed", "InstanceIdentity", owned.Id.String(), nil, map[string]any{"reason": "no-create-intent", "bindingVersion": owned.BindingVersion, "hrReceiptId": id, "generation": generation}); err != nil {
				return err
			}
		}
		confirmed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return confirmed, nil
}

func noIdentityProof(ctx context.Context, tx pgx.Tx, owned muistamov1.InstanceIdentityStatus, id uuid.UUID, generation int64) (bool, error) {
	if owned.BindingVersion == nil {
		return false, ErrConflict
	}
	var proof bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM evidence_events WHERE action='identity.no-effect-confirmed' AND subject_kind='InstanceIdentity' AND subject_name=$1 AND after->>'reason'='no-create-intent' AND after->>'bindingVersion'=$2 AND after->>'hrReceiptId'=$3 AND after->>'generation'=$4)`, owned.Id.String(), owned.BindingVersion.String(), id.String(), fmt.Sprint(generation)).Scan(&proof)
	return proof, err
}

func noIdentityRetirement(ctx context.Context, tx pgx.Tx, owned muistamov1.InstanceIdentityStatus, person string) (bool, error) {
	if owned.ProviderId != nil || owned.CreationId != nil || owned.ObservedState != "unprovisioned" {
		return false, nil
	}
	var reserved bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1)`, owned.Id).Scan(&reserved); err != nil {
		return false, err
	}
	if reserved {
		return false, nil
	}
	latest, generation, kind, err := latestIdentityHR(ctx, tx, person)
	if err != nil {
		return false, err
	}
	if kind != "leaver" {
		return false, nil
	}
	var receipt uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT receipt_id FROM hr_events WHERE event_id=$1 AND generation=$2`, latest, generation).Scan(&receipt); err != nil {
		return false, err
	}
	if err := requireIdentityHRReceipt(ctx, tx, receipt); err != nil {
		return false, err
	}
	return noIdentityProof(ctx, tx, owned, receipt, generation)
}

// SettleEntraSetup waits for earlier person-fenced writers before releasing this receipt's
// setup/erasure barrier, including when its workflow stopped after supersession or cancellation.
func (s *Service) SettleEntraSetup(ctx context.Context, actor Actor, id uuid.UUID) error {
	_, _, _, err := s.withEntraReceipt(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, _ muistamov1.HRIdentityRoute, generation int64) error {
		var complete bool
		err := tx.QueryRow(ctx, `SELECT setup_completed_at IS NOT NULL FROM hr_events WHERE receipt_id=$1 AND generation=$2 AND dispatch_attempted_at IS NOT NULL AND dispatch_state IN ('pending','dispatched') FOR UPDATE`, id, generation).Scan(&complete)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE hr_events SET setup_completed_at=now() WHERE receipt_id=$1`, id); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "hr.event.setup-completed", "HREvent", event.Id, nil, map[string]any{"generation": generation})
	})
	return err
}

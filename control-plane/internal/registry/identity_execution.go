package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// IdentityMutation is an internal adapter callback. It is invoked once only for a newly
// committed intent. It must use ctx for every provider request and return verified ownership.
type IdentityMutation func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error)

// SettledIdentityObservation reads pending work and its last provider observation under the
// same person/instance fence. A successful historical action alone is not global confirmation.
func (s *Service) SettledIdentityObservation(ctx context.Context, actor Actor, id uuid.UUID) (muistamov1.InstanceIdentityStatus, bool, error) {
	var owned muistamov1.InstanceIdentityStatus
	settled := false
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		name, err := operationInstance(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := identityPersonLock(ctx, tx, actor.Tenant, name); err != nil {
			return err
		}
		if _, err := lockInstance(ctx, tx, name); err != nil {
			return err
		}
		owned, err = identityRow(ctx, tx, name)
		if err != nil {
			return err
		}
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1 AND state IN ('pending','indeterminate'))`, owned.Id).Scan(&pending); err != nil {
			return err
		}
		settled = !pending
		return nil
	})
	return owned, settled, err
}

// RunIdentityMutation consumes the first invocation's in-memory permit immediately; callers
// never persist that permit in workflow history. The durable intent means MAY HAVE RUN after
// any crash, including one before this callback. Existing intents only return journal status.
// There are no transaction or mutation retries. The bounded person fence serializes HR intake
// through the provider request/result commit; it cannot settle a request after a process crash.
func (s *Service) RunIdentityMutation(ctx context.Context, actor Actor, name, eventID string, generation int64, action muistamov1.IdentityOperationStatusAction, call IdentityMutation) (muistamov1.IdentityOperationStatus, bool, error) {
	if call == nil {
		return muistamov1.IdentityOperationStatus{}, false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	op, fresh, err := s.ReserveIdentityOperation(ctx, actor, name, eventID, generation, action)
	if err != nil || !fresh {
		return op, false, err
	}
	called := false
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		person, err := identityPersonLock(ctx, tx, actor.Tenant, name)
		if err != nil {
			return err
		}
		current, err := lockInstance(ctx, tx, name)
		if err != nil {
			return err
		}
		owned, err := identityRow(ctx, tx, name)
		if err != nil {
			return err
		}
		stored, err := operationRow(tx.QueryRow(ctx, operationColumns+` WHERE id=$1 FOR UPDATE`, op.Id))
		if err != nil {
			return err
		}
		if owned.ProviderMode != "entra" || owned.BindingVersion == nil || *owned.BindingVersion != stored.BindingVersion || stored.InstanceIdentityId != owned.Id || stored.State != "pending" || stored.Id != op.Id || owned.CreationId == nil || *owned.CreationId != stored.CreationId || person == "" {
			return fmt.Errorf("identity mutation fence does not match its committed intent: %w", ErrConflict)
		}
		latest, gen, kind, err := latestIdentityHR(ctx, tx, person)
		if err != nil {
			return err
		}
		want := "joiner"
		if action == "disable" || action == "delete" {
			want = "leaver"
		}
		if latest != eventID || gen != generation || kind != want || stored.HrGeneration != generation || stored.Action != action {
			return fmt.Errorf("identity mutation superseded before provider call: %w", ErrConflict)
		}
		if err := requireIdentityHRReceipt(ctx, tx, stored.HrReceiptId); err != nil {
			return err
		}
		if action == "create" || action == "enable" {
			if current.Document.Spec.State == "retired" || current.Document.Spec.State == "quarantined" {
				return ErrConflict
			}
		} else if current.Document.Spec.State != "suspended" && current.Document.Spec.State != "retired" {
			return ErrConflict
		}
		var unresolved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1 AND id<>$2 AND state IN ('pending','indeterminate'))`, owned.Id, op.Id).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved && action != "disable" {
			return fmt.Errorf("conflicting provider operation is unresolved: %w", ErrConflict)
		}
		if action == "create" {
			if owned.ProviderId != nil || stored.CreationId != stored.Id {
				return ErrConflict
			}
		} else if owned.ProviderId == nil || stored.ProviderId == nil || *owned.ProviderId != *stored.ProviderId || owned.ObservedState == "deleted" {
			return ErrConflict
		}
		if action == "delete" && owned.ObservedState != "disabled" {
			return ErrConflict
		}
		called = true
		provider, observed, err := call(ctx, stored, owned)
		if err != nil {
			return err
		}
		if provider == uuid.Nil {
			return ErrInvalid
		}
		return s.commitIdentityResult(ctx, tx, actor, current, owned, stored, stored.CreationId, provider, observed)
	})
	if err != nil {
		return op, called, err
	}
	stored, err := s.IdentityOperation(ctx, actor, op.Id)
	return stored, called, err
}

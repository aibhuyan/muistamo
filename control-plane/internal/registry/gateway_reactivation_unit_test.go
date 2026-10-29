package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// keysRow answers the backstop's EXISTS query.
type keysRow struct{ active bool }

func (r keysRow) Scan(dest ...any) error {
	*dest[0].(*bool) = r.active
	return nil
}

type keysTx struct {
	pgx.Tx
	active bool
}

func (tx keysTx) QueryRow(context.Context, string, ...any) pgx.Row { return keysRow{tx.active} }

// updateInstance refuses to reactivate a suspended instance that still has active keys, whichever
// path calls it, so a path that forgets revokeBeforeReactivation fails closed.
func TestUpdateInstanceRefusesReactivationWithActiveKeys(t *testing.T) {
	current := muistamov1.AgentInstanceRecord{Revision: 1}
	current.Document.Metadata.Name = "analyst-intern-person-a"
	current.Document.Spec.State = muistamov1.InstanceStateSuspended
	next := current.Document
	next.Spec.State = muistamov1.InstanceStateActive
	if _, err := updateInstance(context.Background(), keysTx{active: true}, current, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("reactivation with active keys = %v, want a conflict", err)
	}
	if err := refuseReactivationWithKeys(context.Background(), keysTx{active: false}, current, next); err != nil {
		t.Fatalf("reactivation without keys refused: %v", err)
	}
	review := current
	review.Document.Spec.State = muistamov1.InstanceStateUnderReview
	if err := refuseReactivationWithKeys(context.Background(), keysTx{active: true}, review, next); err != nil {
		t.Fatalf("under-review -> active refused although it is not a reinstatement: %v", err)
	}
}

package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

type scopeSelectorRow func(...any) error

func (r scopeSelectorRow) Scan(dest ...any) error { return r(dest...) }

// pgx.Tx is the existing transaction seam. The third read stands for data becoming visible
// after an initially absent selector. No production hook or alternate database path is added.
type changingPublicationTx struct {
	pgx.Tx
	reads          int
	laterScopeRead bool
}

func (tx *changingPublicationTx) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	tx.reads++
	switch tx.reads {
	case 1:
		return scopeSelectorRow(func(dest ...any) error {
			*dest[0].(*string) = "analyst-intern"
			*dest[1].(*string) = "follow"
			return nil
		})
	case 2:
		return scopeSelectorRow(func(...any) error { return pgx.ErrNoRows })
	default:
		tx.laterScopeRead = true
		// A valid publication is now visible to the unlocked fallback. Without the early
		// refusal, effectiveSpec can resolve it successfully despite never locking it.
		return scopeSelectorRow(func(dest ...any) error {
			switch tx.reads {
			case 3: // instance
				*dest[0].(*string) = "follow-instance"
				*dest[1].(*int) = 1
				*dest[2].(*time.Time) = time.Time{}
				*dest[3].(*time.Time) = time.Time{}
				*dest[4].(*[]byte) = []byte(`{"metadata":{"name":"follow-instance"},"spec":{"templateRef":{"name":"analyst-intern","version":"1"},"cloneRef":"follow-clone"}}`)
			case 4: // clone
				*dest[0].(*int) = 1
				*dest[1].(*time.Time) = time.Time{}
				*dest[2].(*time.Time) = time.Time{}
				*dest[3].(*string) = "fixture"
				*dest[4].(*string) = "fixture"
				*dest[5].(**int) = nil
				*dest[6].(*[]byte) = []byte(`{"metadata":{"name":"follow-clone"},"spec":{"template":"analyst-intern","sync":"follow"}}`)
			case 5: // newly appeared publication
				*dest[0].(*int) = 1
			case 6: // immutable template version
				*dest[0].(*string) = "fixture"
				*dest[1].(*[]byte) = []byte(`{"spec":{"modelAlias":"late-visible-alias"}}`)
				*dest[2].(*time.Time) = time.Time{}
				*dest[3].(*string) = "fixture"
			default:
				return errors.New("unexpected scope fixture query")
			}
			return nil
		})
	}
}

func TestGatewayMissingLockedPublicationNeverFallsThroughToNewScope(t *testing.T) {
	tx := &changingPublicationTx{}
	clone := "follow-clone"
	inst := muistamov1.AgentInstanceRecord{}
	inst.Document.Metadata.Name = "follow-instance"
	inst.Document.Spec.CloneRef = &clone
	eff, err := gatewayEffectiveSpec(t.Context(), tx, inst)
	if tx.laterScopeRead {
		if err != nil || eff.Spec.ModelAlias != "late-visible-alias" {
			t.Fatalf("scope-race fixture did not reach the newly visible scope: %+v %v", eff, err)
		}
		t.Fatal("missing locked publication permitted a later unlocked scope read")
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("missing locked follow publication = %v", err)
	}
}

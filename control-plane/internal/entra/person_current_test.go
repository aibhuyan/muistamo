package entra

// HUMAN REVIEW REQUIRED: who the knowledge service admits to its console routes
// (docs/console-entra-signin-plan.md, PR 0). Current answers by exactly the delegation's rule.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func (f delegationFixture) current(t *testing.T, token string) muistamov1.KnowledgePersonCurrent {
	t.Helper()
	f.actor.RequestID = uuid.NewString()
	answer, err := f.delegator.Current(context.Background(), f.actor, muistamov1.KnowledgePersonCurrentRequest{UserToken: token, Nonce: "00000000000000000000000000000000"})
	if err != nil {
		t.Fatal(err)
	}
	return answer
}

func notCurrent(t *testing.T, answer muistamov1.KnowledgePersonCurrent, reason muistamov1.KnowledgePersonCurrentReason) {
	t.Helper()
	if answer.Current || answer.Reason == nil || *answer.Reason != reason {
		t.Fatalf("answer = %+v, want not current: %s", answer, reason)
	}
}

func TestAPersonIsCurrentWhileTheirLinkStandsAndNotAfterLeaving(t *testing.T) {
	f := setupDelegation(t)
	if a := f.current(t, f.dir.token(userClaims(userA))); !a.Current || a.Reason != nil {
		t.Fatalf("linked joiner = %+v", a)
	}
	// Someone the directory knows but Muistamo has no current link for.
	notCurrent(t, f.current(t, f.dir.token(userClaims(userB))), "user-unlinked")

	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	notCurrent(t, f.current(t, f.dir.token(userClaims(userA))), "user-unlinked")
	// A rehire whose joiner has not (yet) linked the user is not current either, as for a
	// delegation: the link's joiner must be the person's latest accepted HR event.
	seedAdapterHR(t, f.conn, f.key, f.actor, "rehire", "joiner", 3)
	notCurrent(t, f.current(t, f.dir.token(userClaims(userA))), "user-unlinked")

	// Read-only: no evidence, and Entra is never asked for an exchange.
	if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.refused"); n != "0" {
		t.Fatalf("a status answer was recorded as a refusal: %s", n)
	}
	if f.dir.exchanges != 0 || f.dir.assertions != 0 {
		t.Fatalf("a status answer reached the exchange")
	}
}

func TestCurrentAnswersExactlyAsTheDelegationDecides(t *testing.T) {
	for name, change := range map[string]string{
		"erased link":     `DELETE FROM person_entra_links`,
		"conflicted link": `UPDATE person_entra_links SET status='conflict', entra_user_object_id=NULL`,
	} {
		t.Run(name, func(t *testing.T) {
			f := setupDelegation(t)
			testdb.Exec(t, f.db.OwnerURL, change)
			notCurrent(t, f.current(t, f.dir.token(userClaims(userA))), "user-unlinked")
			_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
			refusedWith(t, err, "user-unlinked")
		})
	}
	t.Run("enrolled with another directory", func(t *testing.T) {
		f := setupDelegation(t)
		testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE hr_events DROP CONSTRAINT hr_identity_enrollment`)
		testdb.Exec(t, f.db.OwnerURL, `UPDATE identity_enrollments SET binding_version=$1`, otherDirectory(t, f))
		notCurrent(t, f.current(t, f.dir.token(userClaims(userA))), "identity-not-ready")
	})
	t.Run("not enrolled", func(t *testing.T) {
		f := setupDelegation(t)
		testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE hr_events DROP CONSTRAINT hr_identity_enrollment`)
		testdb.Exec(t, f.db.OwnerURL, `DELETE FROM identity_enrollments WHERE binding_version<>$1`, otherDirectory(t, f))
		notCurrent(t, f.current(t, f.dir.token(userClaims(userA))), "user-unlinked")
	})
	// A suspended agent stops a delegation but not the person: they are still an employee.
	t.Run("agent suspended", func(t *testing.T) {
		f := setupDelegation(t)
		if _, err := f.svc.TransitionTo(context.Background(), f.actor, f.name, muistamov1.InstanceStateSuspended); err != nil {
			t.Fatal(err)
		}
		if a := f.current(t, f.dir.token(userClaims(userA))); !a.Current {
			t.Fatalf("a current employee with a suspended agent = %+v", a)
		}
	})
}

func TestCurrentRefusesTokensThatAreNotAPersonsTokenForMuistamo(t *testing.T) {
	f := setupDelegation(t)
	with := func(change func(map[string]any)) string {
		claims := userClaims(userA)
		change(claims)
		return f.dir.token(claims)
	}
	for name, token := range map[string]string{
		"expired":           with(func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }),
		"another audience":  with(func(c map[string]any) { c["aud"] = "https://graph.microsoft.com" }),
		"another directory": with(func(c map[string]any) { c["tid"] = uuid.NewString() }),
		"app token type":    with(func(c map[string]any) { c["idtyp"] = "app" }),
		"not a token":       "obviously-fake-not-a-jwt",
		"oversized":         f.dir.token(userClaims(userA)) + strings.Repeat("A", maxUserToken),
	} {
		t.Run(name, func(t *testing.T) {
			notCurrent(t, f.current(t, token), "token-invalid")
		})
	}
	// A tenant the control plane holds no binding for is not configured.
	other := f.actor
	other.Tenant = uuid.New()
	if _, err := f.delegator.Current(context.Background(), other, muistamov1.KnowledgePersonCurrentRequest{UserToken: f.dir.token(userClaims(userA))}); !errors.Is(err, registry.ErrDelegationNotConfigured) {
		t.Fatalf("another tenant = %v", err)
	}
}

func TestATokenThatCannotBeCheckedIsNoAnswer(t *testing.T) {
	f := setupDelegation(t)
	// The directory's signing keys cannot be fetched: an error, never "not current", so the
	// knowledge service answers "try again" and keeps nothing.
	f.client.http = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("keys unreachable")
	})}
	f.actor.RequestID = uuid.NewString()
	_, err := f.delegator.Current(context.Background(), f.actor, muistamov1.KnowledgePersonCurrentRequest{UserToken: f.dir.token(userClaims(userA))})
	if err == nil || errors.Is(err, registry.ErrDelegationNotConfigured) {
		t.Fatalf("unreachable keys = %v, want an error", err)
	}
}

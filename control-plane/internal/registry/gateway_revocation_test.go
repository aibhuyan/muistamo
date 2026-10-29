package registry_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// The leaver path's revocation (docs/agentgateway-plan.md, step 4). HUMAN REVIEW REQUIRED.

func TestLeaverRevocationRevokesEveryActiveKeyOfTheInstanceOnly(t *testing.T) {
	f, req := gatewayFixture(t)
	other := instance("requested")
	other.Metadata.Name = "analyst-intern-person-b"
	other.Spec.Binding.Ref = "person-b@example.invalid"
	if _, _, err := f.svc.ApplyInstance(t.Context(), f.actor, other, ""); err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,state}','"active"')`)
	var mine []uuid.UUID
	for range 2 {
		issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
		if err != nil {
			t.Fatal(err)
		}
		mine = append(mine, issued.Key.Id)
	}
	expired, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	mine = append(mine, expired.Key.Id)
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE virtual_keys DISABLE TRIGGER virtual_keys_stamp`)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE virtual_keys SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day' WHERE id=$1`, expired.Key.Id)
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE virtual_keys ENABLE TRIGGER virtual_keys_stamp`)
	already, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RevokeKey(t.Context(), f.actor, already.Key.Id, "rotation"); err != nil {
		t.Fatal(err)
	}
	otherReq := req
	otherReq.Instance = other.Metadata.Name
	theirs, err := f.svc.IssueKey(t.Context(), f.actor, otherReq)
	if err != nil {
		t.Fatal(err)
	}

	workflow := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:leaver-test", RequestID: "hr-event:test"}
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "suspended"); err != nil {
		t.Fatal(err)
	}
	before := f.events(t)
	got, err := f.svc.RevokeInstanceKeys(t.Context(), workflow, req.Instance)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(mine, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	if !slices.Equal(got, mine) {
		t.Fatalf("revoked %v, want exactly the instance's active keys %v", got, mine)
	}
	if n := f.events(t) - before; n != len(mine) {
		t.Fatalf("wrote %d evidence events, want one per revoked key (%d)", n, len(mine))
	}
	for _, id := range mine {
		key, err := f.svc.GetKey(t.Context(), f.actor, id)
		if err != nil || key.Status != "revoked" || key.RevokeReason == nil || *key.RevokeReason != "leaver" ||
			key.RevokedBy == nil || *key.RevokedBy != workflow.Name {
			t.Errorf("key %s after leaver = %+v, %v", id, key, err)
		}
	}
	if key, _ := f.svc.GetKey(t.Context(), f.actor, already.Key.Id); key.RevokeReason == nil || *key.RevokeReason != "rotation" {
		t.Errorf("an already revoked key was rewritten: %+v", key)
	}
	if key, _ := f.svc.GetKey(t.Context(), f.actor, theirs.Key.Id); key.Status != "active" {
		t.Errorf("another instance's key was revoked: %+v", key)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='gateway.key.revoked'
		AND actor=$1 AND after->>'reason'='leaver' AND after->>'by'='lifecycle'`, workflow.Name); n != len(mine) {
		t.Errorf("leaver revocation evidence = %d events, want %d", n, len(mine))
	}

	// A retry finds nothing active and records nothing.
	before = f.events(t)
	if again, err := f.svc.RevokeInstanceKeys(t.Context(), workflow, req.Instance); err != nil || len(again) != 0 || f.events(t) != before {
		t.Fatalf("retry revoked %v, err %v, evidence delta %d", again, err, f.events(t)-before)
	}
}

func TestLeaverRevocationIsFinalAcrossReactivation(t *testing.T) {
	f, req := gatewayFixture(t)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	workflow := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:leaver-test", RequestID: "hr-event:test"}
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RevokeInstanceKeys(t.Context(), workflow, req.Instance); err != nil {
		t.Fatal(err)
	}
	// Even if the instance becomes active again (a rehire), the old key stays refused.
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,state}','"active"')`)
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, &route)
	if err != nil || d.Allowed {
		t.Fatalf("a leaver's key was allowed after reactivation: %+v, %v", d, err)
	}
	if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `UPDATE virtual_keys SET status='active' WHERE id=$1`, issued.Key.Id); err == nil {
		t.Fatal("the server role reactivated a revoked key")
	}
}

func TestLeaverRevocationWithoutEvidenceRevokesNothing(t *testing.T) {
	f, req := gatewayFixture(t)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "suspended"); err != nil {
		t.Fatal(err)
	}
	broken := registry.New(f.conn, failingSigner{f.key})
	workflow := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:leaver-test", RequestID: "hr-event:test"}
	before := f.events(t)
	if got, err := broken.RevokeInstanceKeys(t.Context(), workflow, req.Instance); !errors.Is(err, registry.ErrEvidence) || got != nil {
		t.Fatalf("revocation without evidence = %v, %v", got, err)
	}
	if key, err := f.svc.GetKey(t.Context(), f.actor, issued.Key.Id); err != nil || key.Status != "active" || f.events(t) != before {
		t.Fatalf("failed revocation changed state: %+v, %v", key, err)
	}
}

// Revocation refuses an instance that is still active: IssueKey could otherwise mint a key right
// after it commits. The leaver suspends first.
func TestLeaverRevocationRequiresASuspendedInstance(t *testing.T) {
	f, req := gatewayFixture(t)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	workflow := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:leaver-test", RequestID: "hr-event:test"}
	before := f.events(t)
	if got, err := f.svc.RevokeInstanceKeys(t.Context(), workflow, req.Instance); !errors.Is(err, registry.ErrConflict) || got != nil {
		t.Fatalf("revocation of an active instance = %v, %v; want a conflict", got, err)
	}
	if key, _ := f.svc.GetKey(t.Context(), f.actor, issued.Key.Id); key.Status != "active" || f.events(t) != before {
		t.Fatalf("refused revocation changed state: %+v", key)
	}
}

// Keys issued concurrently with a leaver either exist before the suspension, and are revoked, or
// are refused: no active key survives suspend-then-revoke.
func TestLeaverRevocationRacesIssuanceWithoutSurvivors(t *testing.T) {
	f, req := gatewayFixture(t)
	workflow := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:leaver-test", RequestID: "hr-event:test"}
	stop := make(chan struct{})
	done := make(chan int)
	go func() {
		minted := 0
		for {
			select {
			case <-stop:
				done <- minted
				return
			default:
			}
			if _, err := f.svc.IssueKey(context.Background(), f.actor, req); err == nil {
				minted++
			}
		}
	}()
	time.Sleep(200 * time.Millisecond)
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RevokeInstanceKeys(t.Context(), workflow, req.Instance); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	minted := <-done
	if minted == 0 {
		t.Fatal("the race never issued a key before suspension; the test proves nothing")
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM virtual_keys WHERE status='active'`); n != 0 {
		t.Fatalf("%d of %d keys survived the leaver", n, minted)
	}
}


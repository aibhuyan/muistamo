package registry_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func liveGatewayKey(t *testing.T) (fixture, muistamov1.VirtualKeyIssued) {
	t.Helper()
	f, _, rec := liveIdentity(t)
	name := rec.Document.Metadata.Name
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, []string{f.actor.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	create, _, err := f.svc.ReserveIdentityOperation(t.Context(), f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	provider := uuid.New()
	if err := f.svc.CommitIdentityResult(t.Context(), f.actor, create.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	enable, _, err := f.svc.ReserveIdentityOperation(t.Context(), f.actor, name, "join", 1, "enable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(t.Context(), f.actor, enable.Id, create.CreationId, provider, "enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, name, "active"); err != nil {
		t.Fatal(err)
	}
	key, err := f.svc.IssueKey(t.Context(), f.actor, muistamov1.VirtualKeyRequest{Instance: name, Aliases: []string{"reasoning-default"}, MonthlyBudget: muistamov1.Money{Amount: "25", Currency: "EUR"}})
	if err != nil {
		t.Fatal(err)
	}
	return f, key
}

func TestGatewayAuthorizationRefusesAcceptedLiveLeaver(t *testing.T) {
	f, key := liveGatewayKey(t)
	call, route := modelCall()
	if d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, key.Secret, call, &route); err != nil || !d.Allowed {
		t.Fatalf("ready live identity was refused: %+v %v", d, err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	if d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, key.Secret, call, &route); err != nil || d.Allowed || d.Reason != "identity-not-ready" {
		t.Fatalf("accepted live leaver was allowed before suspension: %+v %v", d, err)
	}
}

func TestGatewayAuthorizationSerializesWithRevocationSuspensionAndHR(t *testing.T) {
	for _, action := range []string{"revoke", "suspend", "leaver"} {
		t.Run(action, func(t *testing.T) {
			var f fixture
			var key muistamov1.VirtualKeyIssued
			if action == "leaver" {
				f, key = liveGatewayKey(t)
			} else {
				var req muistamov1.VirtualKeyRequest
				f, req = gatewayFixture(t)
				var err error
				key, err = f.svc.IssueKey(t.Context(), f.actor, req)
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			gateConn, err := pgx.Connect(ctx, f.db.OwnerURL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gateConn.Close(context.Background()) }()
			gate, err := gateConn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gate.Rollback(context.Background()) }()
			if _, err := gate.Exec(ctx, `LOCK TABLE model_catalogue IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			observer, err := pgx.Connect(ctx, f.db.OwnerURL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = observer.Close(context.Background()) }()
			call, route := modelCall()
			authorized := make(chan error, 1)
			go func() {
				d, err := f.svc.AuthorizeGateway(ctx, f.actor.Tenant, key.Secret, call, &route)
				if err == nil && !d.Allowed {
					err = errors.New("ready authorization denied")
				}
				authorized <- err
			}()
			waitForGatewayLock(t, ctx, observer, `query LIKE '%model_catalogue%' AND wait_event_type='Lock'`)
			changed := make(chan error, 1)
			go func() {
				switch action {
				case "revoke":
					_, err := f.svc.RevokeKey(ctx, f.actor, key.Key.Id, "operator")
					changed <- err
				case "suspend":
					_, err := f.svc.TransitionTo(ctx, f.actor, key.Key.Instance, "suspended")
					changed <- err
				case "leaver":
					var event muistamov1.HREvent
					event.Id, event.Type, event.OccurredAt = "leave", "leaver", time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
					event.Person.Id, event.Person.Email, event.Person.JobCode = "HR-PERSON", "person-a@example.invalid", "INTERN"
					_, err := (&lifecycle.Intake{DB: f.conn, Signer: f.key}).Accept(ctx, f.actor.Tenant, "hris:test", "leave", event)
					if errors.Is(err, lifecycle.ErrDispatch) {
						err = nil
					}
					changed <- err
				}
			}()
			predicate := `query LIKE '%FROM virtual_keys%FOR UPDATE%' AND wait_event_type='Lock'`
			if action == "suspend" {
				predicate = `query LIKE '%agent_instances%FOR UPDATE%' AND wait_event_type='Lock'`
			}
			if action == "leaver" {
				predicate = `wait_event='advisory'`
			}
			waited := gatewayLockObserved(ctx, observer, predicate)
			if err := gate.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-authorized; err != nil {
				t.Fatal(err)
			}
			if err := <-changed; err != nil {
				t.Fatal(err)
			}
			if !waited {
				t.Errorf("%s escaped the authorization fence before ledger insertion", action)
			}
			if d, err := f.svc.AuthorizeGateway(ctx, f.actor.Tenant, key.Secret, call, &route); err != nil || d.Allowed {
				t.Errorf("call after %s allowed: %+v %v", action, d, err)
			}
		})
	}
}

func gatewayLockObserved(ctx context.Context, conn *pgx.Conn, predicate string) bool {
	for deadline := time.Now().Add(400 * time.Millisecond); time.Now().Before(deadline); {
		var waiting bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND `+predicate+`)`).Scan(&waiting); err != nil {
			return false
		}
		if waiting {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func waitForGatewayLock(t *testing.T, ctx context.Context, conn *pgx.Conn, predicate string) {
	t.Helper()
	if !gatewayLockObserved(ctx, conn, predicate) {
		t.Fatal("authorization did not reach the pre-insert gate")
	}
}

func TestGatewayAuthorizationTenantComesFromTrustedListener(t *testing.T) {
	f, req := gatewayFixture(t)
	key, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateTenant(t.Context(), f.db.OwnerURL, "listener-tenant")
	if err != nil {
		t.Fatal(err)
	}
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), other, key.Secret, call, &route)
	if err != nil || d.Allowed || d.Reason != "invalid-key" {
		t.Fatalf("other tenant key accepted: %+v %v", d, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id=$1 AND action='gateway.call.denied'`, other); n != 1 {
		t.Fatalf("configured listener denial evidence = %d", n)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id=$1 AND action='gateway.call.denied'`, f.actor.Tenant); n != 0 {
		t.Fatal("guessed key selected victim evidence tenant")
	}
}

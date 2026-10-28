package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestIdentitySignedRouteMustMatchPersistedMode(t *testing.T) {
	for _, mismatch := range []string{"mode", "binding"} {
		t.Run(mismatch, func(t *testing.T) {
			f, b, first := liveIdentity(t)
			ctx := context.Background()
			var event muistamov1.HREvent
			event.Id, event.Type, event.OccurredAt = "mismatched-route", "joiner", time.Now()
			event.Person.Id, event.Person.Email, event.Person.JobCode = "HR-PERSON", "person-a@example.invalid", "INTERN"
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			mode, signedBinding := "entra", b.BindingVersion
			if mismatch == "mode" {
				mode = "simulated"
			} else {
				signedBinding = uuid.NewString()
			}
			err = f.conn.InTenant(ctx, f.actor.Tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, "INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version) VALUES($1,$2,'joiner',$3,'',$4,now(),2,'accepted','pending','entra',$5)", f.actor.Tenant, event.Id, event.Person.Id, raw, uuid.MustParse(b.BindingVersion))
				if err != nil {
					return err
				}
				_, err = evidence.Append(ctx, tx, f.key, evidence.Entry{Tenant: f.actor.Tenant, Actor: "hris:test", RequestID: event.Id, Action: "hr.event.received", SubjectKind: "HRPerson", SubjectName: event.Person.Id, After: map[string]any{"eventId": event.Id, "type": "joiner", "generation": int64(2), "decision": "accepted", "identityMode": mode, "identityBindingVersion": signedBinding}})
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			doc := instance("requested")
			doc.Metadata.Name = first.Document.Metadata.Name + "-route-mismatch"
			if _, _, err := f.svc.CreateEntraInstance(ctx, f.actor, doc, event.Id, 2, uuid.MustParse(b.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
				t.Fatalf("mismatched signed route authorized live creation: %v", err)
			}
		})
	}
}

func TestIdentityNoEffectRetirementCannotBorrowNewerProof(t *testing.T) {
	f, _, record := liveIdentity(t)
	ctx := context.Background()
	name := record.Document.Metadata.Name
	identityHR(t, f, "leave", "leaver", 2)
	old, err := f.svc.IdentityRoute(ctx, f.actor, "leave")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SuspendEntraPerson(ctx, f.actor, old.ReceiptId); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.svc.ConfirmEntraNoIdentity(ctx, f.actor, old.ReceiptId, name); err != nil || !ok {
		t.Fatalf("old no-effect proof: %v %v", ok, err)
	}
	identityHR(t, f, "rehire", "joiner", 3)
	identityHR(t, f, "leave-again", "leaver", 4)
	current, err := f.svc.IdentityRoute(ctx, f.actor, "leave-again")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SuspendEntraPerson(ctx, f.actor, current.ReceiptId); err != nil {
		t.Fatal(err)
	}
	if ok, err := f.svc.ConfirmEntraNoIdentity(ctx, f.actor, current.ReceiptId, name); err != nil || !ok {
		t.Fatalf("current no-effect proof: %v %v", ok, err)
	}
	if err := f.svc.SetEntraState(ctx, f.actor, old.ReceiptId, name, "retired"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("older receipt borrowed newer no-effect proof: %v", err)
	}
	if err := f.svc.SetEntraState(ctx, f.actor, current.ReceiptId, name, "retired"); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityTerminalSetupWaitsForOriginalWriter(t *testing.T) {
	f, _, record := liveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	testdb.Exec(t, f.db.OwnerURL, "UPDATE hr_events SET dispatch_attempted_at=now() WHERE event_id='join'")
	route, err := f.svc.IdentityRoute(ctx, f.actor, "join")
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		_, _, err := f.svc.RunIdentityMutation(ctx, f.actor, record.Document.Metadata.Name, "join", 1, "create", func(ctx context.Context, _ muistamov1.IdentityOperationStatus, _ muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
			close(entered)
			select {
			case <-release:
				return uuid.New(), "disabled", nil
			case <-ctx.Done():
				return uuid.Nil, "", ctx.Err()
			}
		})
		writer <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	settled := make(chan error, 1)
	go func() { settled <- f.svc.SettleEntraSetup(ctx, f.actor, route.ReceiptId) }()
	monitor, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer func() { _ = monitor.Close(context.Background()) }()
	waited := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-settled:
			close(release)
			t.Fatalf("terminal setup escaped original writer fence: %v", err)
		default:
		}
		if err := monitor.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%')").Scan(&waited); err != nil {
			close(release)
			t.Fatal(err)
		}
		if waited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if !waited {
		t.Fatal("terminal setup did not wait for the original writer")
	}
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	if err := <-settled; err != nil {
		t.Fatal(err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, "SELECT count(*) FROM hr_events WHERE event_id='join' AND setup_completed_at IS NOT NULL"); n != 1 {
		t.Fatal("terminal setup was not committed")
	}
}

func TestIdentityEnrollmentDatabaseBoundaries(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	b := identityBinding(f.actor.Tenant)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnrollIdentityTenant(ctx, f.actor, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	insert := fmt.Sprintf("INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version) VALUES('%s','invalid-shape','joiner','HR','','{}',now(),1,'accepted','pending','entra',NULL)", f.actor.Tenant)
	if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, insert); err == nil {
		t.Fatal("database accepted an Entra receipt without a binding")
	}
	other, err := store.CreateTenant(ctx, f.db.OwnerURL, "foreign-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.actor
	foreign.Tenant = other
	b2 := identityBinding(other)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, foreign, b2); err != nil {
		t.Fatal(err)
	}
	insert = fmt.Sprintf("INSERT INTO identity_enrollments(tenant_id,binding_version) VALUES('%s','%s')", other, b2.BindingVersion)
	if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, insert); err == nil {
		t.Fatal("application role enrolled another tenant")
	}
}

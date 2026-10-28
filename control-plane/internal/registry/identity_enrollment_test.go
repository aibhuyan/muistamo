package registry_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestIdentityEnrollmentIsFreshImmutableAndSigned(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	b := identityBinding(f.actor.Tenant)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil {
		t.Fatal(err)
	}
	version := uuid.MustParse(b.BindingVersion)
	broken := registry.New(f.conn, identityBrokenSigner{f.key})
	if _, err := broken.EnrollIdentityTenant(ctx, f.actor, version); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned enrollment committed: %v", err)
	}
	if _, err := f.svc.IdentityEnrollment(ctx, f.actor); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("failed enrollment escaped rollback: %v", err)
	}
	first, err := f.svc.EnrollIdentityTenant(ctx, f.actor, version)
	if err != nil || first.BindingVersion != version || first.TenantId != f.actor.Tenant {
		t.Fatalf("enrollment: %+v %v", first, err)
	}
	again, err := f.svc.EnrollIdentityTenant(ctx, f.actor, version)
	if err != nil || !again.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("enrollment was not idempotent: %+v %v", again, err)
	}
	b.BindingVersion = uuid.NewString()
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnrollIdentityTenant(ctx, f.actor, uuid.MustParse(b.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("live tenant binding retargeted: %v", err)
	}
	// Use another valid binding before any receipt FK can mask a missing UPDATE restriction.
	if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, fmt.Sprintf("UPDATE identity_enrollments SET binding_version='%s'", b.BindingVersion)); err == nil {
		t.Fatal("application role retargeted enrollment")
	}
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("enrolled")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, instance("requested"), ""); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("public creation bypassed live identity routing: %v", err)
	}
	identityHR(t, f, "join", "joiner", 1)
	route, err := f.svc.IdentityRoute(ctx, f.actor, "join")
	if err != nil || route.ProviderMode != "entra" || route.BindingVersion == nil || *route.BindingVersion != version || route.ReceiptId == uuid.Nil {
		t.Fatalf("accepted HR route not pinned: %+v %v", route, err)
	}
	if _, _, err := f.svc.CreateEntraInstance(ctx, f.actor, instance("requested"), "join", 1, uuid.MustParse(b.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("factory ignored enrolled receipt binding: %v", err)
	}
	if _, _, err := f.svc.CreateEntraInstance(ctx, f.actor, instance("requested"), "join", 1, version); err != nil {
		t.Fatal(err)
	}
	foreign := f.actor
	foreign.Tenant, err = store.CreateTenant(ctx, f.db.OwnerURL, "foreign")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IdentityEnrollment(ctx, foreign); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("foreign enrollment exposed: %v", err)
	}
	if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `UPDATE hr_events SET identity_mode='simulated',identity_binding_version=NULL WHERE event_id='join'`); err == nil {
		t.Fatal("application role downgraded a pinned receipt")
	}
}

func TestIdentityEnrollmentRefusesExistingSimulationAndHR(t *testing.T) {
	for _, prior := range []string{"instance", "hr"} {
		t.Run(prior, func(t *testing.T) {
			f := setup(t)
			ctx := context.Background()
			b := identityBinding(f.actor.Tenant)
			if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil {
				t.Fatal(err)
			}
			if prior == "hr" {
				identityHR(t, f, "join", "joiner", 1)
			} else {
				if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("legacy")); err != nil {
					t.Fatal(err)
				}
				if _, _, err := f.svc.ApplyInstance(ctx, f.actor, instance("requested"), ""); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.svc.EnrollIdentityTenant(ctx, f.actor, uuid.MustParse(b.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
				t.Fatalf("existing %s tenant silently migrated: %v", prior, err)
			}
		})
	}
}

func TestIdentityLeaverSuspendsEveryTrustedInstanceAtomically(t *testing.T) {
	f, b, first := liveIdentity(t)
	ctx := context.Background()
	doc := instance("requested")
	doc.Metadata.Name += "-second"
	if _, _, err := f.svc.CreateEntraInstance(ctx, f.actor, doc, "join", 1, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	// A mutable display label is not the trusted association.
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{metadata,labels}', '{"muistamo.dev/hr-person-id":"unrelated"}'::jsonb)`)
	identityHR(t, f, "leave", "leaver", 2)
	route, err := f.svc.IdentityRoute(ctx, f.actor, "leave")
	if err != nil {
		t.Fatal(err)
	}
	broken := registry.New(f.conn, &identityNthSigner{LocalKey: f.key, failAt: 2})
	if _, err := broken.SuspendEntraPerson(ctx, f.actor, route.ReceiptId); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned partial suspension returned success: %v", err)
	}
	for _, name := range []string{first.Document.Metadata.Name, doc.Metadata.Name} {
		rec, err := f.svc.GetInstance(ctx, f.actor, name)
		if err != nil || rec.Document.Spec.State != "requested" {
			t.Fatalf("suspension was only partially rolled back: %+v %v", rec, err)
		}
	}
	names, err := f.svc.SuspendEntraPerson(ctx, f.actor, route.ReceiptId)
	if err != nil || len(names) != 2 {
		t.Fatalf("trusted suspension omitted an instance: %v %v", names, err)
	}
	for _, name := range names {
		rec, err := f.svc.GetInstance(ctx, f.actor, name)
		if err != nil || rec.Document.Spec.State != "suspended" {
			t.Fatalf("local suspension incomplete: %+v %v", rec, err)
		}
	}
	identityHR(t, f, "rehire", "joiner", 3)
	if _, err := f.svc.SuspendEntraPerson(ctx, f.actor, route.ReceiptId); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("old leaver suspended after newer joiner: %v", err)
	}
}

func TestIdentityNoEffectRetirementRequiresNoCreateIntentAndSignedProof(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		t.Run(map[bool]string{false: "never-reserved", true: "uncertain-create"}[reserved], func(t *testing.T) {
			f, _, record := liveIdentity(t)
			ctx := context.Background()
			name := record.Document.Metadata.Name
			if reserved {
				if _, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create"); err != nil {
					t.Fatal(err)
				}
			}
			identityHR(t, f, "leave", "leaver", 2)
			route, err := f.svc.IdentityRoute(ctx, f.actor, "leave")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.SuspendEntraPerson(ctx, f.actor, route.ReceiptId); err != nil {
				t.Fatal(err)
			}
			if err := f.svc.SetEntraState(ctx, f.actor, route.ReceiptId, name, "retired"); !errors.Is(err, registry.ErrConflict) {
				t.Fatalf("unsigned absent-identity proof allowed retirement: %v", err)
			}
			if !reserved {
				broken := registry.New(f.conn, identityBrokenSigner{f.key})
				if _, err := broken.ConfirmEntraNoIdentity(ctx, f.actor, route.ReceiptId, name); !errors.Is(err, evidence.ErrNotRecorded) {
					t.Fatalf("unsigned no-effect proof returned success: %v", err)
				}
			}
			confirmed, err := f.svc.ConfirmEntraNoIdentity(ctx, f.actor, route.ReceiptId, name)
			if err != nil || confirmed == reserved {
				t.Fatalf("no-effect classification: confirmed=%v reserved=%v err=%v", confirmed, reserved, err)
			}
			err = f.svc.SetEntraState(ctx, f.actor, route.ReceiptId, name, "retired")
			if reserved {
				if !errors.Is(err, registry.ErrConflict) {
					t.Fatalf("uncertain create was retired: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentityEnrollmentSerializesHRAndEveryCreationPath(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b := identityBinding(f.actor.Tenant)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("concurrent enrollment")); err != nil {
		t.Fatal(err)
	}
	gate := &identityGateSigner{LocalKey: f.key, entered: make(chan struct{}), release: make(chan struct{})}
	enrolled := make(chan error, 1)
	go func() {
		_, err := registry.New(f.conn, gate).EnrollIdentityTenant(ctx, f.actor, uuid.MustParse(b.BindingVersion))
		enrolled <- err
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	created := make(chan error, 1)
	accepted := make(chan error, 1)
	go func() { _, _, err := f.svc.ApplyInstance(ctx, f.actor, instance("requested"), ""); created <- err }()
	var event muistamov1.HREvent
	event.Id, event.Type, event.OccurredAt = "join-concurrent", "joiner", time.Now()
	event.Person.Id, event.Person.Email, event.Person.JobCode = "HR-CONCURRENT", "concurrent@example.invalid", "INTERN"
	in := lifecycle.Intake{DB: f.conn, Signer: f.key}
	go func() { _, err := in.Accept(ctx, f.actor.Tenant, "hris:test", event.Id, event); accepted <- err }()
	monitor, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		close(gate.release)
		t.Fatal(err)
	}
	defer func() { _ = monitor.Close(context.Background()) }()
	waiters := 0
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-created:
			close(gate.release)
			t.Fatalf("instance creation escaped enrollment fence: %v", err)
		case err := <-accepted:
			close(gate.release)
			t.Fatalf("HR acceptance escaped enrollment fence: %v", err)
		default:
		}
		if err := monitor.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock_shared%'`).Scan(&waiters); err != nil {
			close(gate.release)
			t.Fatal(err)
		}
		if waiters >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(gate.release)
	enrollErr, createErr, acceptErr := <-enrolled, <-created, <-accepted
	if enrollErr != nil {
		t.Fatal(enrollErr)
	}
	if !errors.Is(createErr, registry.ErrConflict) {
		t.Fatalf("enrollment allowed a simulated instance to commit: %v", createErr)
	}
	if !errors.Is(acceptErr, lifecycle.ErrDispatch) {
		t.Fatalf("post-enrollment HR acceptance failed: %v", acceptErr)
	}
	route, err := f.svc.IdentityRoute(ctx, f.actor, event.Id)
	if err != nil || route.ProviderMode != "entra" {
		t.Fatalf("concurrent HR route was downgraded: %+v %v", route, err)
	}
	if waiters < 2 {
		t.Fatal("HR and creation did not both reach the enrollment fence")
	}
}

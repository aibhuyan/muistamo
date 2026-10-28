package registry_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func gatewayFixture(t *testing.T) (fixture, muistamov1.VirtualKeyRequest) {
	t.Helper()
	f := setup(t)
	if _, _, err := f.svc.ApplyTemplate(t.Context(), f.actor, template("gateway")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyInstance(t.Context(), f.actor, instance("requested"), ""); err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,state}','"active"')`)
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, []string{f.actor.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	return f, muistamov1.VirtualKeyRequest{
		Instance: "analyst-intern-person-a", Aliases: []string{"reasoning-default"},
		MonthlyBudget: muistamov1.Money{Amount: "25.50", Currency: "EUR"},
	}
}

func TestGatewayKeyIssuanceRequiresAnActiveInstance(t *testing.T) {
	f, req := gatewayFixture(t)
	for _, state := range []string{"requested", "under-review", "suspended", "quarantined", "retired"} {
		testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,state}',to_jsonb($1::text))`, state)
		issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
		if !errors.Is(err, registry.ErrConflict) || issued.Secret != "" {
			t.Errorf("%s instance issued a usable key: secret present %v, err %v", state, issued.Secret != "", err)
		}
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM virtual_keys`); n != 0 {
		t.Errorf("inactive instances minted %d keys", n)
	}
}

func TestGatewayKeyIssuanceRefusesAnAcceptedLiveLeaverBeforeSuspension(t *testing.T) {
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
	req := muistamov1.VirtualKeyRequest{Instance: name, Aliases: []string{"reasoning-default"}, MonthlyBudget: muistamov1.Money{Amount: "10", Currency: "EUR"}}
	if _, err := f.svc.IssueKey(t.Context(), f.actor, req); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	// Deliberately leave the instance's local state active: intake has fenced the newer HR
	// generation, but the leaver's suspension activity has not run yet.
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if !errors.Is(err, registry.ErrConflict) || issued.Secret != "" {
		t.Fatalf("accepted live leaver minted a key before suspension: secret present %v, err %v", issued.Secret != "", err)
	}
}

func TestGatewayRevocationReasonsAreFixedCodes(t *testing.T) {
	f, req := gatewayFixture(t)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"", "Jane Doe", "HR-12345", "+35840123456", "mvk_fake_secret", "operator extra"} {
		if _, err := f.svc.RevokeKey(t.Context(), f.actor, issued.Key.Id, reason); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("unsafe revocation reason %q was accepted: %v", reason, err)
		}
	}
	if key, err := f.svc.GetKey(t.Context(), f.actor, issued.Key.Id); err != nil || key.Status != "active" {
		t.Fatalf("invalid reason changed key: %+v, %v", key, err)
	}
}

func TestGatewayKeyEvidenceFailureRollsBackAndReturnsNoSecret(t *testing.T) {
	f, req := gatewayFixture(t)
	broken := registry.New(f.conn, failingSigner{f.key})
	before := f.events(t)
	issued, err := broken.IssueKey(t.Context(), f.actor, req)
	if !errors.Is(err, registry.ErrEvidence) || issued.Secret != "" {
		t.Fatalf("issue without evidence = secret present %v, err %v", issued.Secret != "", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM virtual_keys`); n != 0 || f.events(t) != before {
		t.Fatalf("failed issue left keys=%d or changed evidence", n)
	}
	issued, err = f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	before = f.events(t)
	if _, err := broken.RevokeKey(t.Context(), f.actor, issued.Key.Id, "operator"); !errors.Is(err, registry.ErrEvidence) {
		t.Fatalf("revoke without evidence = %v", err)
	}
	key, err := f.svc.GetKey(t.Context(), f.actor, issued.Key.Id)
	if err != nil || key.Status != "active" || f.events(t) != before {
		t.Fatalf("failed revocation changed state: %+v, %v", key, err)
	}
}

func TestGatewayKeyWritesHoldTheErasureFence(t *testing.T) {
	for _, action := range []string{"issue", "revoke", "configure"} {
		t.Run(action, func(t *testing.T) {
			f, req := gatewayFixture(t)
			f.actor.Name = "dev:issuer@example.invalid"
			if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, []string{f.actor.Name}, f.key); err != nil {
				t.Fatal(err)
			}
			issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
			if err != nil {
				t.Fatal(err)
			}
			gate := &identityGateSigner{LocalKey: f.key, entered: make(chan struct{}), release: make(chan struct{})}
			svc := registry.New(f.conn, gate)
			ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
			defer cancel()
			written := make(chan error, 1)
			go func() {
				switch action {
				case "issue":
					_, err := svc.IssueKey(ctx, f.actor, req)
					written <- err
				case "revoke":
					_, err := svc.RevokeKey(ctx, f.actor, issued.Key.Id, "operator")
					written <- err
				default:
					written <- registry.ConfigureGatewayAdmins(ctx, f.db.OwnerURL, f.actor, []string{f.actor.Name}, gate)
				}
			}()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			officer := registry.Actor{Tenant: f.actor.Tenant, Name: "dev:officer@example.invalid", RequestID: uuid.NewString()}
			if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.actor.Tenant, []string{officer.Name}); err != nil {
				close(gate.release)
				t.Fatal(err)
			}
			erased := make(chan error, 1)
			go func() {
				_, _, err := f.svc.Erase(ctx, officer, muistamov1.ErasureRequest{
					Id: uuid.New(), Subject: muistamov1.PrivacySubject{Email: "issuer@example.invalid", Identities: []string{f.actor.Name}},
					Reason: "test erasure",
				})
				erased <- err
			}()
			monitor, err := pgx.Connect(ctx, f.db.OwnerURL)
			if err != nil {
				close(gate.release)
				t.Fatal(err)
			}
			defer func() { _ = monitor.Close(context.Background()) }()
			fenced := false
			for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
				if err := monitor.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
					AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock(%')`).Scan(&fenced); err != nil {
					close(gate.release)
					t.Fatal(err)
				}
				if fenced {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			close(gate.release)
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if err := <-erased; err != nil {
				t.Fatal(err)
			}
			if !fenced {
				t.Error("key write did not hold the erasure fence")
			}
			if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM virtual_keys WHERE created_by=$1 OR revoked_by=$1`, f.actor.Name); n != 0 {
				t.Errorf("concurrent key write restored erased attribution: %d", n)
			}
			if _, err := f.svc.IssueKey(ctx, f.actor, req); err == nil || !strings.Contains(err.Error(), "forbidden") {
				t.Errorf("erased administrator issued a key: %v", err)
			}
			if err := registry.ConfigureGatewayAdmins(ctx, f.db.OwnerURL, officer, []string{f.actor.Name}, f.key); !errors.Is(err, registry.ErrConflict) {
				t.Errorf("erased administrator was reappointed: %v", err)
			}
		})
	}
}

func TestGatewayKeyIssuanceSerializesWithSuspension(t *testing.T) {
	f, req := gatewayFixture(t)
	gate := &identityGateSigner{LocalKey: f.key, entered: make(chan struct{}), release: make(chan struct{})}
	svc := registry.New(f.conn, gate)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	issued := make(chan error, 1)
	go func() { _, err := svc.IssueKey(ctx, f.actor, req); issued <- err }()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	suspended := make(chan error, 1)
	go func() { _, err := f.svc.TransitionTo(ctx, f.actor, req.Instance, "suspended"); suspended <- err }()
	monitor, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		close(gate.release)
		t.Fatal(err)
	}
	defer func() { _ = monitor.Close(context.Background()) }()
	waited := false
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if err := monitor.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND wait_event_type='Lock' AND query LIKE '%agent_instances%FOR UPDATE%')`).Scan(&waited); err != nil {
			close(gate.release)
			t.Fatal(err)
		}
		if waited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(gate.release)
	if err := <-issued; err != nil {
		t.Fatal(err)
	}
	if err := <-suspended; err != nil {
		t.Fatal(err)
	}
	if !waited {
		t.Error("suspension did not wait for the key issuer's instance lock")
	}
	if _, err := f.svc.IssueKey(ctx, f.actor, req); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("key issued after suspension committed: %v", err)
	}
}

func TestGatewayAdministratorChangesRequireOwnerAndEvidence(t *testing.T) {
	f := setup(t)
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, []string{f.actor.Name}, failingSigner{f.key}); !errors.Is(err, registry.ErrEvidence) {
		t.Fatalf("configuration without evidence = %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM gateway_admins`); n != 0 {
		t.Fatalf("unsigned administrator grant committed: %d", n)
	}
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.AppURL, f.actor, []string{f.actor.Name}, f.key); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("application role configured administrators: %v", err)
	}
	other, err := store.CreateTenant(t.Context(), f.db.OwnerURL, "other-tenant")
	if err != nil {
		t.Fatal(err)
	}
	otherActor := registry.Actor{Tenant: other, Name: "operator:other", RequestID: uuid.NewString()}
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, otherActor, []string{"dev:other-private-admin@example.invalid"}, f.key); err != nil {
		t.Fatal(err)
	}
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, []string{f.actor.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	if raw := testdb.Scalar(t, f.db.OwnerURL, `SELECT coalesce(string_agg(to_jsonb(e)::text,''),'') FROM evidence_events e WHERE tenant_id=$1`, f.actor.Tenant); strings.Contains(raw, "other-private-admin") {
		t.Error("operator configuration leaked another tenant's administrators into evidence")
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id=$1 AND action='gateway.admins.configured'`, f.actor.Tenant); n != 1 {
		t.Fatalf("configuration evidence = %d", n)
	}
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, nil, f.key); err != nil {
		t.Fatal(err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM gateway_admins WHERE tenant_id=$1`, f.actor.Tenant); n != 0 {
		t.Fatalf("clearing administrators left %d rows", n)
	}
}

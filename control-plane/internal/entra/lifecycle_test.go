package entra

import (
	"context"
	"errors"
	"strings"
	"testing"

	"go.temporal.io/sdk/temporal"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func adapterLifecycleRef(t *testing.T, f adapterFixture, id string) muistamov1.EntraLifecycleRef {
	t.Helper()
	route, err := f.svc.IdentityRoute(context.Background(), f.actor, id)
	if err != nil {
		t.Fatal(err)
	}
	return muistamov1.EntraLifecycleRef{TenantId: f.actor.Tenant, ReceiptId: route.ReceiptId}
}

func TestAdapterLiveRehireReusesOriginalIdentity(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	acts := &lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: lifecycle.KeyRevoker{Registry: f.svc}}
	join := adapterLifecycleRef(t, f, "join")
	if err := acts.EntraCreate(ctx, join, f.name); err != nil {
		t.Fatal(err)
	}
	if err := acts.EntraEnable(ctx, join, f.name); err != nil {
		t.Fatal(err)
	}
	if err := acts.EntraActivate(ctx, join, f.name); err != nil {
		t.Fatal(err)
	}
	if err := registry.ConfigureGatewayAdmins(ctx, f.db.OwnerURL, f.actor, []string{f.actor.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	issued, err := f.svc.IssueKey(ctx, f.actor, muistamov1.VirtualKeyRequest{Instance: f.name, Aliases: []string{"reasoning-default"},
		MonthlyBudget: muistamov1.Money{Amount: "5", Currency: "EUR"}})
	if err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	leave := adapterLifecycleRef(t, f, "leave")
	if _, err := acts.EntraPrepareLeaver(ctx, leave); err != nil {
		t.Fatal(err)
	}
	// The live leaver really revokes the instance's gateway keys, and says so.
	if err := acts.EntraRevoke(ctx, leave, f.name); err != nil {
		t.Fatal(err)
	}
	revoked := testdb.Scalar(t, f.db.OwnerURL, `SELECT status || ' ' || revoke_reason FROM virtual_keys WHERE id=$1`, issued.Key.Id)
	evidence := testdb.Scalar(t, f.db.OwnerURL, `SELECT after::text FROM evidence_events WHERE action='credentials.revoked' ORDER BY seq DESC LIMIT 1`)
	if revoked != "revoked leaver" || !strings.Contains(evidence, `"simulated": false`) || !strings.Contains(evidence, issued.Key.Id.String()) {
		t.Fatalf("live leaver revocation = %q, evidence %s", revoked, evidence)
	}
	if err := acts.EntraDisable(ctx, leave, f.name); err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "rehire", "joiner", 3)
	rehire := adapterLifecycleRef(t, f, "rehire")
	if err := acts.EntraCreate(ctx, rehire, f.name); err != nil {
		t.Fatalf("rehire attempted another create: %v", err)
	}
	if err := acts.EntraEnable(ctx, rehire, f.name); err != nil {
		t.Fatal(err)
	}
	if err := acts.EntraActivate(ctx, rehire, f.name); err != nil {
		t.Fatal(err)
	}
	posts := 0
	for _, call := range f.graph.calls {
		if strings.HasPrefix(call, "POST /v1.0/") {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("rehire issued %d creates", posts)
	}
	// A rehire never resurrects the leaver's keys.
	if got := testdb.Scalar(t, f.db.OwnerURL, `SELECT status FROM virtual_keys WHERE id=$1`, issued.Key.Id); got != "revoked" {
		t.Fatalf("rehire resurrected a key: %s", got)
	}
}

func TestAdapterRetirementResumesAfterRecordedDeletion(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	acts := &lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: &lifecycle.Simulated{}}
	join := adapterLifecycleRef(t, f, "join")
	if err := acts.EntraCreate(ctx, join, f.name); err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	leave := adapterLifecycleRef(t, f, "leave")
	if _, err := acts.EntraPrepareLeaver(ctx, leave); err != nil {
		t.Fatal(err)
	}
	if err := acts.EntraDisable(ctx, leave, f.name); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.Apply(ctx, f.actor, f.name, "leave", 2, "delete"); err != nil {
		t.Fatal(err)
	}
	before := len(f.graph.calls)
	for range 2 {
		if err := acts.EntraRetire(ctx, leave, f.name); err != nil {
			t.Fatalf("recorded deletion could not resume local retirement: %v", err)
		}
	}
	if len(f.graph.calls) != before {
		t.Fatal("local retirement repeated a provider mutation")
	}
	record, err := f.svc.GetInstance(ctx, f.actor, f.name)
	if err != nil || record.Document.Spec.State != "retired" {
		t.Fatalf("retirement incomplete: %+v %v", record, err)
	}
}

// A live rehire after a leaver whose key revocation never succeeded revokes the old key on
// reactivation: keys from before a suspension never survive reinstatement.
func TestAdapterLiveRehireRevokesKeysTheLeaverMissed(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	acts := &lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: lifecycle.KeyRevoker{Registry: f.svc}}
	join := adapterLifecycleRef(t, f, "join")
	for _, step := range []func(context.Context, muistamov1.EntraLifecycleRef, string) error{acts.EntraCreate, acts.EntraEnable, acts.EntraActivate} {
		if err := step(ctx, join, f.name); err != nil {
			t.Fatal(err)
		}
	}
	if err := registry.ConfigureGatewayAdmins(ctx, f.db.OwnerURL, f.actor, []string{f.actor.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	issued, err := f.svc.IssueKey(ctx, f.actor, muistamov1.VirtualKeyRequest{Instance: f.name, Aliases: []string{"reasoning-default"},
		MonthlyBudget: muistamov1.Money{Amount: "5", Currency: "EUR"}})
	if err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	leave := adapterLifecycleRef(t, f, "leave")
	if _, err := acts.EntraPrepareLeaver(ctx, leave); err != nil {
		t.Fatal(err)
	}
	if err := acts.EntraDisable(ctx, leave, f.name); err != nil {
		t.Fatal(err)
	}
	// EntraRevoke never succeeded. The person is rehired.
	seedAdapterHR(t, f.conn, f.key, f.actor, "rehire", "joiner", 3)
	rehire := adapterLifecycleRef(t, f, "rehire")
	for _, step := range []func(context.Context, muistamov1.EntraLifecycleRef, string) error{acts.EntraCreate, acts.EntraEnable, acts.EntraActivate} {
		if err := step(ctx, rehire, f.name); err != nil {
			t.Fatal(err)
		}
	}
	if got := testdb.Scalar(t, f.db.OwnerURL, `SELECT status || ' ' || revoke_reason FROM virtual_keys WHERE id=$1`, issued.Key.Id); got != "revoked reactivation" {
		t.Fatalf("rehire left the leaver's key %q", got)
	}
}

// A revocation the registry refuses (here: the instance was never suspended) is permanent, so the
// live leaver fails fast rather than retrying it for an hour.
func TestAdapterLiveRevokeRefusalIsNotRetried(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	acts := &lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: lifecycle.KeyRevoker{Registry: f.svc}}
	join := adapterLifecycleRef(t, f, "join")
	for _, step := range []func(context.Context, muistamov1.EntraLifecycleRef, string) error{acts.EntraCreate, acts.EntraEnable, acts.EntraActivate} {
		if err := step(ctx, join, f.name); err != nil {
			t.Fatal(err)
		}
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	err := acts.EntraRevoke(ctx, adapterLifecycleRef(t, f, "leave"), f.name)
	var app *temporal.ApplicationError
	if !errors.As(err, &app) || !app.NonRetryable() {
		t.Fatalf("revocation of an unsuspended instance = %v, want a non-retryable refusal", err)
	}
}

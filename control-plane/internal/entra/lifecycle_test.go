package entra

import (
	"context"
	"strings"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
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
	acts := &lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: &lifecycle.Simulated{}}
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
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	leave := adapterLifecycleRef(t, f, "leave")
	if _, err := acts.EntraPrepareLeaver(ctx, leave); err != nil {
		t.Fatal(err)
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

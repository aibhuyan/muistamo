//go:build authz

package registry_test

import (
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Tenant B's gateway ingest and gateway administrator attack tenant A's calls: B cannot meter
// A's call (which would spend A's budget) and cannot read it. Never skip or weaken (AGENTS.md).
func TestAuthzUsageIsTenantScoped(t *testing.T) {
	f, _, id := meteredFixture(t)
	tenantB, err := store.CreateTenant(t.Context(), f.db.OwnerURL, "beta")
	if err != nil {
		t.Fatal(err)
	}
	b := registry.Actor{Tenant: tenantB, Name: f.actor.Name, RequestID: uuid.NewString()}
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, b, []string{b.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.RecordUsage(t.Context(), tenantB, []registry.UsageLine{line(id, 1000, 0, 1000),
		{RequestID: id, Model: "test-model", UsageMissing: true}, {RequestID: id, Model: "test-model", FailedStatus: 500}})
	if err != nil || len(got.Accepted) != 0 || len(got.WithoutUsage) != 0 || len(got.Failed) != 0 || got.Unmatched != 3 {
		t.Fatalf("B metered A's call or spent A's allowance: %+v, %v", got, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM calls_without_usage`); n != 0 {
		t.Fatalf("B's ingest recorded %d calls without usage", n)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM usage_records`); n != 0 {
		t.Fatalf("B's ingest recorded %d usage rows", n)
	}
	page, err := f.svc.ListUsage(t.Context(), b, registry.UsageFilter{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("B's administrator, with the same identity, sees A's usage: %+v, %v", page.Items, err)
	}
}

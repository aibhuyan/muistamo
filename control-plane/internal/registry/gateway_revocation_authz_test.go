//go:build authz

package registry_test

import (
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// A leaver in tenant B, for an instance with the very same name, never revokes tenant A's keys.
// Never skip or weaken (AGENTS.md).
func TestAuthzLeaverRevocationIsTenantScoped(t *testing.T) {
	f, req := gatewayFixture(t)
	keyA, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.CreateTenant(t.Context(), f.db.OwnerURL, "beta")
	if err != nil {
		t.Fatal(err)
	}
	testdb.ApprovedModelAlias(t, f.db.OwnerURL, tenantB, "reasoning-default")
	b := registry.Actor{Tenant: tenantB, Name: f.actor.Name, RequestID: uuid.NewString()}
	if _, _, err := f.svc.ApplyTemplate(t.Context(), b, template("gateway")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyInstance(t.Context(), b, instance("requested"), ""); err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,state}','"active"') WHERE tenant_id=$1`, tenantB)
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, b, []string{b.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	keyB, err := f.svc.IssueKey(t.Context(), b, req)
	if err != nil {
		t.Fatal(err)
	}

	workflowB := registry.Actor{Tenant: tenantB, Name: "workflow:leaver-b", RequestID: "hr-event:b"}
	if _, err := f.svc.TransitionTo(t.Context(), b, req.Instance, "suspended"); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.RevokeInstanceKeys(t.Context(), workflowB, req.Instance)
	if err != nil || len(got) != 1 || got[0] != keyB.Key.Id {
		t.Fatalf("B's leaver revoked %v, err %v; want only B's key %s", got, err, keyB.Key.Id)
	}
	if key, err := f.svc.GetKey(t.Context(), f.actor, keyA.Key.Id); err != nil || key.Status != "active" {
		t.Fatalf("A's key after B's leaver = %+v, %v; want active", key, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id=$1 AND action='gateway.key.revoked'`, f.actor.Tenant); n != 0 {
		t.Fatalf("B's leaver wrote %d revocation events into A's chain", n)
	}
}

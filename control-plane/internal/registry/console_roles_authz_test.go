//go:build authz

package registry_test

import (
	"errors"
	"testing"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// A console administrator of tenant B, and a person with no role in A, both try to read tenant
// A's agents and templates through the console. Never skip or weaken (AGENTS.md).
func TestAuthzConsoleRolesAreTenantScoped(t *testing.T) {
	f := setup(t)
	seedAgent(t, f)
	const person = "entra:aaaaaaaa-0000-4000-8000-000000000001"
	tenantB, err := store.CreateTenant(t.Context(), f.db.OwnerURL, "beta")
	if err != nil {
		t.Fatal(err)
	}
	setRole(t, f, tenantB, "administrator", person)

	// The same identity signed in to A holds no role there.
	inA := throughConsole(f.actor, person)
	for name, err := range reads(f, inA) {
		if !errors.Is(err, registry.ErrForbidden) {
			t.Errorf("B's administrator in A, %s = %v, want forbidden", name, err)
		}
	}
	if got, err := f.svc.ConsoleAccess(t.Context(), inA); err != nil || got.Administrator || got.Auditor {
		t.Errorf("B's administrator in A has access %+v, %v", got, err)
	}
	// In B the role holds, and B has none of A's agents or templates.
	inB := inA
	inB.Tenant = tenantB
	instances, err := f.svc.ListInstances(t.Context(), inB, "", 50)
	if err != nil || len(instances.Items) != 0 {
		t.Errorf("B's administrator lists %d of A's instances, %v", len(instances.Items), err)
	}
	templates, err := f.svc.ListTemplates(t.Context(), inB, "", 50)
	if err != nil || len(templates.Items) != 0 {
		t.Errorf("B's administrator lists %d of A's templates, %v", len(templates.Items), err)
	}
	if _, err := f.svc.GetInstance(t.Context(), inB, "analyst-intern-person-a"); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("B's administrator reads A's instance: %v", err)
	}
	if _, err := f.svc.GetTemplate(t.Context(), inB, "analyst-intern"); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("B's administrator reads A's template: %v", err)
	}
}

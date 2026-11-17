//go:build authz

package api_test

// HUMAN REVIEW REQUIRED: who reads agents and templates through the console
// (docs/console-management-plan.md, D70). Run by `make test-authz`; never skip or weaken.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// consoleAs is a console sign-in decided by the test: whoever the bearer token names, in the
// tenant the test chose. The real resolver (entra.ConsoleResolver) has its own tests.
type consoleAs struct{ tenant *uuid.UUID }

func (c consoleAs) ResolveConsole(r *http.Request) (uuid.UUID, string, uuid.UUID, error) {
	return *c.tenant, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), uuid.MustParse("c0c0c0c0-0000-4000-8000-0000000c0501"), nil
}

func TestAuthzConsoleReadsOfAgentsAndTemplatesNeedTheAdministratorRole(t *testing.T) {
	var signedInto uuid.UUID
	h := newHarness(t, api.WithConsole{Console: consoleAs{&signedInto}, Fallback: api.InsecureDevHeaders{}})
	a, b := h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	// In order: an instance needs its template.
	for _, seed := range [][2]string{{"/v1/templates/analyst-intern", templateJSON}, {"/v1/instances/analyst-intern-person-a", instanceJSON}} {
		if got := h.call(t, a, http.MethodPut, seed[0], seed[1]); got.status != http.StatusCreated {
			t.Fatalf("seed %s = %d: %s", seed[0], got.status, got.raw)
		}
	}
	const admin, auditor, nobody, adminOfB = "entra:aaaaaaaa-0000-4000-8000-00000000000a", "entra:aaaaaaaa-0000-4000-8000-00000000000b",
		"entra:aaaaaaaa-0000-4000-8000-00000000000c", "entra:bbbbbbbb-0000-4000-8000-00000000000a"
	role := func(tenant uuid.UUID, role string, people ...string) {
		t.Helper()
		op := registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: uuid.NewString()}
		if err := registry.ConfigureConsoleRole(t.Context(), h.db.OwnerURL, op, role, people, h.key); err != nil {
			t.Fatal(err)
		}
	}
	role(a, registry.ConsoleAdministrator, admin)
	role(a, registry.ConsoleAuditor, auditor)
	role(b, registry.ConsoleAdministrator, adminOfB)

	console := func(person, method, path string) response {
		t.Helper()
		return h.call(t, uuid.Nil, method, path, "", "Authorization", "Bearer "+person)
	}
	reads := []string{"/v1/instances", "/v1/instances/analyst-intern-person-a", "/v1/templates", "/v1/templates/analyst-intern"}

	signedInto = a
	for _, path := range reads {
		if got := console(admin, http.MethodGet, path); got.status != http.StatusOK || !strings.Contains(got.raw, "analyst-intern") {
			t.Errorf("administrator GET %s = %d: %s", path, got.status, got.raw)
		}
		// Not an administrator of A: an auditor, someone with no role, and B's administrator.
		for _, person := range []string{auditor, nobody, adminOfB} {
			got := console(person, http.MethodGet, path)
			if got.status != http.StatusForbidden || strings.Contains(got.raw, "person-a") || strings.Contains(got.raw, "Support interns") {
				t.Errorf("%s GET %s = %d: %s", person, path, got.status, got.raw)
			}
		}
	}
	// A name that does not exist is refused the same way: no hint of what exists.
	for _, path := range []string{"/v1/instances/no-such-agent", "/v1/templates/no-such-template"} {
		if got := console(nobody, http.MethodGet, path); got.status != http.StatusForbidden {
			t.Errorf("non-administrator GET %s = %d, want 403", path, got.status)
		}
		if got := console(admin, http.MethodGet, path); got.status != http.StatusNotFound {
			t.Errorf("administrator GET %s = %d, want 404", path, got.status)
		}
	}

	// B's administrator signed in to B reads B, which has none of A's records.
	signedInto = b
	for _, path := range []string{"/v1/instances", "/v1/templates"} {
		if got := console(adminOfB, http.MethodGet, path); got.status != http.StatusOK || strings.Contains(got.raw, "analyst-intern") {
			t.Errorf("B's administrator GET %s = %d: %s", path, got.status, got.raw)
		}
	}
	for _, path := range []string{"/v1/instances/analyst-intern-person-a", "/v1/templates/analyst-intern"} {
		if got := console(adminOfB, http.MethodGet, path); got.status != http.StatusNotFound {
			t.Errorf("B's administrator GET %s = %d, want 404", path, got.status)
		}
	}
	// A's administrator signed in to B holds no role there.
	if got := console(admin, http.MethodGet, "/v1/instances"); got.status != http.StatusForbidden {
		t.Errorf("A's administrator in B = %d, want 403", got.status)
	}

	// Even an administrator reaches nothing else through the console: no write, nothing beneath a
	// name, and no other list.
	signedInto = a
	for _, r := range [][2]string{
		{http.MethodPut, "/v1/instances/analyst-intern-person-a"},
		{http.MethodPut, "/v1/templates/analyst-intern"},
		{http.MethodPost, "/v1/instances/analyst-intern-person-a/transitions"},
		{http.MethodGet, "/v1/instances/analyst-intern-person-a/effective"},
		{http.MethodGet, "/v1/templates/analyst-intern/versions/1"},
		{http.MethodGet, "/v1/templates/analyst-intern/clones"},
		{http.MethodGet, "/v1/action-policies"},
		{http.MethodGet, "/v1/usage"},
		{http.MethodGet, "/v1/virtual-keys"},
	} {
		if got := console(admin, r[0], r[1]); got.status != http.StatusUnauthorized {
			t.Errorf("administrator %s %s = %d, want 401: %s", r[0], r[1], got.status, got.raw)
		}
	}

	// The access route reports each caller's own roles and nothing about anyone else.
	for person, want := range map[string]string{
		admin:   `"administrator":true,"auditor":false`,
		auditor: `"administrator":false,"auditor":true`,
		nobody:  `"administrator":false,"auditor":false`,
		// B's administrator, signed in to A.
		adminOfB: `"administrator":false,"auditor":false`,
	} {
		got := console(person, http.MethodGet, "/v1/console/access")
		if got.status != http.StatusOK || !strings.Contains(strings.ReplaceAll(got.raw, " ", ""), want) {
			t.Errorf("%s access = %d %s, want %s", person, got.status, got.raw, want)
		}
	}

	// Development callers are unchanged: no console app, no role needed.
	for _, path := range reads {
		if got := h.call(t, a, http.MethodGet, path, ""); got.status != http.StatusOK {
			t.Errorf("development GET %s = %d: %s", path, got.status, got.raw)
		}
	}
}

// Only a console auditor of the tenant reads its evidence log through the console, and only
// reads it. Never skip or weaken.
func TestAuthzConsoleEvidenceIsForAuditors(t *testing.T) {
	var signedInto uuid.UUID
	h := newHarness(t, api.WithConsole{Console: consoleAs{&signedInto}, Fallback: api.InsecureDevHeaders{}})
	a, b := h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed = %d: %s", got.status, got.raw)
	}
	const auditor, admin, nobody, auditorOfB = "entra:aaaaaaaa-0000-4000-8000-00000000000b", "entra:aaaaaaaa-0000-4000-8000-00000000000a",
		"entra:aaaaaaaa-0000-4000-8000-00000000000c", "entra:bbbbbbbb-0000-4000-8000-00000000000b"
	role := func(tenant uuid.UUID, role string, people ...string) {
		t.Helper()
		op := registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: uuid.NewString()}
		if err := registry.ConfigureConsoleRole(t.Context(), h.db.OwnerURL, op, role, people, h.key); err != nil {
			t.Fatal(err)
		}
	}
	role(a, registry.ConsoleAuditor, auditor)
	role(a, registry.ConsoleAdministrator, admin)
	role(b, registry.ConsoleAuditor, auditorOfB)
	console := func(person, method, path string) response {
		t.Helper()
		return h.call(t, uuid.Nil, method, path, "", "Authorization", "Bearer "+person)
	}

	signedInto = a
	got := console(auditor, http.MethodGet, "/v1/events?limit=200")
	if got.status != http.StatusOK || !strings.Contains(got.raw, `"action":"template.version.created"`) {
		t.Fatalf("auditor = %d: %s", got.status, got.raw)
	}
	for _, person := range []string{admin, nobody, auditorOfB} {
		got := console(person, http.MethodGet, "/v1/events")
		if got.status != http.StatusForbidden || strings.Contains(got.raw, "template.version.created") {
			t.Errorf("%s reads A's evidence = %d: %s", person, got.status, got.raw)
		}
	}
	if got := console(auditor, http.MethodPost, "/v1/events"); got.status != http.StatusUnauthorized {
		t.Errorf("auditor POST /v1/events = %d, want 401", got.status)
	}
	if got := console(auditor, http.MethodGet, "/v1/console/access"); !strings.Contains(strings.ReplaceAll(got.raw, " ", ""), `"administrator":false,"auditor":true`) {
		t.Errorf("auditor access = %s", got.raw)
	}
	// B's auditor in B reads B's chain, which holds none of A's events.
	signedInto = b
	if got := console(auditorOfB, http.MethodGet, "/v1/events?limit=200"); got.status != http.StatusOK || strings.Contains(got.raw, "template.version.created") || strings.Contains(got.raw, a.String()) {
		t.Errorf("B's auditor = %d: %s", got.status, got.raw)
	}
	// mst exports with development headers, unchanged.
	if got := h.call(t, a, http.MethodGet, "/v1/events", ""); got.status != http.StatusOK {
		t.Errorf("development export = %d", got.status)
	}
}

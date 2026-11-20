//go:build authz

package api_test

// HUMAN REVIEW REQUIRED: who reads agent links and action policies through the console, and that
// nothing else of the policy engine (decide, simulate, the compiled Cedar, writes) reaches a console
// caller (docs/console-management-plan.md, slice 4; D70). Run by `make test-authz`; never skip or
// weaken.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

func TestAuthzConsolePoliciesAreForAdministrators(t *testing.T) {
	var signedInto uuid.UUID
	h := newHarness(t, api.WithConsole{Console: consoleAs{&signedInto}, Fallback: api.InsecureDevHeaders{}})
	a, b := h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	for path, body := range map[string]string{"/v1/links/intern-to-market": linkJSON, "/v1/action-policies/intern-actions": actionPolicyJSON} {
		if got := h.call(t, a, http.MethodPut, path, body); got.status != http.StatusCreated {
			t.Fatalf("seed %s = %d: %s", path, got.status, got.raw)
		}
	}
	// B has its own link, which A's administrator must never see.
	bLink := strings.NewReplacer("intern-to-market", "b-only-link").Replace(linkJSON)
	if got := h.call(t, b, http.MethodPut, "/v1/links/b-only-link", bLink); got.status != http.StatusCreated {
		t.Fatalf("seed B = %d: %s", got.status, got.raw)
	}
	const admin, auditor, nobody, adminOfB = "entra:aaaaaaaa-0000-4000-8000-00000000001a", "entra:aaaaaaaa-0000-4000-8000-00000000001b",
		"entra:aaaaaaaa-0000-4000-8000-00000000001c", "entra:bbbbbbbb-0000-4000-8000-00000000001a"
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
	console := func(person, method, path, body string) response {
		t.Helper()
		return h.call(t, uuid.Nil, method, path, body, "Authorization", "Bearer "+person)
	}

	signedInto = a
	reads := map[string]string{
		"/v1/links":                          `"intern-to-market"`,
		"/v1/links/intern-to-market":         `"get-quotes"`,
		"/v1/action-policies":                `"intern-actions"`,
		"/v1/action-policies/intern-actions": `"crm.update"`,
	}
	for path, want := range reads {
		if got := console(admin, http.MethodGet, path, ""); got.status != http.StatusOK || !strings.Contains(got.raw, want) || strings.Contains(got.raw, "b-only-link") {
			t.Errorf("administrator GET %s = %d: %s", path, got.status, got.raw)
		}
	}
	// Not an administrator of A: an auditor, no role, and B's administrator signed in to A. An
	// unknown name is refused as a known one is, so a refusal says nothing about what exists.
	for _, who := range []string{auditor, nobody, adminOfB} {
		for _, path := range []string{"/v1/links", "/v1/links/intern-to-market", "/v1/links/no-such-link",
			"/v1/action-policies", "/v1/action-policies/intern-actions", "/v1/action-policies/no-such-policy"} {
			if got := console(who, http.MethodGet, path, ""); got.status != http.StatusForbidden || strings.Contains(got.raw, "get-quotes") || strings.Contains(got.raw, "crm.update") {
				t.Errorf("%s GET %s = %d: %s", who, path, got.status, got.raw)
			}
		}
	}
	for _, path := range []string{"/v1/links/no-such-link", "/v1/action-policies/no-such-policy"} {
		if got := console(admin, http.MethodGet, path, ""); got.status != http.StatusNotFound {
			t.Errorf("administrator GET %s = %d, want 404", path, got.status)
		}
	}

	// B's administrator in B sees B's link only; A's are not there.
	signedInto = b
	if got := console(adminOfB, http.MethodGet, "/v1/links", ""); got.status != http.StatusOK || !strings.Contains(got.raw, "b-only-link") || strings.Contains(got.raw, `"intern-to-market"`) {
		t.Errorf("B's administrator links = %d: %s", got.status, got.raw)
	}
	if got := console(adminOfB, http.MethodGet, "/v1/action-policies/intern-actions", ""); got.status != http.StatusNotFound {
		t.Errorf("B's administrator, A's policy = %d, want 404: %s", got.status, got.raw)
	}

	// Nothing else of the policy engine, no write, and no name outside the pattern reaches a
	// console caller, even an administrator.
	signedInto = a
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/policy/cedar", ""},
		{http.MethodPost, "/v1/policy/decisions", quoteCall},
		{http.MethodPost, "/v1/policy/simulate", `{"request":` + quoteCall + `}`},
		{http.MethodPut, "/v1/links/intern-to-market", linkJSON},
		{http.MethodDelete, "/v1/links/intern-to-market", ""},
		{http.MethodPut, "/v1/action-policies/intern-actions", actionPolicyJSON},
		{http.MethodDelete, "/v1/action-policies/intern-actions", ""},
		{http.MethodGet, "/v1/links/intern-to-market/x", ""},
		{http.MethodGet, "/v1/links/Intern-To-Market", ""},
		{http.MethodGet, "/v1/links/intern%2Dto-market", ""},
		{http.MethodGet, "/v1/action-policies/intern-actions/", ""},
	} {
		if got := console(admin, c.method, c.path, c.body); got.status != http.StatusUnauthorized {
			t.Errorf("administrator %s %s = %d, want 401: %s", c.method, c.path, got.status, got.raw)
		}
	}
	// The refused writes changed nothing.
	if got := h.call(t, a, http.MethodGet, "/v1/links/intern-to-market", ""); got.status != http.StatusOK || got.etag != `"1"` {
		t.Errorf("the link after refused writes = %d %s: %s", got.status, got.etag, got.raw)
	}

	// Development callers are unchanged: no console app, no role needed, to read or to decide.
	for path := range reads {
		if got := h.call(t, a, http.MethodGet, path, ""); got.status != http.StatusOK {
			t.Errorf("development GET %s = %d: %s", path, got.status, got.raw)
		}
	}
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", quoteCall)); got != "allow" {
		t.Errorf("development decision = %s, want allow", got)
	}
}

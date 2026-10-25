//go:build authz

// Adversarial tenant-isolation suite, run by `make test-authz`. Never skip or weaken these
// (CLAUDE.md invariants 1-3). Tenant B attacks tenant A through the API and through direct SQL
// as the server's own database role.
package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

var tenantTables = []string{"agent_templates", "agent_template_versions", "agent_instances", "evidence_outbox"}

// seedTenantA gives tenant A a template and an instance.
func seedTenantA(t *testing.T, h harness) (a, b uuid.UUID) {
	t.Helper()
	a, b = h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed template = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON); got.status != http.StatusCreated {
		t.Fatalf("seed instance = %d: %s", got.status, got.raw)
	}
	return a, b
}

func TestAuthzTenantCannotReadAnotherTenantsRecords(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	_, b := seedTenantA(t, h)

	for _, path := range []string{
		"/v1/templates/analyst-intern",
		"/v1/templates/analyst-intern/versions/1",
		"/v1/instances/analyst-intern-person-a",
	} {
		got := h.call(t, b, http.MethodGet, path, "")
		// The same answer as for a name that exists nowhere, so B cannot infer A's names.
		absent := h.call(t, b, http.MethodGet, strings.Replace(path, "analyst-intern", "no-such-name", 1), "")
		if got.status != http.StatusNotFound || absent.status != http.StatusNotFound || got.body["title"] != absent.body["title"] {
			t.Errorf("GET %s as B = %d %v; absent name = %d %v; want identical 404s", path, got.status, got.body["title"], absent.status, absent.body["title"])
		}
	}
	for _, path := range []string{"/v1/templates", "/v1/instances"} {
		got := h.call(t, b, http.MethodGet, path, "")
		if items, _ := got.body["items"].([]any); got.status != http.StatusOK || len(items) != 0 {
			t.Errorf("GET %s as B = %d with %d items, want 200 and none: %s", path, got.status, len(items), got.raw)
		}
	}
}

func TestAuthzTenantCannotChangeAnotherTenantsRecords(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a, b := seedTenantA(t, h)

	got := h.call(t, b, http.MethodPost, "/v1/instances/analyst-intern-person-a/transitions", `{"to":"active"}`, "If-Match", `"1"`)
	if got.status != http.StatusNotFound {
		t.Errorf("B transitions A's instance = %d, want 404", got.status)
	}
	// A's template version does not exist for B, so B cannot bind an instance to it.
	if got = h.call(t, b, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON); got.status != http.StatusUnprocessableEntity {
		t.Errorf("B binds to A's template = %d, want 422: %s", got.status, got.raw)
	}
	// Reusing A's name gives B its own version 1, not a collision that would reveal A.
	if got = h.call(t, b, http.MethodPut, "/v1/templates/analyst-intern", strings.Replace(templateJSON, "Support interns", "B's purpose", 1)); got.status != http.StatusCreated || got.etag != `"1"` {
		t.Errorf("B applies A's template name = %d etag %s, want 201 \"1\"", got.status, got.etag)
	}

	mine := h.call(t, a, http.MethodGet, "/v1/templates/analyst-intern", "")
	doc, _ := mine.body["document"].(map[string]any)
	spec, _ := doc["spec"].(map[string]any)
	if mine.etag != `"1"` || spec["purpose"] != "Support interns" {
		t.Errorf("A's template after B's writes = etag %s purpose %v, want unchanged", mine.etag, spec["purpose"])
	}
	state := h.call(t, a, http.MethodGet, "/v1/instances/analyst-intern-person-a", "")
	if state.etag != `"1"` {
		t.Errorf("A's instance revision = %s, want \"1\" (untouched)", state.etag)
	}
}

func TestAuthzAppRoleSeesNothingWithoutTenant(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	seedTenantA(t, h)

	for _, table := range tenantTables {
		if table == "evidence_outbox" {
			continue // the app role cannot read the outbox at all; checked below
		}
		if n := testdb.CountIn(t, h.db.AppURL, uuid.Nil, "SELECT count(*) FROM "+table); n != 0 {
			t.Errorf("%s with no tenant set: %d rows visible, want 0", table, n)
		}
		if n := testdb.Count(t, h.db.OwnerURL, "SELECT count(*) FROM "+table); n == 0 {
			t.Errorf("%s has no rows as owner; the test seeded nothing and proves nothing", table)
		}
	}
	if err := testdb.ExecErr(h.db.AppURL, uuid.Nil, "SELECT count(*) FROM evidence_outbox"); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("app role reading evidence_outbox: err = %v, want permission denied", err)
	}
}

func TestAuthzAppRoleCannotReachAnotherTenantBySQL(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a, b := seedTenantA(t, h)
	// B needs rows of its own, or "retarget a row to A" would pass by matching nothing.
	if got := h.call(t, b, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed B template = %d", got.status)
	}
	if got := h.call(t, b, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON); got.status != http.StatusCreated {
		t.Fatalf("seed B instance = %d", got.status)
	}

	for _, table := range []string{"agent_templates", "agent_template_versions", "agent_instances"} {
		if n := testdb.CountIn(t, h.db.AppURL, b, "SELECT count(*) FROM "+table+" WHERE tenant_id = $1", a); n != 0 {
			t.Errorf("%s: B sees %d of A's rows by explicit tenant_id, want 0", table, n)
		}
	}

	attacks := map[string]string{
		"insert a template into A": `INSERT INTO agent_templates (tenant_id, name, latest_version) VALUES ($1, 'planted', 1)`,
		"insert evidence for A":    `INSERT INTO evidence_outbox (tenant_id, actor, action, subject_kind, subject_name, request_id) VALUES ($1, 'x', 'x', 'x', 'x', 'x')`,
		"retarget a row to A":      `UPDATE agent_instances SET tenant_id = $1`,
	}
	for name, stmt := range attacks {
		if err := testdb.ExecErr(h.db.AppURL, b, stmt, a); err == nil {
			t.Errorf("%s as B: succeeded, want a row-level security violation", name)
		}
	}

	// UPDATE and DELETE of A's rows match nothing under B's policy; the owner sees A intact.
	if err := testdb.ExecErr(h.db.AppURL, b, `UPDATE agent_instances SET state = 'retired' WHERE tenant_id = $1`, a); err != nil {
		t.Fatalf("UPDATE as B: %v", err)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM agent_instances WHERE tenant_id = $1 AND state = 'requested'`, a); n != 1 {
		t.Errorf("A's instance after B's UPDATE: %d in requested, want 1", n)
	}
}

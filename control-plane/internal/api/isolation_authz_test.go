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

var tenantTables = []string{"agent_templates", "agent_template_versions", "agent_instances", "evidence_events", "evidence_heads"}

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
	for _, path := range []string{"/v1/templates", "/v1/instances", "/v1/events"} {
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
		if n := testdb.CountIn(t, h.db.AppURL, uuid.Nil, "SELECT count(*) FROM "+table); n != 0 {
			t.Errorf("%s with no tenant set: %d rows visible, want 0", table, n)
		}
		if n := testdb.Count(t, h.db.OwnerURL, "SELECT count(*) FROM "+table); n == 0 {
			t.Errorf("%s has no rows as owner; the test seeded nothing and proves nothing", table)
		}
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

	var keyID string
	{
		rows := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_signing_keys`)
		if rows != 1 {
			t.Fatalf("signing keys = %d, want 1", rows)
		}
		keyID = testdb.Scalar(t, h.db.OwnerURL, `SELECT key_id FROM evidence_signing_keys`)
	}
	hex64 := strings.Repeat("ab", 32)
	// Every value is otherwise valid, so the only thing that can refuse these is row-level security.
	attacks := map[string]struct {
		stmt string
		args []any
	}{
		"insert a template into A": {`INSERT INTO agent_templates (tenant_id, name, latest_version) VALUES ($1, 'planted', 1)`, []any{a}},
		"insert an event into A's chain": {`INSERT INTO evidence_events (tenant_id, seq, occurred_at, actor, action, subject_kind,
			subject_name, request_id, prev_hash, hash, key_id, signature)
			VALUES ($1, 99, now(), 'x', 'x', 'x', 'x', 'x', $2, $2, $3, 'x')`, []any{a, hex64, keyID}},
		"plant a chain head for A": {`INSERT INTO evidence_heads (tenant_id, seq, hash) VALUES ($1, 0, $2)
			ON CONFLICT (tenant_id) DO UPDATE SET seq = 0`, []any{a, hex64}},
		"retarget a row to A": {`UPDATE agent_instances SET tenant_id = $1`, []any{a}},
	}
	for name, attack := range attacks {
		err := testdb.ExecErr(h.db.AppURL, b, attack.stmt, attack.args...)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Errorf("%s as B: err = %v, want a row-level security violation", name, err)
		}
	}

	// UPDATE and DELETE of A's rows match nothing under B's policy; the owner sees A intact.
	if err := testdb.ExecErr(h.db.AppURL, b, `UPDATE agent_instances SET state = 'retired' WHERE tenant_id = $1`, a); err != nil {
		t.Fatalf("UPDATE as B: %v", err)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM agent_instances WHERE tenant_id = $1 AND state = 'requested'`, a); n != 1 {
		t.Errorf("A's instance after B's UPDATE: %d in requested, want 1", n)
	}
	if err := testdb.ExecErr(h.db.AppURL, b, `UPDATE evidence_heads SET seq = 0 WHERE tenant_id = $1`, a); err != nil {
		t.Fatalf("UPDATE head as B: %v", err)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT seq FROM evidence_heads WHERE tenant_id = $1`, a); n != 2 {
		t.Errorf("A's chain head after B's UPDATE = %d, want 2 (template and instance events)", n)
	}
}

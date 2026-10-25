//go:build authz

// Adversarial tenant-isolation suite, run by `make test-authz`. Never skip or weaken these
// (CLAUDE.md invariants 1-3). Tenant B attacks tenant A through the API and through direct SQL
// as the server's own database role.
package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

var tenantTables = []string{"agent_templates", "agent_template_versions", "agent_instances", "evidence_events", "evidence_heads", "hr_events", "hr_webhook_secrets",
	"catalogue_approvers", "catalogue_requests", "catalogue_approvals", "catalogue_published", "policy_documents", "privacy_officers", "erasure_requests"}

// seedTenantA gives tenant A a template, an instance, an HR secret and one HR event.
func seedTenantA(t *testing.T, h harness) (a, b uuid.UUID) {
	t.Helper()
	a, b = h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	if got := h.postHR(t, a, h.hrSecret(t, a), time.Now(), hrEvent("a-ev-1", "joiner", "A-PERSON")); got.status != http.StatusAccepted {
		t.Fatalf("seed HR event = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed template = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON); got.status != http.StatusCreated {
		t.Fatalf("seed instance = %d: %s", got.status, got.raw)
	}
	// A high-risk template (no tier) published through two approvers, so every catalogue table
	// has rows of A's for the attacks to target.
	for _, tenant := range []uuid.UUID{a, b} {
		if err := store.SetCatalogueApprovers(context.Background(), h.db.OwnerURL, tenant,
			[]string{"dev:cat-1@example.invalid", "dev:cat-2@example.invalid"}); err != nil {
			t.Fatal(err)
		}
	}
	req := h.call(t, a, http.MethodPost, "/v1/templates/analyst-intern/versions/1/publication", "")
	if req.status != http.StatusCreated {
		t.Fatalf("seed publication request = %d: %s", req.status, req.raw)
	}
	for _, approver := range []string{"cat-1@example.invalid", "cat-2@example.invalid"} {
		got := h.call(t, a, http.MethodPost, "/v1/catalogue/requests/"+req.body["id"].(string)+"/decision",
			`{"decision":"approve","reason":"ok"}`, "X-Muistamo-Actor", approver)
		if got.status != http.StatusOK {
			t.Fatalf("seed approval by %s = %d: %s", approver, got.status, got.raw)
		}
	}
	for path, body := range map[string]string{"/v1/links/intern-to-market": linkJSON, "/v1/action-policies/intern-actions": actionPolicyJSON} {
		if got := h.call(t, a, http.MethodPut, path, body); got.status != http.StatusCreated {
			t.Fatalf("seed %s = %d: %s", path, got.status, got.raw)
		}
	}
	// Both tenants have a privacy officer; A has one completed erasure (of someone with no data).
	for _, tenant := range []uuid.UUID{a, b} {
		if err := store.SetPrivacyOfficers(context.Background(), h.db.OwnerURL, tenant, []string{"dev:" + officer}); err != nil {
			t.Fatal(err)
		}
	}
	nobody := `{"id":"` + seededErasure + `","reason":"seed","subject":{"identities":["dev:nobody@example.invalid"],"email":"nobody@example.invalid"}}`
	if got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", nobody, asOfficer()...); got.status != http.StatusCreated {
		t.Fatalf("seed erasure = %d: %s", got.status, got.raw)
	}
	return a, b
}

const seededErasure = "6f1c2c1e-1d0b-4b0e-9a54-6a3f1c2b7d10"

func TestAuthzTenantCannotReadAnotherTenantsRecords(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
	_, b := seedTenantA(t, h)

	for _, path := range []string{
		"/v1/templates/analyst-intern",
		"/v1/templates/analyst-intern/versions/1",
		"/v1/instances/analyst-intern-person-a",
		"/v1/links/intern-to-market",
		"/v1/action-policies/intern-actions",
	} {
		got := h.call(t, b, http.MethodGet, path, "")
		// The same answer as for a name that exists nowhere, so B cannot infer A's names.
		absent := h.call(t, b, http.MethodGet, strings.NewReplacer("analyst-intern", "no-such-name", "intern-to-market", "no-such-name", "intern-actions", "no-such-name").Replace(path), "")
		if got.status != http.StatusNotFound || absent.status != http.StatusNotFound || got.body["title"] != absent.body["title"] {
			t.Errorf("GET %s as B = %d %v; absent name = %d %v; want identical 404s", path, got.status, got.body["title"], absent.status, absent.body["title"])
		}
	}
	for _, path := range []string{"/v1/templates", "/v1/instances", "/v1/events", "/v1/links", "/v1/action-policies"} {
		got := h.call(t, b, http.MethodGet, path, "")
		if items, _ := got.body["items"].([]any); got.status != http.StatusOK || len(items) != 0 {
			t.Errorf("GET %s as B = %d with %d items, want 200 and none: %s", path, got.status, len(items), got.raw)
		}
	}
}

func TestAuthzTenantCannotChangeAnotherTenantsRecords(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
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
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
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
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
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
	events := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id = $1`, a)
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT seq FROM evidence_heads WHERE tenant_id = $1`, a); n != events || n == 0 {
		t.Errorf("A's chain head after B's UPDATE = %d, want %d (A's own event count)", n, events)
	}
}

func TestAuthzHRCredentialsAndLifecycleAreTenantScoped(t *testing.T) {
	d := &fakeDispatcher{}
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, d)
	a, b := seedTenantA(t, h)
	bSecret := h.hrSecret(t, b)

	// B's secret cannot speak for A, even for A's real person and a fresh event id.
	if got := h.postHR(t, a, bSecret, time.Now(), hrEvent("forged", "leaver", "A-PERSON")); got.status != http.StatusUnauthorized {
		t.Errorf("B's secret on A's tenant = %d, want 401", got.status)
	}
	// B naming A's person in its own tenant is accepted for B only and touches nothing of A's.
	before := d.count()
	if got := h.postHR(t, b, bSecret, time.Now(), hrEvent("b-ev-1", "leaver", "A-PERSON")); got.status != http.StatusAccepted {
		t.Fatalf("B's own leaver = %d", got.status)
	}
	if d.count() != before+1 || !strings.HasPrefix(d.calls[len(d.calls)-1], b.String()+"/") {
		t.Errorf("dispatch scope = %v, want B's tenant", d.calls)
	}
	if n := testdb.CountIn(t, h.db.AppURL, b, `SELECT count(*) FROM hr_events WHERE event_id = 'a-ev-1'`); n != 0 {
		t.Errorf("B sees A's HR event")
	}
	if n := testdb.CountIn(t, h.db.AppURL, b, `SELECT count(*) FROM hr_webhook_secrets WHERE tenant_id = $1`, a); n != 0 {
		t.Errorf("B can read A's HR secret")
	}

	// The workflow activities run in B's scope cannot find or bind to A's records.
	conn, err := store.Open(context.Background(), h.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	acts := &lifecycle.Activities{Registry: registry.New(conn, h.key), Provisioner: &lifecycle.Simulated{}, Revoker: &lifecycle.Simulated{}}
	bScope := lifecycle.Scope{Tenant: b, WorkflowID: "attack", EventID: "b-ev-1"}
	if names, err := acts.PersonInstances(context.Background(), bScope, "A-PERSON"); err != nil || len(names) != 0 {
		t.Errorf("B's leaver finds %v (%v), want none of A's instances", names, err)
	}
	if templates, err := acts.MatchTemplates(context.Background(), bScope, "ANALYST_INTERN"); err != nil || len(templates) != 0 {
		t.Errorf("B's joiner matches %v (%v), want none of A's templates", templates, err)
	}
	if _, err := acts.EnsureInstance(context.Background(), bScope, registry.TemplateVersionRef{Name: "analyst-intern", Version: 1},
		lifecycle.Person{ID: "B-PERSON", Email: "b@example.invalid", JobCode: "ANALYST_INTERN"}); err == nil {
		t.Errorf("B created an instance bound to A's template")
	}

	attacks := map[string]string{
		"plant an HR event in A": `INSERT INTO hr_events (tenant_id, event_id, type, person_id, workflow_id, payload) VALUES ($1, 'planted', 'leaver', 'A-PERSON', 'x', '{}')`,
		"replace A's HR secret":  `INSERT INTO hr_webhook_secrets (tenant_id, secret) VALUES ($1, decode(repeat('ab', 32), 'hex'))`,
	}
	for name, stmt := range attacks {
		err := testdb.ExecErr(h.db.AppURL, b, stmt, a)
		if err == nil || (!strings.Contains(err.Error(), "row-level security") && !strings.Contains(err.Error(), "permission denied")) {
			t.Errorf("%s as B: err = %v, want refusal", name, err)
		}
	}
}

func TestAuthzCatalogueIsTenantScoped(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
	a, b := seedTenantA(t, h)
	requests := h.call(t, a, http.MethodGet, "/v1/catalogue/requests", "")
	id := requests.body["items"].([]any)[0].(map[string]any)["id"].(string)

	// B, even as one of B's own catalogue approvers, cannot see, decide or withdraw A's catalogue.
	cat := []string{"X-Muistamo-Actor", "cat-1@example.invalid"}
	if got := h.call(t, b, http.MethodGet, "/v1/catalogue", "", cat...); len(got.body["items"].([]any)) != 0 {
		t.Errorf("B sees A's catalogue: %s", got.raw)
	}
	if got := h.call(t, b, http.MethodGet, "/v1/catalogue/requests", "", cat...); len(got.body["items"].([]any)) != 0 {
		t.Errorf("B sees A's requests: %s", got.raw)
	}
	if got := h.call(t, b, http.MethodPost, "/v1/catalogue/requests/"+id+"/decision", `{"decision":"reject","reason":"x"}`, cat...); got.status != http.StatusNotFound {
		t.Errorf("B decides A's request = %d, want 404", got.status)
	}
	if got := h.call(t, b, http.MethodDelete, "/v1/catalogue/analyst-intern", "", cat...); got.status != http.StatusNotFound {
		t.Errorf("B withdraws A's template = %d, want 404", got.status)
	}
	if got := h.call(t, a, http.MethodGet, "/v1/catalogue", ""); len(got.body["items"].([]any)) != 1 {
		t.Errorf("A's catalogue after B's attempts: %s", got.raw)
	}

	keyAttacks := map[string]string{
		"publish into A's catalogue": `INSERT INTO catalogue_published (tenant_id, template, version, request_id) VALUES ($1, 'analyst-intern', 1, gen_random_uuid())`,
		"approve as A's approver":    `INSERT INTO catalogue_approvals (tenant_id, request_id, approver, decision, reason) VALUES ($1, gen_random_uuid(), 'x', 'approve', 'x')`,
	}
	for name, stmt := range keyAttacks {
		err := testdb.ExecErr(h.db.AppURL, b, stmt, a)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Errorf("%s as B: err = %v, want a row-level security violation", name, err)
		}
	}
	if err := testdb.ExecErr(h.db.AppURL, a, `INSERT INTO catalogue_approvers (tenant_id, approver) VALUES ($1, 'dev:self-appointed')`, a); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("server role adding an approver: err = %v, want permission denied", err)
	}
}

func TestAuthzPolicyIsTenantScoped(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
	a, b := seedTenantA(t, h)

	// B grants itself everything A's rules deny. None of it may change A's decisions.
	permissive := strings.NewReplacer(`"allowedSkills":["get-quotes"]`, `"allowedSkills":["get-quotes","place-order"]`,
		"intern-to-market", "b-reverse").Replace(linkJSON)
	permissive = strings.Replace(permissive, `"from":{"template":"analyst-intern"},"to":{"template":"market-data-agent"}`,
		`"from":{"template":"market-data-agent"},"to":{"template":"analyst-intern"}`, 1)
	if got := h.call(t, b, http.MethodPut, "/v1/links/b-reverse", permissive); got.status != http.StatusCreated {
		t.Fatalf("B's link = %d: %s", got.status, got.raw)
	}
	allowAll := strings.NewReplacer(`"default":"deny"`, `"default":"allow"`, `{"action":"crm.update","effect":"deny"}`, `{"action":"crm.update","effect":"allow"}`).Replace(actionPolicyJSON)
	if got := h.call(t, b, http.MethodPut, "/v1/action-policies/intern-actions", allowAll); got.status != http.StatusCreated {
		t.Fatalf("B's policy = %d: %s", got.status, got.raw)
	}
	for name, req := range map[string]string{
		"reverse call":    `{"kind":"call","from":"market-data-agent","to":"analyst-intern","skill":"get-quotes"}`,
		"unlinked skill":  `{"kind":"call","from":"analyst-intern","to":"market-data-agent","skill":"place-order"}`,
		"denied action":   `{"kind":"action","agent":"analyst-intern","action":"crm.update"}`,
		"unlisted action": `{"kind":"action","agent":"analyst-intern","action":"calendar.write"}`,
	} {
		if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", req)); got != "deny" {
			t.Errorf("%s for A with B's permissive rules: %s, want deny", name, got)
		}
		if got := decisionOf(t, h.call(t, b, http.MethodPost, "/v1/policy/decisions", req)); name != "unlinked skill" && got != "allow" {
			t.Errorf("%s for B under B's own rules: %s, want allow (the attack must be real)", name, got)
		}
	}
	// A's own rules still hold for A and are invisible to B.
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", quoteCall)); got != "allow" {
		t.Errorf("A's linked call: %s, want allow", got)
	}
	if got := decisionOf(t, h.call(t, b, http.MethodPost, "/v1/policy/decisions", quoteCall)); got != "deny" {
		t.Errorf("B using A's link: %s, want deny", got)
	}
	cedarB := h.call(t, b, http.MethodGet, "/v1/policy/cedar", "")
	if text, _ := cedarB.body["cedar"].(string); strings.Contains(text, "intern-to-market") {
		t.Errorf("B's compiled Cedar contains A's link:\n%s", text)
	}
	// A simulation as B, proposing A's names, sees only B's rules.
	sim := h.call(t, b, http.MethodPost, "/v1/policy/simulate", `{"request":`+quoteCall+`}`)
	if cur, _ := sim.body["current"].(map[string]any); cur["decision"] != "deny" {
		t.Errorf("B's simulation used A's link: %s", sim.raw)
	}
	// B cannot delete A's rules: deleting a name both hold removes B's own only.
	if got := h.call(t, b, http.MethodDelete, "/v1/links/intern-to-market", ""); got.status != http.StatusNotFound {
		t.Errorf("B deletes A's link = %d, want 404", got.status)
	}
	if got := h.call(t, b, http.MethodDelete, "/v1/action-policies/intern-actions", ""); got.status != http.StatusNoContent {
		t.Errorf("B deletes its own policy = %d, want 204", got.status)
	}
	for _, path := range []string{"/v1/links/intern-to-market", "/v1/action-policies/intern-actions"} {
		if got := h.call(t, a, http.MethodGet, path, ""); got.status != http.StatusOK {
			t.Errorf("A's %s after B's deletes = %d", path, got.status)
		}
	}
	// A's decision evidence stays in A's chain.
	if n := testdb.CountIn(t, h.db.AppURL, b, `SELECT count(*) FROM evidence_events WHERE tenant_id = $1 AND action = 'policy.decision'`, a); n != 0 {
		t.Errorf("B sees %d of A's decisions", n)
	}

	attacks := map[string]string{
		"plant a link in A": `INSERT INTO policy_documents (tenant_id, kind, name, revision, digest, document, updated_by)
			VALUES ($1, 'AgentLink', 'planted', 1, 'x', '{}', 'x')`,
		"retarget B's rules to A": `UPDATE policy_documents SET tenant_id = $1`,
	}
	for name, stmt := range attacks {
		err := testdb.ExecErr(h.db.AppURL, b, stmt, a)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Errorf("%s as B: err = %v, want a row-level security violation", name, err)
		}
	}
	if err := testdb.ExecErr(h.db.AppURL, b, `DELETE FROM policy_documents WHERE tenant_id = $1`, a); err != nil {
		t.Fatalf("DELETE as B: %v", err)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM policy_documents WHERE tenant_id = $1`, a); n != 2 {
		t.Errorf("A's rules after B's DELETE: %d, want 2", n)
	}
	// The database itself refuses a second action policy for one template within a tenant (B
	// holding one for the same template name above shows the rule is per tenant).
	err := testdb.ExecErr(h.db.AppURL, a, `INSERT INTO policy_documents (tenant_id, kind, name, template, revision, digest, document, updated_by)
		VALUES ($1, 'ActionPolicy', 'second', 'analyst-intern', 1, 'x', '{}', 'x')`, a)
	if err == nil || !strings.Contains(err.Error(), "policy_documents_one_policy_per_template") {
		t.Errorf("second action policy for a template by SQL: err = %v, want the unique index to refuse it", err)
	}
}

func TestAuthzPrivacyIsTenantScoped(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
	a, b := seedTenantA(t, h)
	// A holds person A (template author, instance binding, HR event) and so does B.
	if got := h.call(t, b, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed B template = %d", got.status)
	}
	aBefore := remaining(t, h, a)
	if len(aBefore) < 3 {
		t.Fatalf("A holds person A in %v; the test proves nothing", aBefore)
	}

	// B's officer erases person A in B. A's records are untouched.
	got := h.call(t, b, http.MethodPost, "/v1/privacy/erasures", erasureBody(uuid.New(), "DSR"), asOfficer()...)
	if got.status != http.StatusCreated {
		t.Fatalf("B's erasure = %d: %s", got.status, got.raw)
	}
	if aAfter := remaining(t, h, a); len(aAfter) != len(aBefore) || aAfter["agent_template_versions"] != aBefore["agent_template_versions"] {
		t.Errorf("B's erasure changed A's records: before %v, after %v", aBefore, aAfter)
	}
	if n := remaining(t, h, b)["agent_template_versions"]; n != 0 {
		t.Errorf("B's own template still names person A: %d", n)
	}
	// B's officer cannot read A's proof or export A's records.
	if got := h.call(t, b, http.MethodGet, "/v1/privacy/erasures/"+seededErasure, "", asOfficer()...); got.status != http.StatusNotFound {
		t.Errorf("B reads A's proof = %d, want 404", got.status)
	}
	export := h.call(t, b, http.MethodPost, "/v1/privacy/access", accessBody, asOfficer()...)
	if strings.Contains(export.raw, "Support interns") && strings.Contains(export.raw, a.String()) {
		t.Errorf("B's export contains A's records: %s", export.raw)
	}
	for table, rows := range export.body["sections"].(map[string]any) {
		for _, row := range rows.([]any) {
			if tenant, _ := row.(map[string]any)["tenant_id"].(string); tenant == a.String() {
				t.Errorf("B's export has A's %s row", table)
			}
		}
	}

	// The definer function: tenant B's setting reaches only B; no setting or a free-form
	// pseudonym is refused; the server role has no other way to rewrite history.
	if err := testdb.ExecErr(h.db.AppURL, b, `SELECT erase_subject(ARRAY['dev:person-a@example.invalid'], 'erased:'||gen_random_uuid())`); err != nil {
		t.Fatalf("erase_subject as B: %v", err)
	}
	if aAfter := remaining(t, h, a); aAfter["agent_template_versions"] != aBefore["agent_template_versions"] {
		t.Errorf("erase_subject in B's tenant reached A")
	}
	for name, stmt := range map[string]string{
		"no tenant":           `SELECT erase_subject(ARRAY['dev:person-a@example.invalid'], 'erased:'||gen_random_uuid())`,
		"free-form pseudonym": `SELECT erase_subject(ARRAY['dev:person-a@example.invalid'], 'attacker-chosen')`,
		"empty subject":       `SELECT erase_subject(ARRAY[]::text[], 'erased:'||gen_random_uuid())`,
		"short subject":       `SELECT erase_subject(ARRAY['a'], 'erased:'||gen_random_uuid())`,
	} {
		tenant := b
		if name == "no tenant" {
			tenant = uuid.Nil
		}
		if err := testdb.ExecErr(h.db.AppURL, tenant, stmt); err == nil || !strings.Contains(err.Error(), "erase_subject") {
			t.Errorf("%s: err = %v, want erase_subject to refuse", name, err)
		}
	}
	for name, stmt := range map[string]string{
		"rewrite authorship directly": `UPDATE agent_template_versions SET created_by = 'x'`,
		"appoint an officer":          `INSERT INTO privacy_officers (tenant_id, officer) VALUES ($1, 'dev:self-appointed')`,
		"alter a proof":               `UPDATE erasure_requests SET reason = 'x'`,
	} {
		var args []any
		if strings.Contains(stmt, "$1") {
			args = []any{b}
		}
		if err := testdb.ExecErr(h.db.AppURL, b, stmt, args...); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s as the server role: err = %v, want permission denied", name, err)
		}
	}
}

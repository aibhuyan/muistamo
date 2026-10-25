package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

const linkJSON = `{"apiVersion":"muistamo.dev/v1","kind":"AgentLink","metadata":{"name":"intern-to-market"},
 "spec":{"from":{"template":"analyst-intern"},"to":{"template":"market-data-agent"},
         "allowedSkills":["get-quotes"],"dataClasses":["public","internal"],"rateLimit":"60/min"}}`

const actionPolicyJSON = `{"apiVersion":"muistamo.dev/v1","kind":"ActionPolicy","metadata":{"name":"intern-actions"},
 "spec":{"appliesTo":{"template":"analyst-intern"},"default":"deny","mode":"enforce",
         "rules":[{"action":"sharepoint.read","effect":"allow"},{"action":"crm.update","effect":"deny"}]}}`

const quoteCall = `{"kind":"call","from":"analyst-intern","to":"market-data-agent","skill":"get-quotes","dataClasses":["public"]}`

func decisionOf(t *testing.T, got response) string {
	t.Helper()
	if got.status != http.StatusOK {
		t.Fatalf("decision = %d: %s", got.status, got.raw)
	}
	if got.body["enforced"] != false || got.body["mode"] != "observe" {
		t.Fatalf("release 1 decision claims enforcement: %s", got.raw)
	}
	return got.body["decision"].(string)
}

func events(t *testing.T, h harness, tenant uuid.UUID, action string) int {
	t.Helper()
	return testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id = $1 AND action = $2`, tenant, action)
}

func TestPolicyApplyDecideChange(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")

	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", quoteCall)); got != "deny" {
		t.Errorf("before any link: %s, want deny", got)
	}
	got := h.call(t, a, http.MethodPut, "/v1/links/intern-to-market", linkJSON)
	if got.status != http.StatusCreated || got.etag != `"1"` {
		t.Fatalf("create link = %d %s: %s", got.status, got.etag, got.raw)
	}
	if got = h.call(t, a, http.MethodPut, "/v1/links/intern-to-market", linkJSON); got.status != http.StatusOK || got.etag != `"1"` {
		t.Errorf("identical apply = %d %s, want 200 \"1\"", got.status, got.etag)
	}
	if n := events(t, h, a, "link.created"); n != 1 {
		t.Errorf("link.created events = %d, want 1 (identical apply records nothing)", n)
	}

	d := h.call(t, a, http.MethodPost, "/v1/policy/decisions", quoteCall)
	if decisionOf(t, d) != "allow" || d.body["wouldBlock"] != false {
		t.Errorf("after the link: %s", d.raw)
	}
	if !strings.Contains(strings.Join(anyStrings(d.body["notEvaluated"]), ","), "rateLimit") {
		t.Errorf("notEvaluated does not admit rateLimit: %s", d.raw)
	}
	reverse := `{"kind":"call","from":"market-data-agent","to":"analyst-intern","skill":"get-quotes"}`
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", reverse)); got != "deny" {
		t.Errorf("reverse direction: %s, want deny", got)
	}
	if n := events(t, h, a, "policy.decision"); n != 3 {
		t.Errorf("policy.decision events = %d, want 3 (one per decision)", n)
	}

	// Narrow the link: the next decision follows the new rule, and the change is evidenced.
	narrowed := strings.Replace(linkJSON, `"public","internal"`, `"internal"`, 1)
	if got = h.call(t, a, http.MethodPut, "/v1/links/intern-to-market", narrowed); got.status != http.StatusOK || got.etag != `"2"` {
		t.Fatalf("update link = %d %s: %s", got.status, got.etag, got.raw)
	}
	if n := events(t, h, a, "link.updated"); n != 1 {
		t.Errorf("link.updated events = %d, want 1", n)
	}
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", quoteCall)); got != "deny" {
		t.Errorf("public data after narrowing: %s, want deny", got)
	}

	// Removing the link denies again.
	if got = h.call(t, a, http.MethodDelete, "/v1/links/intern-to-market", ""); got.status != http.StatusNoContent {
		t.Fatalf("delete link = %d: %s", got.status, got.raw)
	}
	internalCall := strings.Replace(quoteCall, `"public"`, `"internal"`, 1)
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", internalCall)); got != "deny" {
		t.Errorf("after delete: %s, want deny", got)
	}
	if n := events(t, h, a, "link.deleted"); n != 1 {
		t.Errorf("link.deleted events = %d, want 1", n)
	}
	if got = h.call(t, a, http.MethodDelete, "/v1/links/intern-to-market", ""); got.status != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", got.status)
	}
}

func TestPolicyActionPolicies(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	if got := h.call(t, a, http.MethodPut, "/v1/action-policies/intern-actions", actionPolicyJSON); got.status != http.StatusCreated {
		t.Fatalf("create policy = %d: %s", got.status, got.raw)
	}
	read := `{"kind":"action","agent":"analyst-intern","action":"sharepoint.read"}`
	update := `{"kind":"action","agent":"analyst-intern","action":"crm.update"}`
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", read)); got != "allow" {
		t.Errorf("sharepoint.read: %s", got)
	}
	d := h.call(t, a, http.MethodPost, "/v1/policy/decisions", update)
	if decisionOf(t, d) != "deny" || d.body["wouldBlock"] != true {
		t.Errorf("crm.update: %s", d.raw)
	}

	// A second policy for the same template is a conflict; nothing is stored or evidenced.
	other := strings.Replace(actionPolicyJSON, "intern-actions", "intern-actions-2", 1)
	got := h.call(t, a, http.MethodPut, "/v1/action-policies/intern-actions-2", other)
	if detail, _ := got.body["detail"].(string); got.status != http.StatusConflict || !strings.Contains(detail, `action policy "intern-actions" already applies`) {
		t.Errorf("second policy for one template = %d, want 409 naming the existing policy: %s", got.status, got.raw)
	}
	// requireApproval is release 2 and refused by the contract.
	approval := strings.Replace(actionPolicyJSON, `"effect":"deny"`, `"effect":"requireApproval"`, 1)
	if got := h.call(t, a, http.MethodPut, "/v1/action-policies/intern-actions", approval); got.status != http.StatusUnprocessableEntity {
		t.Errorf("requireApproval = %d, want 422", got.status)
	}
	// A body of the wrong kind on this route is refused.
	if got := h.call(t, a, http.MethodPut, "/v1/action-policies/intern-to-market",
		linkJSON); got.status != http.StatusUnprocessableEntity {
		t.Errorf("AgentLink body on the action-policy route = %d, want 422: %s", got.status, got.raw)
	}
	if n := events(t, h, a, "action-policy.created"); n != 1 {
		t.Errorf("action-policy.created events = %d, want 1", n)
	}

	// Monitor mode: the denial is reported, would not block.
	monitor := strings.Replace(actionPolicyJSON, `"mode":"enforce"`, `"mode":"monitor"`, 1)
	if got := h.call(t, a, http.MethodPut, "/v1/action-policies/intern-actions", monitor); got.status != http.StatusOK || got.etag != `"2"` {
		t.Fatalf("switch to monitor = %d: %s", got.status, got.raw)
	}
	d = h.call(t, a, http.MethodPost, "/v1/policy/decisions", update)
	if decisionOf(t, d) != "deny" || d.body["wouldBlock"] != false || d.body["monitored"] != true || d.body["policyMode"] != "monitor" {
		t.Errorf("monitor mode: %s", d.raw)
	}

	list := h.call(t, a, http.MethodGet, "/v1/action-policies", "")
	if items, _ := list.body["items"].([]any); len(items) != 1 {
		t.Errorf("list = %s", list.raw)
	}
}

func TestPolicyDecisionRequestsAreContractChecked(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	for name, body := range map[string]string{
		"call without a skill":     `{"kind":"call","from":"a","to":"b"}`,
		"action without an action": `{"kind":"action","agent":"a"}`,
		"call fields on an action": `{"kind":"action","agent":"a","action":"x.y","skill":"s"}`,
		"non-boolean attribute":    `{"kind":"action","agent":"a","action":"x.y","attributes":{"x":"yes"}}`,
		"unknown field":            `{"kind":"call","from":"a","to":"b","skill":"s","enforce":true}`,
		"depth below one":          `{"kind":"call","from":"a","to":"b","skill":"s","depth":0}`,
	} {
		if got := h.call(t, a, http.MethodPost, "/v1/policy/decisions", body); got.status != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d, want 422: %s", name, got.status, got.raw)
		}
	}
	if n := events(t, h, a, "policy.decision"); n != 0 {
		t.Errorf("rejected requests recorded %d decisions", n)
	}
}

func TestPolicySimulationChangesNothing(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	if got := h.call(t, a, http.MethodPut, "/v1/action-policies/intern-actions", actionPolicyJSON); got.status != http.StatusCreated {
		t.Fatalf("create policy = %d: %s", got.status, got.raw)
	}
	before := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id = $1`, a)

	proposed := strings.Replace(actionPolicyJSON, `{"action":"crm.update","effect":"deny"}`, `{"action":"crm.update","effect":"allow"}`, 1)
	sim := h.call(t, a, http.MethodPost, "/v1/policy/simulate",
		`{"request":{"kind":"action","agent":"analyst-intern","action":"crm.update"},"policies":[`+proposed+`]}`)
	if sim.status != http.StatusOK {
		t.Fatalf("simulate = %d: %s", sim.status, sim.raw)
	}
	current, _ := sim.body["current"].(map[string]any)
	next, _ := sim.body["proposed"].(map[string]any)
	if current["decision"] != "deny" || next["decision"] != "allow" || sim.body["changed"] != true {
		t.Errorf("simulation: %s", sim.raw)
	}

	if after := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE tenant_id = $1`, a); after != before {
		t.Errorf("simulation wrote %d evidence events", after-before)
	}
	stored := h.call(t, a, http.MethodGet, "/v1/action-policies/intern-actions", "")
	if stored.etag != `"1"` {
		t.Errorf("stored policy revision after simulation = %s, want \"1\"", stored.etag)
	}
	if got := decisionOf(t, h.call(t, a, http.MethodPost, "/v1/policy/decisions", `{"kind":"action","agent":"analyst-intern","action":"crm.update"}`)); got != "deny" {
		t.Errorf("real decision after simulation: %s, want deny", got)
	}

	// A proposal that cannot compile is refused, not half-applied.
	clash := strings.Replace(actionPolicyJSON, "intern-actions", "another", 1)
	if got := h.call(t, a, http.MethodPost, "/v1/policy/simulate",
		`{"request":{"kind":"action","agent":"analyst-intern","action":"crm.update"},"policies":[`+clash+`]}`); got.status != http.StatusUnprocessableEntity {
		t.Errorf("simulating two policies for one template = %d, want 422", got.status)
	}
}

func TestPolicyCompiledCedar(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	for path, body := range map[string]string{"/v1/links/intern-to-market": linkJSON, "/v1/action-policies/intern-actions": actionPolicyJSON} {
		if got := h.call(t, a, http.MethodPut, path, body); got.status != http.StatusCreated {
			t.Fatalf("PUT %s = %d: %s", path, got.status, got.raw)
		}
	}
	got := h.call(t, a, http.MethodGet, "/v1/policy/cedar", "")
	text, _ := got.body["cedar"].(string)
	for _, want := range []string{
		`@id("link/intern-to-market")`,
		`resource == Muistamo::Template::"market-data-agent"`,
		`forbid (`,
		`action == Muistamo::Action::"crm.update"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("compiled Cedar lacks %q:\n%s", want, text)
		}
	}
	if rules, _ := got.body["rules"].([]any); len(rules) != 3 {
		t.Errorf("rules = %v, want 3", got.body["rules"])
	}
}

func anyStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, i := range items {
		s, _ := i.(string)
		out = append(out, s)
	}
	return out
}

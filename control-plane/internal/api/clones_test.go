package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// lowTemplate is a low-risk template, so requesting publication publishes it at once.
func lowTemplate(name, purpose string) string {
	return `{"apiVersion":"muistamo.dev/v1","kind":"AgentTemplate","metadata":{"name":"` + name + `"},
	 "spec":{"purpose":"` + purpose + `","modelAlias":"reasoning-default","riskTier":"low",
	         "knowledgePacks":[{"name":"basics","version":"1.x"},{"name":"style"}],
	         "budget":{"perInstanceMonthlyEUR":100},"assignment":{"hrJobCodes":["ANALYST"]}}}`
}

func cloneJSON(name, sync, extra string) string {
	return `{"apiVersion":"muistamo.dev/v1","kind":"AgentClone","metadata":{"name":"` + name + `"},
	 "spec":{"template":"analyst","sync":"` + sync + `"` + extra + `}}`
}

func publishVersion(t *testing.T, h harness, tenant uuid.UUID, name string, version int, purpose string) {
	t.Helper()
	if got := h.call(t, tenant, http.MethodPut, "/v1/templates/"+name, lowTemplate(name, purpose)); got.status >= 300 {
		t.Fatalf("apply %s = %d: %s", name, got.status, got.raw)
	}
	got := h.call(t, tenant, http.MethodPost, "/v1/templates/"+name+"/versions/"+itoa(version)+"/publication", "")
	if got.status != http.StatusCreated || got.body["state"] != "published" {
		t.Fatalf("publish %s v%d = %d: %s", name, version, got.status, got.raw)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

type cloneState struct {
	resolved   any
	upstream   any
	assignable bool
	reason     string
}

func getClone(t *testing.T, h harness, tenant uuid.UUID, name string) cloneState {
	t.Helper()
	got := h.call(t, tenant, http.MethodGet, "/v1/clones/"+name, "")
	if got.status != http.StatusOK {
		t.Fatalf("GET clone %s = %d: %s", name, got.status, got.raw)
	}
	reason, _ := got.body["reason"].(string)
	return cloneState{got.body["resolvedVersion"], got.body["upstreamVersion"], got.body["assignable"] == true, reason}
}

func TestCloneSyncPolicies(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	publishVersion(t, h, a, "analyst", 1, "Support analysts")

	for name, body := range map[string]string{
		"c-follow": cloneJSON("c-follow", "follow", ""),
		"c-pin":    cloneJSON("c-pin", "pin", `,"version":1`),
		"c-manual": cloneJSON("c-manual", "manual", ""),
	} {
		if got := h.call(t, a, http.MethodPut, "/v1/clones/"+name, body); got.status != http.StatusCreated {
			t.Fatalf("create %s = %d: %s", name, got.status, got.raw)
		}
		if s := getClone(t, h, a, name); s.resolved != float64(1) || !s.assignable {
			t.Errorf("%s at v1: %+v", name, s)
		}
	}

	// A new published version: follow moves, pin stays, manual reports drift.
	publishVersion(t, h, a, "analyst", 2, "Support analysts and new hires")
	if s := getClone(t, h, a, "c-follow"); s.resolved != float64(2) || !s.assignable || s.upstream != nil {
		t.Errorf("follow after v2: %+v", s)
	}
	if s := getClone(t, h, a, "c-pin"); s.resolved != float64(1) || s.assignable || s.upstream != float64(2) {
		t.Errorf("pin after v2: %+v", s)
	}
	if s := getClone(t, h, a, "c-manual"); s.resolved != float64(1) || s.assignable || s.upstream != float64(2) || !strings.Contains(s.reason, "mst clone sync") {
		t.Errorf("manual after v2: %+v", s)
	}
	published := testdbAfter(t, h, a, "catalogue.published")
	if !strings.Contains(published, `"followClones": ["c-follow"]`) {
		t.Errorf("publication evidence does not name the follow clone it moved: %s", published)
	}

	// Sync moves only the manual clone, and only by hand.
	if got := h.call(t, a, http.MethodPost, "/v1/clones/c-manual/sync", ""); got.status != http.StatusOK || got.body["resolvedVersion"] != float64(2) || got.etag != `"2"` {
		t.Errorf("sync = %d %s: %s", got.status, got.etag, got.raw)
	}
	if n := events(t, h, a, "clone.synced"); n != 1 {
		t.Errorf("clone.synced events = %d, want 1", n)
	}
	if got := h.call(t, a, http.MethodPost, "/v1/clones/c-follow/sync", ""); got.status != http.StatusConflict {
		t.Errorf("sync of a follow clone = %d, want 409", got.status)
	}

	// Withdrawing the template leaves follow clones with nothing to resolve to.
	if err := store.SetCatalogueApprovers(context.Background(), h.db.OwnerURL, a, []string{"dev:cat-1@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if got := h.call(t, a, http.MethodDelete, "/v1/catalogue/analyst", "", "X-Muistamo-Actor", "cat-1@example.invalid"); got.status != http.StatusNoContent {
		t.Fatalf("withdraw = %d: %s", got.status, got.raw)
	}
	if s := getClone(t, h, a, "c-follow"); s.resolved != nil || s.assignable {
		t.Errorf("follow after withdrawal: %+v", s)
	}
	if s := getClone(t, h, a, "c-manual"); s.resolved != float64(2) || s.assignable {
		t.Errorf("manual after withdrawal: %+v (keeps its version, not assignable)", s)
	}

	list := h.call(t, a, http.MethodGet, "/v1/templates/analyst/clones", "")
	if items, _ := list.body["items"].([]any); len(items) != 3 {
		t.Errorf("template clones = %s", list.raw)
	}
	if got := h.call(t, a, http.MethodGet, "/v1/templates/nope/clones", ""); got.status != http.StatusNotFound {
		t.Errorf("clones of a missing template = %d", got.status)
	}
}

func TestCloneRules(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst", lowTemplate("analyst", "x")); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	for name, c := range map[string]struct {
		body   string
		status int
	}{
		"manual before publication": {cloneJSON("c", "manual", ""), http.StatusConflict},
		"pin to a missing version":  {cloneJSON("c", "pin", `,"version":9`), http.StatusUnprocessableEntity},
		"pin without a version":     {cloneJSON("c", "pin", ""), http.StatusUnprocessableEntity},
		"follow with a version":     {cloneJSON("c", "follow", `,"version":1`), http.StatusUnprocessableEntity},
		"overlay changes tools":     {cloneJSON("c", "follow", `,"overlay":{"tools":["email.send"]}`), http.StatusUnprocessableEntity},
		"overlay changes risk tier": {cloneJSON("c", "follow", `,"overlay":{"riskTier":"low"}`), http.StatusUnprocessableEntity},
		"missing template":          {strings.Replace(cloneJSON("c", "follow", ""), `"template":"analyst"`, `"template":"nope"`, 1), http.StatusUnprocessableEntity},
	} {
		if got := h.call(t, a, http.MethodPut, "/v1/clones/c", c.body); got.status != c.status {
			t.Errorf("%s = %d, want %d: %s", name, got.status, c.status, got.raw)
		}
	}
	if got := h.call(t, a, http.MethodPut, "/v1/clones/c", cloneJSON("c", "follow", "")); got.status != http.StatusCreated {
		t.Fatalf("create = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/clones/c", cloneJSON("c", "follow", "")); got.status != http.StatusOK || got.etag != `"1"` {
		t.Errorf("identical apply = %d %s", got.status, got.etag)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/templates/other", lowTemplate("other", "x")); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	moved := strings.Replace(cloneJSON("c", "follow", ""), `"template":"analyst"`, `"template":"other"`, 1)
	if got := h.call(t, a, http.MethodPut, "/v1/clones/c", moved); got.status != http.StatusConflict {
		t.Errorf("changing a clone's template = %d, want 409", got.status)
	}
	if n := events(t, h, a, "clone.created"); n != 1 {
		t.Errorf("clone.created = %d, want 1", n)
	}
}

func TestEffectiveSpecMergesOnlyTheOverlay(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	publishVersion(t, h, a, "analyst", 1, "Support analysts")
	overlay := `,"overlay":{"knowledgePacks":[{"name":"basics","version":"2.x"},{"name":"finland-tax"}],
	  "budget":{"perInstanceMonthlyEUR":50},"assignment":{"hrJobCodes":["ANALYST_FI"]}}`
	if got := h.call(t, a, http.MethodPut, "/v1/clones/analyst-fi", cloneJSON("analyst-fi", "follow", overlay)); got.status != http.StatusCreated {
		t.Fatalf("clone = %d: %s", got.status, got.raw)
	}
	inst := func(name, clone, version string) string {
		ref := ""
		if clone != "" {
			ref = `"cloneRef":"` + clone + `",`
		}
		return `{"apiVersion":"muistamo.dev/v1","kind":"AgentInstance","metadata":{"name":"` + name + `"},
		 "spec":{"templateRef":{"name":"analyst","version":"` + version + `"},` + ref + `
		         "binding":{"type":"user","ref":"person-a@example.invalid"},"state":"requested"}}`
	}
	if got := h.call(t, a, http.MethodPut, "/v1/instances/fi-1", inst("fi-1", "analyst-fi", "1")); got.status != http.StatusCreated {
		t.Fatalf("clone instance = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/instances/plain-1", inst("plain-1", "", "1")); got.status != http.StatusCreated {
		t.Fatalf("plain instance = %d: %s", got.status, got.raw)
	}

	eff := h.call(t, a, http.MethodGet, "/v1/instances/fi-1/effective", "")
	if eff.status != http.StatusOK || eff.body["clone"] != "analyst-fi" || eff.body["version"] != float64(1) {
		t.Fatalf("effective = %d: %s", eff.status, eff.raw)
	}
	spec := eff.body["spec"].(map[string]any)
	packs, _ := json.Marshal(spec["knowledgePacks"])
	if string(packs) != `[{"name":"basics","version":"2.x"},{"name":"style"},{"name":"finland-tax"}]` {
		t.Errorf("packs = %s", packs)
	}
	if spec["purpose"] != "Support analysts" || spec["riskTier"] != "low" || spec["modelAlias"] != "reasoning-default" {
		t.Errorf("template fields changed: %v", spec)
	}
	if b := spec["budget"].(map[string]any); b["perInstanceMonthlyEUR"] != float64(50) {
		t.Errorf("budget = %v", b)
	}
	plain := h.call(t, a, http.MethodGet, "/v1/instances/plain-1/effective", "")
	if pb := plain.body["spec"].(map[string]any)["budget"].(map[string]any); plain.body["clone"] != nil || pb["perInstanceMonthlyEUR"] != float64(100) {
		t.Errorf("plain effective = %s", plain.raw)
	}

	// The clone's instances move with it.
	publishVersion(t, h, a, "analyst", 2, "Support analysts, v2")
	if eff := h.call(t, a, http.MethodGet, "/v1/instances/fi-1/effective", ""); eff.body["version"] != float64(2) ||
		eff.body["spec"].(map[string]any)["purpose"] != "Support analysts, v2" {
		t.Errorf("clone instance after v2: %s", eff.raw)
	}

	// cloneRef must be a clone of the template, at its resolved version.
	if got := h.call(t, a, http.MethodPut, "/v1/instances/fi-2", inst("fi-2", "analyst-fi", "1")); got.status != http.StatusUnprocessableEntity {
		t.Errorf("cloneRef at a version the clone does not resolve to = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodPut, "/v1/instances/fi-3", inst("fi-3", "no-such-clone", "2")); got.status != http.StatusUnprocessableEntity {
		t.Errorf("unknown cloneRef = %d", got.status)
	}

	// Withdrawn: the clone cannot resolve, and effective refuses rather than guessing.
	if err := store.SetCatalogueApprovers(context.Background(), h.db.OwnerURL, a, []string{"dev:cat-1@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if got := h.call(t, a, http.MethodDelete, "/v1/catalogue/analyst", "", "X-Muistamo-Actor", "cat-1@example.invalid"); got.status != http.StatusNoContent {
		t.Fatal(got.raw)
	}
	if got := h.call(t, a, http.MethodGet, "/v1/instances/fi-1/effective", ""); got.status != http.StatusConflict {
		t.Errorf("effective of an unresolvable clone = %d, want 409: %s", got.status, got.raw)
	}
}

func testdbAfter(t *testing.T, h harness, tenant uuid.UUID, action string) string {
	t.Helper()
	conn := mustConn(t, h.db.OwnerURL)
	var after string
	if err := conn.QueryRow(context.Background(), `SELECT after::text FROM evidence_events WHERE tenant_id = $1 AND action = $2 ORDER BY seq DESC LIMIT 1`,
		tenant, action).Scan(&after); err != nil {
		t.Fatal(err)
	}
	return after
}

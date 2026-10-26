package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

func modelJSON(name, region string) string {
	return `{"apiVersion":"muistamo.dev/v1","kind":"ModelCatalogueItem","metadata":{"name":"` + name + `"},
	 "spec":{"provider":"anthropic","model":"claude-sonnet-5-5","region":"` + region + `","termsRef":"legal/anthropic-2026",
	         "dpaRef":"legal/dpa-anthropic","subProcessors":["aws-eu"],"priceSheet":{"currency":"EUR","inputPerMTok":2.8,"outputPerMTok":14}}}`
}

func aliasJSON(name, target string) string {
	return `{"apiVersion":"muistamo.dev/v1","kind":"ModelAlias","metadata":{"name":"` + name + `"},"spec":{"target":"` + target + `"}}`
}

const (
	platform = "platform@example.invalid"
	dpo      = "dpo@example.invalid"
)

func as(who string) []string { return []string{"X-Muistamo-Actor", who} }

func modelHarness(t *testing.T) (harness, uuid.UUID) {
	t.Helper()
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	if err := store.SetPrivacyOfficers(context.Background(), h.db.OwnerURL, a, []string{"dev:" + dpo, "dev:" + platform}); err != nil {
		t.Fatal(err)
	}
	return h, a
}

func decideModel(t *testing.T, h harness, tenant uuid.UUID, who, name, decision string) response {
	t.Helper()
	return h.call(t, tenant, http.MethodPost, "/v1/models/"+name+"/approval", `{"decision":"`+decision+`","reason":"reviewed"}`, as(who)...)
}

func approval(t *testing.T, h harness, tenant uuid.UUID, name string) string {
	t.Helper()
	got := h.call(t, tenant, http.MethodGet, "/v1/models/"+name, "")
	return got.body["approval"].(map[string]any)["status"].(string)
}

func TestModelApprovalRules(t *testing.T) {
	h, a := modelHarness(t)
	if got := h.call(t, a, http.MethodPut, "/v1/models/claude-eu", modelJSON("claude-eu", "eu-west-1"), as(platform)...); got.status != http.StatusCreated {
		t.Fatalf("apply = %d: %s", got.status, got.raw)
	}
	if s := approval(t, h, a, "claude-eu"); s != "pending" {
		t.Fatalf("new model = %s, want pending", s)
	}
	// Not an officer; then the officer who last changed it.
	if got := decideModel(t, h, a, "someone@example.invalid", "claude-eu", "approve"); got.status != http.StatusForbidden {
		t.Errorf("non-officer approval = %d, want 403", got.status)
	}
	if got := decideModel(t, h, a, platform, "claude-eu", "approve"); got.status != http.StatusForbidden {
		t.Errorf("approval by its last editor = %d, want 403", got.status)
	}
	if got := decideModel(t, h, a, dpo, "claude-eu", "approve"); got.status != http.StatusOK || approval(t, h, a, "claude-eu") != "approved" {
		t.Fatalf("approval = %d: %s", got.status, got.raw)
	}
	if got := decideModel(t, h, a, dpo, "claude-eu", "approve"); got.status != http.StatusConflict {
		t.Errorf("approving twice = %d, want 409", got.status)
	}
	// Any change (here, the region) needs approval again.
	if got := h.call(t, a, http.MethodPut, "/v1/models/claude-eu", modelJSON("claude-eu", "us-east-1"), as(platform)...); got.status != http.StatusOK {
		t.Fatalf("change = %d", got.status)
	}
	if s := approval(t, h, a, "claude-eu"); s != "pending" {
		t.Errorf("changed model = %s, want pending", s)
	}
	if got := decideModel(t, h, a, dpo, "claude-eu", "reject"); got.status != http.StatusOK || approval(t, h, a, "claude-eu") != "rejected" {
		t.Errorf("reject = %d", got.status)
	}
	if got := decideModel(t, h, a, dpo, "claude-eu", "revoke"); got.status != http.StatusConflict {
		t.Errorf("revoking a rejected model = %d, want 409", got.status)
	}
	// The contract requires region, terms and a price sheet.
	missing := strings.Replace(modelJSON("x", "eu"), `"termsRef":"legal/anthropic-2026",`, "", 1)
	if got := h.call(t, a, http.MethodPut, "/v1/models/x", missing); got.status != http.StatusUnprocessableEntity {
		t.Errorf("model without terms = %d, want 422", got.status)
	}
	if n := events(t, h, a, "model.approval.decided"); n != 2 {
		t.Errorf("model.approval.decided = %d, want 2", n)
	}
}

func TestAliasesRolloutsAndTheGate(t *testing.T) {
	h, a := modelHarness(t)
	for _, m := range []string{"claude-eu", "gemini-eu"} {
		if got := h.call(t, a, http.MethodPut, "/v1/models/"+m, modelJSON(m, "eu-west-1"), as(platform)...); got.status != http.StatusCreated {
			t.Fatalf("apply %s = %d", m, got.status)
		}
	}
	// An alias needs an approved target.
	if got := h.call(t, a, http.MethodPut, "/v1/model-aliases/reasoning", aliasJSON("reasoning", "claude-eu")); got.status != http.StatusConflict {
		t.Errorf("alias on a pending model = %d, want 409", got.status)
	}
	decideModel(t, h, a, dpo, "claude-eu", "approve")
	if got := h.call(t, a, http.MethodPut, "/v1/model-aliases/reasoning", aliasJSON("reasoning", "claude-eu")); got.status != http.StatusCreated || got.body["compliant"] != true {
		t.Fatalf("alias = %d: %s", got.status, got.raw)
	}

	// The gate: a template on a missing alias cannot be published; on a compliant one it can.
	unbound := strings.Replace(lowTemplate("unbound", "x"), "reasoning-default", "no-such-alias", 1)
	if got := h.call(t, a, http.MethodPut, "/v1/templates/unbound", unbound); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	if got := h.call(t, a, http.MethodPost, "/v1/templates/unbound/versions/1/publication", ""); got.status != http.StatusConflict ||
		!strings.Contains(got.raw, "no-such-alias") {
		t.Errorf("publishing on a missing alias = %d: %s", got.status, got.raw)
	}
	bound := strings.Replace(lowTemplate("analyst", "Support analysts"), "reasoning-default", "reasoning", 1)
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst", bound); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	if got := h.call(t, a, http.MethodPost, "/v1/templates/analyst/versions/1/publication", ""); got.status != http.StatusCreated || got.body["state"] != "published" {
		t.Fatalf("publish = %d: %s", got.status, got.raw)
	}

	// Retargeting is a rollout, never an edit; it needs an approved target and the acknowledgement.
	if got := h.call(t, a, http.MethodPut, "/v1/model-aliases/reasoning", aliasJSON("reasoning", "gemini-eu")); got.status != http.StatusConflict {
		t.Errorf("retargeting by PUT = %d, want 409", got.status)
	}
	start := func(to string, ack bool) response {
		ackJSON := "false"
		if ack {
			ackJSON = "true"
		}
		return h.call(t, a, http.MethodPost, "/v1/model-aliases/reasoning/rollouts",
			`{"to":"`+to+`","reason":"cheaper","acknowledgeUnevaluated":`+ackJSON+`}`)
	}
	if got := start("gemini-eu", true); got.status != http.StatusConflict {
		t.Errorf("rollout to a pending model = %d, want 409", got.status)
	}
	decideModel(t, h, a, dpo, "gemini-eu", "approve")
	if got := start("gemini-eu", false); got.status != http.StatusUnprocessableEntity {
		t.Errorf("rollout without acknowledgement = %d, want 422", got.status)
	}
	r := start("gemini-eu", true)
	if r.status != http.StatusCreated {
		t.Fatalf("rollout = %d: %s", r.status, r.raw)
	}
	eval := r.body["evaluation"].(map[string]any)
	if eval["status"] != "not-run" || !strings.Contains(eval["reason"].(string), "D28") || r.body["from"] != "claude-eu" || r.body["to"] != "gemini-eu" {
		t.Errorf("rollout record = %s", r.raw)
	}
	alias := h.call(t, a, http.MethodGet, "/v1/model-aliases/reasoning", "")
	if alias.body["document"].(map[string]any)["spec"].(map[string]any)["target"] != "gemini-eu" {
		t.Errorf("alias after rollout = %s", alias.raw)
	}

	// Rollback returns to the previous model, once.
	id := r.body["id"].(string)
	back := h.call(t, a, http.MethodPost, "/v1/rollouts/"+id+"/rollback", `{"reason":"quality"}`)
	if back.status != http.StatusOK || back.body["status"] != "rolled-back" {
		t.Fatalf("rollback = %d: %s", back.status, back.raw)
	}
	alias = h.call(t, a, http.MethodGet, "/v1/model-aliases/reasoning", "")
	if alias.body["document"].(map[string]any)["spec"].(map[string]any)["target"] != "claude-eu" {
		t.Errorf("alias after rollback = %s", alias.raw)
	}
	if got := h.call(t, a, http.MethodPost, "/v1/rollouts/"+id+"/rollback", `{"reason":"again"}`); got.status != http.StatusConflict {
		t.Errorf("second rollback = %d, want 409", got.status)
	}
	for action, want := range map[string]int{"rollout.started": 1, "rollout.rolled_back": 1} {
		if n := events(t, h, a, action); n != want {
			t.Errorf("%s = %d, want %d", action, n, want)
		}
	}

	// Revocation: the alias stops being compliant, republishing is refused, and the evidence
	// names what it affects.
	if got := decideModel(t, h, a, dpo, "claude-eu", "revoke"); got.status != http.StatusOK {
		t.Fatalf("revoke = %d", got.status)
	}
	if got := h.call(t, a, http.MethodGet, "/v1/model-aliases/reasoning", ""); got.body["compliant"] != false {
		t.Errorf("alias after revocation: %s", got.raw)
	}
	revoked := testdbAfter(t, h, a, "model.approval.decided")
	if !strings.Contains(revoked, `"nonCompliantAliases": ["reasoning"]`) || !strings.Contains(revoked, `"affectedPublishedTemplates": ["analyst"]`) {
		t.Errorf("revocation evidence = %s", revoked)
	}
	v2 := strings.Replace(bound, "Support analysts", "Support analysts, v2", 1)
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst", v2); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	if got := h.call(t, a, http.MethodPost, "/v1/templates/analyst/versions/2/publication", ""); got.status != http.StatusConflict {
		t.Errorf("publishing on a revoked model = %d, want 409", got.status)
	}
	if got := h.call(t, a, http.MethodGet, "/v1/rollouts", ""); len(got.body["items"].([]any)) != 1 {
		t.Errorf("rollouts = %s", got.raw)
	}
}

func mediumTemplate(name, alias string) string {
	return strings.NewReplacer(`"riskTier":"low"`, `"riskTier":"medium"`, "reasoning-default", alias).Replace(lowTemplate(name, "x"))
}

// The publish-time check: a model revoked while a request awaits approval stops the publication.
func TestRevocationWhileAwaitingApprovalStopsPublication(t *testing.T) {
	h, a := modelHarness(t)
	if err := store.SetCatalogueApprovers(context.Background(), h.db.OwnerURL, a, []string{"dev:cat-1@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	h.call(t, a, http.MethodPut, "/v1/models/claude-eu", modelJSON("claude-eu", "eu-west-1"), as(platform)...)
	decideModel(t, h, a, dpo, "claude-eu", "approve")
	h.call(t, a, http.MethodPut, "/v1/model-aliases/reasoning", aliasJSON("reasoning", "claude-eu"))
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst", mediumTemplate("analyst", "reasoning")); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	req := h.call(t, a, http.MethodPost, "/v1/templates/analyst/versions/1/publication", "")
	if req.status != http.StatusCreated || req.body["state"] != "pending" {
		t.Fatalf("request = %d: %s", req.status, req.raw)
	}
	decideModel(t, h, a, dpo, "claude-eu", "revoke")
	got := h.call(t, a, http.MethodPost, "/v1/catalogue/requests/"+req.body["id"].(string)+"/decision",
		`{"decision":"approve","reason":"ok"}`, as("cat-1@example.invalid")...)
	if got.status != http.StatusConflict {
		t.Errorf("approving after the model was revoked = %d, want 409: %s", got.status, got.raw)
	}
	if cat := h.call(t, a, http.MethodGet, "/v1/catalogue", ""); len(cat.body["items"].([]any)) != 0 {
		t.Errorf("published despite the revoked model: %s", cat.raw)
	}
}

// The request-time check: a version that could never publish leaves no pending request behind.
func TestUnpublishableVersionsLeaveNoPendingRequest(t *testing.T) {
	h, a := modelHarness(t)
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst", mediumTemplate("analyst", "no-such-alias")); got.status != http.StatusCreated {
		t.Fatal(got.raw)
	}
	if got := h.call(t, a, http.MethodPost, "/v1/templates/analyst/versions/1/publication", ""); got.status != http.StatusConflict {
		t.Errorf("request on a missing alias = %d, want 409: %s", got.status, got.raw)
	}
	if got := h.call(t, a, http.MethodGet, "/v1/catalogue/requests", ""); len(got.body["items"].([]any)) != 0 {
		t.Errorf("a pending request was left for a version that can never publish: %s", got.raw)
	}
}

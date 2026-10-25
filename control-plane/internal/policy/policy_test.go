package policy_test

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/goccy/go-yaml"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/policy"
)

var update = flag.Bool("update", false, "rewrite testdata/compiled.cedar")

// docs decodes YAML documents through the contract, as the API does.
func docs(t *testing.T, src string) ([]muistamov1.AgentLink, []muistamov1.ActionPolicy) {
	t.Helper()
	var links []muistamov1.AgentLink
	var policies []muistamov1.ActionPolicy
	for _, part := range strings.Split(src, "\n---\n") {
		var v any
		if err := yaml.Unmarshal([]byte(part), &v); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(v)
		if err := contracts.Validate(body); err != nil {
			t.Fatalf("fixture does not match its contract: %v", err)
		}
		var head struct{ Kind string }
		_ = json.Unmarshal(body, &head)
		switch head.Kind {
		case "AgentLink":
			var l muistamov1.AgentLink
			_ = json.Unmarshal(body, &l)
			links = append(links, l)
		case "ActionPolicy":
			var p muistamov1.ActionPolicy
			_ = json.Unmarshal(body, &p)
			policies = append(policies, p)
		}
	}
	return links, policies
}

func compile(t *testing.T, src string) *policy.Set {
	t.Helper()
	set, err := policy.Compile(docs(t, src))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func examples(t *testing.T) string {
	t.Helper()
	var parts []string
	for _, f := range []string{"agentlink.yaml", "actionpolicy.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "examples", f))
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(b))
	}
	return strings.Join(parts, "\n---\n")
}

func ptr[T any](v T) *T { return &v }

func call(from, to, skill string, classes ...string) muistamov1.PolicyDecisionRequest {
	return muistamov1.PolicyDecisionRequest{Kind: muistamov1.PolicyDecisionRequestKindCall,
		From: &from, To: &to, Skill: &skill, DataClasses: &classes}
}

func action(agent, act string, attrs map[string]bool) muistamov1.PolicyDecisionRequest {
	return muistamov1.PolicyDecisionRequest{Kind: muistamov1.PolicyDecisionRequestKindAction,
		Agent: &agent, Action: &act, Attributes: &attrs}
}

func decide(t *testing.T, set *policy.Set, req muistamov1.PolicyDecisionRequest) muistamov1.PolicyDecision {
	t.Helper()
	d, err := set.Decide(req)
	if err != nil {
		t.Fatal(err)
	}
	if d.Enforced != muistamov1.PolicyDecisionEnforcedFalse || d.Mode != muistamov1.PolicyDecisionModeObserve {
		t.Fatalf("release 1 must never claim enforcement: %+v", d)
	}
	return d
}

func TestRules(t *testing.T) {
	set := compile(t, examples(t))
	const intern, market = "analyst-intern", "market-data-agent"
	internal := map[string]bool{"recipients.allInternal": true}
	external := map[string]bool{"recipients.allInternal": false}

	cases := []struct {
		name      string
		req       muistamov1.PolicyDecisionRequest
		allow     bool
		monitored bool
		matched   string // comma-separated ids, "" for denial by default
	}{
		{"linked call with an allowed skill and classes", call(intern, market, "get-quotes", "public", "internal"), true, false, "link/analyst-intern-to-market-data"},
		{"linked call carrying no data", call(intern, market, "get-company-financials"), true, false, "link/analyst-intern-to-market-data"},
		{"no link means deny", call(intern, "hr-agent", "get-quotes"), false, false, ""},
		{"links are one-way", call(market, intern, "get-quotes"), false, false, ""},
		{"a skill the link does not allow", call(intern, market, "place-order"), false, false, ""},
		{"a data class the link does not allow", call(intern, market, "get-quotes", "public", "confidential"), false, false, ""},
		{"delegation deeper than the link allows", func() muistamov1.PolicyDecisionRequest {
			r := call(intern, market, "get-quotes")
			r.Depth = ptr(2)
			return r
		}(), false, false, ""},
		{"act-for mode other than the link's", func() muistamov1.PolicyDecisionRequest {
			r := call(intern, market, "get-quotes")
			r.ActFor = ptr(muistamov1.PolicyDecisionRequestActForService)
			return r
		}(), false, false, ""},
		{"an allowed action", action(intern, "sharepoint.read", nil), true, false, "action-policy/analyst-intern-actions/rule/1"},
		{"an action no rule allows (default deny)", action(intern, "calendar.write", nil), false, false, ""},
		{"an explicitly denied action", action(intern, "crm.update", nil), false, false, "action-policy/analyst-intern-actions/rule/5"},
		{"monitor allows and flags", action(intern, "email.send", internal), true, true, "action-policy/analyst-intern-actions/rule/3"},
		{"deny overrides allow: external mail", action(intern, "email.send", external), false, false, "action-policy/analyst-intern-actions/rule/4"},
		{"a missing attribute counts against the caller", action(intern, "email.send", nil), false, false, "action-policy/analyst-intern-actions/rule/4"},
		{"an agent with no action policy is denied", action(market, "sharepoint.read", nil), false, false, ""},
		{"an action rule never permits a call", action(intern, "call", nil), false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := decide(t, set, c.req)
			if got := d.Decision == muistamov1.PolicyDecisionDecisionAllow; got != c.allow {
				t.Errorf("decision = %s, want allow=%v (%s)", d.Decision, c.allow, d.Reason)
			}
			if d.WouldBlock == c.allow {
				t.Errorf("wouldBlock = %v for an enforce-mode decision of %s", d.WouldBlock, d.Decision)
			}
			if d.Monitored != c.monitored {
				t.Errorf("monitored = %v, want %v", d.Monitored, c.monitored)
			}
			var ids []string
			for _, r := range d.MatchedRules {
				ids = append(ids, r.Id)
			}
			if got := strings.Join(ids, ","); got != c.matched {
				t.Errorf("matched = %q, want %q", got, c.matched)
			}
			if d.Reason == "" {
				t.Error("no reason given")
			}
		})
	}
}

func TestDenyOverridesAllowRegardlessOfOrder(t *testing.T) {
	for _, rules := range []string{
		"  - {action: crm.update, effect: allow}\n  - {action: crm.update, effect: deny}",
		"  - {action: crm.update, effect: deny}\n  - {action: crm.update, effect: allow}",
	} {
		set := compile(t, "apiVersion: muistamo.dev/v1\nkind: ActionPolicy\nmetadata: {name: p}\nspec:\n  appliesTo: {template: a}\n  default: allow\n  rules:\n"+rules)
		if d := decide(t, set, action("a", "crm.update", nil)); d.Decision != muistamov1.PolicyDecisionDecisionDeny {
			t.Errorf("rules %q: %s, want deny", rules, d.Decision)
		}
		if d := decide(t, set, action("a", "crm.read", nil)); d.Decision != muistamov1.PolicyDecisionDecisionAllow {
			t.Errorf("default allow for an unmentioned action: %s", d.Decision)
		}
	}
}

func TestDefaultAllowNeverCoversCalls(t *testing.T) {
	set := compile(t, "apiVersion: muistamo.dev/v1\nkind: ActionPolicy\nmetadata: {name: p}\nspec:\n  appliesTo: {template: a}\n  default: allow\n  rules:\n  - {action: call, effect: allow}")
	if d := decide(t, set, call("a", "b", "anything")); d.Decision != muistamov1.PolicyDecisionDecisionDeny {
		t.Errorf("an action policy permitted an agent call: %+v", d)
	}
}

func TestMonitorModeReportsButWouldNotBlock(t *testing.T) {
	set := compile(t, strings.Replace(examples(t), "mode: enforce", "mode: monitor", 1))
	d := decide(t, set, action("analyst-intern", "crm.update", nil))
	if d.Decision != muistamov1.PolicyDecisionDecisionDeny || d.WouldBlock || !d.Monitored {
		t.Errorf("monitor mode: decision %s wouldBlock %v monitored %v; want deny, false, true", d.Decision, d.WouldBlock, d.Monitored)
	}
	if d.PolicyMode == nil || *d.PolicyMode != muistamov1.PolicyDecisionPolicyModeMonitor {
		t.Errorf("policyMode = %v, want monitor", d.PolicyMode)
	}
	// Calls are links, which have no monitor mode: still blocked.
	if d := decide(t, set, call("market-data-agent", "analyst-intern", "get-quotes")); !d.WouldBlock {
		t.Errorf("a denied call in a tenant with a monitor-mode policy: wouldBlock false")
	}
}

func TestWhenNeedsEveryAttributeAndUnlessAny(t *testing.T) {
	set := compile(t, `apiVersion: muistamo.dev/v1
kind: ActionPolicy
metadata: {name: p}
spec:
  appliesTo: {template: a}
  rules:
  - {action: files.share, effect: allow, when: [target.internal, file.unclassified]}
  - {action: files.share, effect: deny, unless: [approved.byOwner, target.internal]}`)
	for _, c := range []struct {
		attrs map[string]bool
		allow bool
	}{
		{map[string]bool{"target.internal": true, "file.unclassified": true}, true},
		{map[string]bool{"target.internal": true, "file.unclassified": false}, false},
		{map[string]bool{"target.internal": true}, false},
		{map[string]bool{"file.unclassified": true, "approved.byOwner": true}, false}, // no allow: target not internal
		{map[string]bool{}, false},
	} {
		d := decide(t, set, action("a", "files.share", c.attrs))
		if got := d.Decision == muistamov1.PolicyDecisionDecisionAllow; got != c.allow {
			t.Errorf("attrs %v: %s (%s), want allow=%v", c.attrs, d.Decision, d.Reason, c.allow)
		}
	}
}

func TestEmptySetDeniesEverything(t *testing.T) {
	set, err := policy.Compile(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []muistamov1.PolicyDecisionRequest{call("a", "b", "s"), action("a", "x.y", nil)} {
		if d := decide(t, set, req); d.Decision != muistamov1.PolicyDecisionDecisionDeny || !d.WouldBlock || len(d.MatchedRules) != 0 {
			t.Errorf("empty set: %+v", d)
		}
	}
	if set.Cedar() != "" {
		t.Errorf("empty set compiles to %q", set.Cedar())
	}
}

func TestOnePolicyPerTemplate(t *testing.T) {
	p := "apiVersion: muistamo.dev/v1\nkind: ActionPolicy\nmetadata: {name: NAME}\nspec:\n  appliesTo: {template: a}\n  rules: []"
	_, err := policy.Compile(docs(t, strings.Replace(p, "NAME", "one", 1)+"\n---\n"+strings.Replace(p, "NAME", "two", 1)))
	if !errors.Is(err, policy.ErrInvalid) {
		t.Errorf("two policies for one template: err = %v, want ErrInvalid", err)
	}
}

func TestRequireApprovalIsRefused(t *testing.T) {
	doc := `{"apiVersion":"muistamo.dev/v1","kind":"ActionPolicy","metadata":{"name":"p"},
	  "spec":{"appliesTo":{"template":"a"},"rules":[{"action":"email.send","effect":"requireApproval"}]}}`
	if err := contracts.Validate([]byte(doc)); err == nil {
		t.Error("the contract accepted requireApproval")
	}
	var p muistamov1.ActionPolicy
	_ = json.Unmarshal([]byte(doc), &p)
	if _, err := policy.Compile(nil, []muistamov1.ActionPolicy{p}); !errors.Is(err, policy.ErrInvalid) {
		t.Errorf("the compiler accepted requireApproval: %v", err)
	}
}

func TestNamesCannotInjectCedar(t *testing.T) {
	// The contract forbids these characters; the compiler must be safe even without it.
	var p muistamov1.ActionPolicy
	_ = json.Unmarshal([]byte(`{"metadata":{"name":"p"},"spec":{"appliesTo":{"template":"a"},
	  "rules":[{"action":"x\") || true; permit(principal, action, resource);//","effect":"deny"}]}}`), &p)
	set, err := policy.Compile(nil, []muistamov1.ActionPolicy{p})
	if err != nil {
		t.Fatal(err)
	}
	if d := decide(t, set, action("a", "anything.else", nil)); d.Decision != muistamov1.PolicyDecisionDecisionDeny {
		t.Errorf("an injected permit took effect: %+v", d)
	}
	if n := len(set.Rules()); n != 1 {
		t.Errorf("rules = %d, want 1", n)
	}
}

func TestDecideRejectsIncompleteRequests(t *testing.T) {
	set, _ := policy.Compile(nil, nil)
	for _, req := range []muistamov1.PolicyDecisionRequest{
		{Kind: muistamov1.PolicyDecisionRequestKindCall, From: ptr("a")},
		{Kind: muistamov1.PolicyDecisionRequestKindAction, Agent: ptr("a")},
		{Kind: "other"},
	} {
		if _, err := set.Decide(req); !errors.Is(err, policy.ErrInvalid) {
			t.Errorf("%+v: err = %v, want ErrInvalid", req, err)
		}
	}
}

// The compiled text is what reviewers read; a change to it must be deliberate.
func TestCedarSnapshot(t *testing.T) {
	got := compile(t, examples(t)).Cedar() + "\n"
	if _, err := cedar.NewPolicySetFromBytes("compiled.cedar", []byte(got)); err != nil {
		t.Fatalf("the compiled text is not valid Cedar: %v", err)
	}
	path := filepath.Join("testdata", "compiled.cedar")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./control-plane/internal/policy -update)", err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("compiled Cedar changed; if intended, rerun with -update.\ngot:\n%s", got)
	}
}

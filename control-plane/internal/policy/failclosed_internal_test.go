package policy

import (
	"strings"
	"testing"

	"github.com/cedar-policy/cedar-go"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// Cedar skips a policy whose condition fails to evaluate. For a forbid that would turn a denial
// into an allow, so Decide must deny whenever Cedar reports any evaluation error.
func TestEvaluationErrorsFailClosed(t *testing.T) {
	set, err := Compile(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var permitAll, brokenForbid cedar.Policy
	if err := permitAll.UnmarshalCedar([]byte(`permit (principal, action, resource);`)); err != nil {
		t.Fatal(err)
	}
	if err := brokenForbid.UnmarshalCedar([]byte(`forbid (principal, action, resource) when { context.noSuchAttribute == 1 };`)); err != nil {
		t.Fatal(err)
	}
	set.cedar.Add("permit-all", &permitAll)
	set.cedar.Add("broken-forbid", &brokenForbid)
	set.refs["permit-all"] = muistamov1.PolicyRuleRef{Id: "permit-all", Effect: muistamov1.PolicyRuleRefEffectAllow}
	set.refs["broken-forbid"] = muistamov1.PolicyRuleRef{Id: "broken-forbid", Effect: muistamov1.PolicyRuleRefEffectDeny}

	// Cedar on its own allows this request: the forbid errors and is skipped.
	agent, action := "a", "x.y"
	req := muistamov1.PolicyDecisionRequest{Kind: muistamov1.PolicyDecisionRequestKindAction, Agent: &agent, Action: &action}
	d, err := set.Decide(req)
	if err != nil {
		t.Fatal(err)
	}
	if d.Decision != muistamov1.PolicyDecisionDecisionDeny || !d.WouldBlock || !strings.Contains(d.Reason, "fail closed") {
		t.Errorf("an erroring forbid let the request through: %+v", d)
	}
}

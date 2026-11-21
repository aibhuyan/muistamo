package registry_test

// HUMAN REVIEW REQUIRED (AGENTS.md): who may read agent links and action policies through the
// console (docs/console-management-plan.md, slice 4; D70).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	muistamov1 "muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

func TestConsoleCallersNeedTheAdministratorRoleToReadPolicies(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var link muistamov1.AgentLink
	var policy muistamov1.ActionPolicy
	if err := json.Unmarshal([]byte(`{"apiVersion":"muistamo.dev/v1","kind":"AgentLink","metadata":{"name":"intern-to-market"},
		"spec":{"from":{"template":"analyst-intern"},"to":{"template":"market-data-agent"},"allowedSkills":["get-quotes"],"dataClasses":["public"]}}`), &link); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"apiVersion":"muistamo.dev/v1","kind":"ActionPolicy","metadata":{"name":"intern-actions"},
		"spec":{"appliesTo":{"template":"analyst-intern"},"rules":[{"action":"email.send","effect":"allow"}]}}`), &policy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyLink(ctx, f.actor, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyActionPolicy(ctx, f.actor, policy); err != nil {
		t.Fatal(err)
	}
	const admin, auditor, nobody = "entra:aaaaaaaa-0000-4000-8000-000000000011", "entra:aaaaaaaa-0000-4000-8000-000000000012", "entra:aaaaaaaa-0000-4000-8000-000000000013"
	setRole(t, f, f.actor.Tenant, "administrator", admin)
	setRole(t, f, f.actor.Tenant, "auditor", auditor)

	reads := func(a registry.Actor) map[string]error {
		links, linksErr := f.svc.ListLinks(ctx, a)
		policies, policiesErr := f.svc.ListActionPolicies(ctx, a)
		_, linkErr := f.svc.GetLink(ctx, a, "intern-to-market")
		_, policyErr := f.svc.GetActionPolicy(ctx, a, "intern-actions")
		// An unknown name: refused, not missing, for a caller without the role.
		_, missingLinkErr := f.svc.GetLink(ctx, a, "no-such-link")
		_, missingPolicyErr := f.svc.GetActionPolicy(ctx, a, "no-such-policy")
		if linksErr == nil && len(links) != 1 {
			t.Errorf("links = %d, want 1", len(links))
		}
		if policiesErr == nil && len(policies) != 1 {
			t.Errorf("policies = %d, want 1", len(policies))
		}
		return map[string]error{"list links": linksErr, "list policies": policiesErr, "link": linkErr, "policy": policyErr,
			"missing link": missingLinkErr, "missing policy": missingPolicyErr}
	}
	for who, want := range map[string]error{auditor: registry.ErrForbidden, nobody: registry.ErrForbidden} {
		for name, err := range reads(throughConsole(f.actor, who)) {
			if !errors.Is(err, want) {
				t.Errorf("%s %s = %v, want %v", who, name, err, want)
			}
		}
	}
	for _, a := range []registry.Actor{throughConsole(f.actor, admin), f.actor} {
		for name, err := range reads(a) {
			wantMissing := name == "missing link" || name == "missing policy"
			if (wantMissing && !errors.Is(err, registry.ErrNotFound)) || (!wantMissing && err != nil) {
				t.Errorf("%s %s = %v", a.Name, name, err)
			}
		}
	}

	// Deciding is not a console read and needs no console role from a development caller.
	got, err := f.svc.Decide(ctx, f.actor, muistamov1.PolicyDecisionRequest{Kind: "action",
		Agent: new("analyst-intern"), Action: new("email.send")})
	if err != nil || got.Decision != "allow" {
		t.Errorf("development decision = %+v, %v", got, err)
	}
}

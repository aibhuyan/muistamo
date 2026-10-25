// Package policy compiles agent links and action policies to Cedar and decides requests against
// them (PRD section 8.1, FR-1003 to FR-1006).
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): this is the gateway's policy path. Every rule here decides
// whether an agent may call another agent or act with a tool.
//
// The rules, each pinned by a test:
//   - Deny by default: a request no policy permits is denied.
//   - Links are one-way: a link from A to B permits calls from A to B only.
//   - Deny overrides allow: Cedar denies whenever any forbid matches, so rule order never matters.
//   - Calls and tool actions cannot be confused: link permits name a Template resource, action
//     rules a Tool resource, so no action rule (or default: allow) can permit an agent call.
//   - Missing request attributes count against the caller: they stop allow and monitor rules
//     applying and let deny rules apply.
//   - Fail closed: if Cedar reports an evaluation error for any policy, the request is denied.
//
// Policies are built with cedar-go's AST, never by formatting Cedar text, so no name or attribute
// in a document can change a policy's structure.
package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/types"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// ErrInvalid means the documents do not form a valid policy set, or the request is malformed.
var ErrInvalid = errors.New("invalid policy")

const (
	templateType types.EntityType = "Muistamo::Template"
	toolType     types.EntityType = "Muistamo::Tool"
	actionType   types.EntityType = "Muistamo::Action"
	callAction   types.String     = "call"
)

// Set is a compiled policy set.
type Set struct {
	cedar *cedar.PolicySet
	refs  map[cedar.PolicyID]muistamov1.PolicyRuleRef
	// modes and policies are keyed by template: at most one ActionPolicy applies to each.
	modes    map[string]muistamov1.ActionPolicySpecMode
	policies map[string]string
	links    map[[2]string][]string // (from, to) -> link names, for explanations only
}

// Compile turns links and action policies into one Cedar policy set.
func Compile(links []muistamov1.AgentLink, policies []muistamov1.ActionPolicy) (*Set, error) {
	s := &Set{
		cedar:    cedar.NewPolicySet(),
		refs:     map[cedar.PolicyID]muistamov1.PolicyRuleRef{},
		modes:    map[string]muistamov1.ActionPolicySpecMode{},
		policies: map[string]string{},
		links:    map[[2]string][]string{},
	}
	for _, link := range links {
		if err := s.addLink(link); err != nil {
			return nil, err
		}
	}
	for _, p := range policies {
		if err := s.addActionPolicy(p); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Set) add(id string, p *ast.Policy, ref muistamov1.PolicyRuleRef) error {
	pid := cedar.PolicyID(id)
	if s.cedar.Get(pid) != nil {
		return fmt.Errorf("two rules compile to policy id %q: %w", id, ErrInvalid)
	}
	ref.Id = id
	s.cedar.Add(pid, cedar.NewPolicyFromAST(p.Annotate("id", types.String(id))))
	s.refs[pid] = ref
	return nil
}

// addLink: permit (principal == from, action == call, resource == to) when the skill is allowed,
// every data class carried is allowed, the delegation depth is within the limit and the act-for
// mode matches.
func (s *Set) addLink(link muistamov1.AgentLink) error {
	spec := link.Spec
	if len(spec.AllowedSkills) == 0 {
		return fmt.Errorf("link %q allows no skills: %w", link.Metadata.Name, ErrInvalid)
	}
	depth := 1
	if spec.MaxDelegationDepth != nil {
		depth = *spec.MaxDelegationDepth
	}
	if depth < 1 {
		return fmt.Errorf("link %q: maxDelegationDepth must be at least 1: %w", link.Metadata.Name, ErrInvalid)
	}
	actFor := string(muistamov1.AgentLinkSpecActForSameUser)
	if spec.ActFor != nil {
		actFor = string(*spec.ActFor)
	}
	ctx := ast.Context()
	cond := setOf(spec.AllowedSkills).Contains(ctx.Access("skill")).
		And(setOf(spec.DataClasses).ContainsAll(ctx.Access("dataClasses"))).
		And(ctx.Access("depth").LessThanOrEqual(ast.Long(depth))).
		And(ctx.Access("actFor").Equal(ast.String(actFor)))
	p := ast.Permit().
		PrincipalEq(templateUID(spec.From.Template)).
		ActionEq(types.NewEntityUID(actionType, callAction)).
		ResourceEq(templateUID(spec.To.Template)).
		When(cond)
	key := [2]string{spec.From.Template, spec.To.Template}
	s.links[key] = append(s.links[key], link.Metadata.Name)
	return s.add("link/"+link.Metadata.Name, p, muistamov1.PolicyRuleRef{
		Kind: muistamov1.PolicyRuleRefKindAgentLink, Name: link.Metadata.Name, Effect: muistamov1.PolicyRuleRefEffectAllow,
	})
}

func (s *Set) addActionPolicy(p muistamov1.ActionPolicy) error {
	name, template := p.Metadata.Name, p.Spec.AppliesTo.Template
	if other, ok := s.policies[template]; ok {
		return fmt.Errorf("action policies %q and %q both apply to template %q; at most one may: %w", other, name, template, ErrInvalid)
	}
	s.policies[template] = name
	s.modes[template] = muistamov1.ActionPolicySpecModeEnforce
	if p.Spec.Mode != nil {
		if !p.Spec.Mode.Valid() {
			return fmt.Errorf("action policy %q: unknown mode %q: %w", name, *p.Spec.Mode, ErrInvalid)
		}
		s.modes[template] = *p.Spec.Mode
	}
	principal := templateUID(template)
	prefix := "action-policy/" + name

	if p.Spec.Default != nil {
		switch *p.Spec.Default {
		case muistamov1.ActionPolicySpecDefaultAllow:
			// Every tool action of this template; forbids still override it. Never calls: the
			// resource must be a Tool.
			rule := ast.Permit().PrincipalEq(principal).ResourceIs(toolType)
			if err := s.add(prefix+"/default", rule, muistamov1.PolicyRuleRef{
				Kind: muistamov1.PolicyRuleRefKindActionPolicy, Name: name, Effect: muistamov1.PolicyRuleRefEffectAllow,
			}); err != nil {
				return err
			}
		case muistamov1.ActionPolicySpecDefaultDeny:
			// Nothing to add: Cedar denies whatever no permit allows.
		default:
			return fmt.Errorf("action policy %q: unknown default %q: %w", name, *p.Spec.Default, ErrInvalid)
		}
	}

	for i, rule := range p.Spec.Rules {
		var when, unless []string
		if rule.When != nil {
			when = *rule.When
		}
		if rule.Unless != nil {
			unless = *rule.Unless
		}
		var policy *ast.Policy
		var effect muistamov1.PolicyRuleRefEffect
		switch rule.Effect {
		case muistamov1.ActionPolicySpecRulesEffectAllow, muistamov1.ActionPolicySpecRulesEffectMonitor:
			effect = muistamov1.PolicyRuleRefEffect(rule.Effect)
			policy = ast.Permit()
			if len(when) > 0 {
				policy = policy.When(all(when, proven))
			}
			if len(unless) > 0 {
				policy = policy.Unless(anyOf(unless, notDisproven))
			}
		case muistamov1.ActionPolicySpecRulesEffectDeny:
			effect = muistamov1.PolicyRuleRefEffectDeny
			policy = ast.Forbid()
			if len(when) > 0 {
				policy = policy.When(all(when, notDisproven))
			}
			if len(unless) > 0 {
				policy = policy.Unless(anyOf(unless, proven))
			}
		default:
			// requireApproval is release 2; the contract refuses it, and so does the compiler.
			return fmt.Errorf("action policy %q rule %d: effect %q is not supported in release 1: %w", name, i+1, rule.Effect, ErrInvalid)
		}
		policy = policy.PrincipalEq(principal).
			ActionEq(types.NewEntityUID(actionType, types.String(rule.Action))).
			ResourceIs(toolType)
		n := i + 1
		if err := s.add(prefix+"/rule/"+strconv.Itoa(n), policy, muistamov1.PolicyRuleRef{
			Kind: muistamov1.PolicyRuleRefKindActionPolicy, Name: name, Rule: &n, Effect: effect,
		}); err != nil {
			return err
		}
	}
	return nil
}

// proven: the request supplies the attribute and it is true.
func proven(attr string) ast.Node {
	attrs := ast.Context().Access("attributes")
	return attrs.Has(types.String(attr)).And(attrs.Access(types.String(attr)).Equal(ast.True()))
}

// notDisproven: the request does not supply the attribute, or it is true.
func notDisproven(attr string) ast.Node {
	attrs := ast.Context().Access("attributes")
	return ast.Not(attrs.Has(types.String(attr))).Or(attrs.Access(types.String(attr)).Equal(ast.True()))
}

func all(attrs []string, f func(string) ast.Node) ast.Node {
	node := f(attrs[0])
	for _, a := range attrs[1:] {
		node = node.And(f(a))
	}
	return node
}

func anyOf(attrs []string, f func(string) ast.Node) ast.Node {
	node := f(attrs[0])
	for _, a := range attrs[1:] {
		node = node.Or(f(a))
	}
	return node
}

func setOf(values []string) ast.Node {
	nodes := make([]ast.Node, len(values))
	for i, v := range values {
		nodes[i] = ast.String(v)
	}
	return ast.Set(nodes...)
}

func templateUID(name string) types.EntityUID {
	return types.NewEntityUID(templateType, types.String(name))
}

// Cedar returns the policy set as Cedar text, ordered by policy id.
func (s *Set) Cedar() string { return string(s.cedar.MarshalCedar()) }

// Rules returns every compiled rule, ordered by policy id.
func (s *Set) Rules() []muistamov1.PolicyRuleRef {
	out := make([]muistamov1.PolicyRuleRef, 0, len(s.refs))
	for _, ref := range s.refs {
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b muistamov1.PolicyRuleRef) int { return strings.Compare(a.Id, b.Id) })
	return out
}

// Decide answers a request. Release 1 is observe mode: the answer is never enforced.
func (s *Set) Decide(req muistamov1.PolicyDecisionRequest) (muistamov1.PolicyDecision, error) {
	out := muistamov1.PolicyDecision{
		Mode:         muistamov1.PolicyDecisionModeObserve,
		Enforced:     muistamov1.PolicyDecisionEnforcedFalse,
		MatchedRules: []muistamov1.PolicyRuleRef{},
	}
	var creq cedar.Request
	var policyMode muistamov1.ActionPolicySpecMode
	switch req.Kind {
	case muistamov1.PolicyDecisionRequestKindCall:
		from, to, skill := deref(req.From), deref(req.To), deref(req.Skill)
		if from == "" || to == "" || skill == "" {
			return out, fmt.Errorf("a call needs from, to and skill: %w", ErrInvalid)
		}
		depth := 1
		if req.Depth != nil {
			depth = *req.Depth
		}
		actFor := string(muistamov1.PolicyDecisionRequestActForSameUser)
		if req.ActFor != nil {
			actFor = string(*req.ActFor)
		}
		var classes []types.Value
		if req.DataClasses != nil {
			for _, c := range *req.DataClasses {
				classes = append(classes, types.String(c))
			}
		}
		creq = cedar.Request{
			Principal: templateUID(from),
			Action:    types.NewEntityUID(actionType, callAction),
			Resource:  templateUID(to),
			Context: types.NewRecord(types.RecordMap{
				"skill":       types.String(skill),
				"dataClasses": types.NewSet(classes...),
				"depth":       types.Long(depth),
				"actFor":      types.String(actFor),
			}),
		}
		out.Checked = []string{"link", "skill", "dataClasses", "delegationDepth", "actFor"}
		out.NotEvaluated = []string{"rateLimit", "callerScope", "humanAccess"}
	case muistamov1.PolicyDecisionRequestKindAction:
		agent, action := deref(req.Agent), deref(req.Action)
		if agent == "" || action == "" {
			return out, fmt.Errorf("an action needs agent and action: %w", ErrInvalid)
		}
		attrs := types.RecordMap{}
		if req.Attributes != nil {
			for k, v := range *req.Attributes {
				attrs[types.String(k)] = types.Boolean(v)
			}
		}
		creq = cedar.Request{
			Principal: templateUID(agent),
			Action:    types.NewEntityUID(actionType, types.String(action)),
			Resource:  types.NewEntityUID(toolType, types.String(action)),
			Context:   types.NewRecord(types.RecordMap{"attributes": types.NewRecord(attrs)}),
		}
		if mode, ok := s.modes[agent]; ok {
			policyMode = mode
			m := muistamov1.PolicyDecisionPolicyMode(mode)
			out.PolicyMode = &m
		}
		out.Checked = []string{"actionPolicy"}
		out.NotEvaluated = []string{"humanAccess"}
	default:
		return out, fmt.Errorf("unknown request kind %q: %w", req.Kind, ErrInvalid)
	}

	decision, diag := cedar.Authorize(s.cedar, types.EntityMap{}, creq)
	switch {
	case len(diag.Errors) > 0:
		// A forbid that fails to evaluate is skipped by Cedar; never let that become an allow.
		out.Decision = muistamov1.PolicyDecisionDecisionDeny
		msgs := make([]string, len(diag.Errors))
		for i, e := range diag.Errors {
			msgs[i] = e.String()
		}
		out.Reason = "denied because a rule could not be evaluated (fail closed): " + strings.Join(msgs, "; ")
	case decision == cedar.Allow:
		out.Decision = muistamov1.PolicyDecisionDecisionAllow
	default:
		out.Decision = muistamov1.PolicyDecisionDecisionDeny
	}
	if len(diag.Errors) == 0 {
		for _, r := range diag.Reasons {
			ref, ok := s.refs[r.PolicyID]
			if !ok {
				return out, fmt.Errorf("cedar matched unknown policy %q", r.PolicyID)
			}
			out.MatchedRules = append(out.MatchedRules, ref)
		}
		slices.SortFunc(out.MatchedRules, func(a, b muistamov1.PolicyRuleRef) int { return strings.Compare(a.Id, b.Id) })
	}

	deny := out.Decision == muistamov1.PolicyDecisionDecisionDeny
	monitorMode := policyMode == muistamov1.ActionPolicySpecModeMonitor
	out.WouldBlock = deny && !monitorMode
	out.Monitored = deny && monitorMode
	for _, ref := range out.MatchedRules {
		if !deny && ref.Effect == muistamov1.PolicyRuleRefEffectMonitor {
			out.Monitored = true
		}
	}
	if out.Reason == "" {
		out.Reason = s.explain(req, out)
	}
	return out, nil
}

func (s *Set) explain(req muistamov1.PolicyDecisionRequest, d muistamov1.PolicyDecision) string {
	ids := make([]string, len(d.MatchedRules))
	for i, r := range d.MatchedRules {
		ids[i] = r.Id
	}
	matched := strings.Join(ids, ", ")
	var text string
	switch {
	case d.Decision == muistamov1.PolicyDecisionDecisionAllow && d.Monitored:
		text = "allowed and flagged for review by " + matched
	case d.Decision == muistamov1.PolicyDecisionDecisionAllow:
		text = "allowed by " + matched
	case len(d.MatchedRules) > 0:
		text = "denied by " + matched + " (deny overrides allow)"
	case req.Kind == muistamov1.PolicyDecisionRequestKindCall:
		from, to := deref(req.From), deref(req.To)
		if names := s.links[[2]string{from, to}]; len(names) > 0 {
			text = fmt.Sprintf("denied: link %s does not allow this call (skill, data classes, delegation depth or act-for mode)",
				strings.Join(names, ", "))
		} else {
			text = fmt.Sprintf("denied by default: no link lets %s call %s", from, to)
		}
	default:
		agent := deref(req.Agent)
		if name, ok := s.policies[agent]; ok {
			text = fmt.Sprintf("denied by default: no rule in action policy %s allows %s", name, deref(req.Action))
		} else {
			text = fmt.Sprintf("denied by default: no action policy applies to %s", agent)
		}
	}
	if d.Monitored && d.Decision == muistamov1.PolicyDecisionDecisionDeny {
		text += "; the policy is in monitor mode, so this would be reported, not blocked"
	}
	return text
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Package policy compiles agent links and action policies to Cedar and decides requests against
// them (PRD section 8.1, FR-1003 to FR-1006).
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): this is the gateway's policy path. Every rule here decides
// whether an agent may call another agent or act with a tool.
//
// The rules, each pinned by a test:
//   - Deny by default: a request no policy permits is denied.
//   - Links are one-way: a link from A to B permits calls from A to B only.
//   - Clones: a clone is a child entity of its template, so template links and rules cover it
//     (principal in template); clone links and rules name it alone (principal == clone). A
//     clone's own policy only narrows: deny rules, and monitor rules that flag an allowed action
//     but sit outside the decision set, so they can never allow. A request naming a clone must
//     name its real template, or a caller could borrow another clone's links.
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
	cloneType    types.EntityType = "Muistamo::Clone"
	toolType     types.EntityType = "Muistamo::Tool"
	actionType   types.EntityType = "Muistamo::Action"
	callAction   types.String     = "call"
)

// Set is a compiled policy set.
type Set struct {
	cedar *cedar.PolicySet
	// flags holds clone policies' monitor rules. It is consulted only after cedar allows, to
	// flag the action; it can never allow anything (a clone policy only narrows).
	flags    *cedar.PolicySet
	refs     map[cedar.PolicyID]muistamov1.PolicyRuleRef
	entities types.EntityMap
	clones   map[string]string // clone -> its template
	// modes is keyed by template: a clone runs under its template policy's mode.
	modes map[string]muistamov1.ActionPolicySpecMode
	// policies is keyed by target ("template:x" or "clone:y"): at most one policy per target.
	policies map[string]string
	links    map[[2]string][]string // (from target, to target) -> link names, for explanations only
}

// Compile turns links and action policies into one Cedar policy set. clones maps each clone to
// its template; clone entities are children of their template, so template rules cover them.
func Compile(links []muistamov1.AgentLink, policies []muistamov1.ActionPolicy, clones map[string]string) (*Set, error) {
	s := &Set{
		cedar:    cedar.NewPolicySet(),
		flags:    cedar.NewPolicySet(),
		refs:     map[cedar.PolicyID]muistamov1.PolicyRuleRef{},
		entities: types.EntityMap{},
		clones:   map[string]string{},
		modes:    map[string]muistamov1.ActionPolicySpecMode{},
		policies: map[string]string{},
		links:    map[[2]string][]string{},
	}
	for clone, template := range clones {
		s.clones[clone] = template
		uid := cloneUID(clone)
		s.entities[uid] = types.Entity{UID: uid, Parents: types.NewEntityUIDSet(templateUID(template))}
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

func (s *Set) add(set *cedar.PolicySet, id string, p *ast.Policy, ref muistamov1.PolicyRuleRef) error {
	pid := cedar.PolicyID(id)
	if _, taken := s.refs[pid]; taken {
		return fmt.Errorf("two rules compile to policy id %q: %w", id, ErrInvalid)
	}
	ref.Id = id
	set.Add(pid, cedar.NewPolicyFromAST(p.Annotate("id", types.String(id))))
	s.refs[pid] = ref
	return nil
}

// target is one end of a link, or what a policy applies to: exactly one template or clone.
type target struct {
	uid      types.EntityUID
	template bool
	key      string // "template:x" or "clone:y"
}

func targetOf(template, clone *string, what string) (target, error) {
	switch {
	case template != nil && *template != "" && clone == nil:
		return target{uid: templateUID(*template), template: true, key: "template:" + *template}, nil
	case clone != nil && *clone != "" && template == nil:
		return target{uid: cloneUID(*clone), key: "clone:" + *clone}, nil
	}
	return target{}, fmt.Errorf("%s must name exactly one template or clone: %w", what, ErrInvalid)
}

// principal scopes a policy to a target: a template covers itself and its clones (in), a clone
// only itself (==).
func (t target) principal(p *ast.Policy) *ast.Policy {
	if t.template {
		return p.PrincipalIn(t.uid)
	}
	return p.PrincipalEq(t.uid)
}

func (t target) resource(p *ast.Policy) *ast.Policy {
	if t.template {
		return p.ResourceIn(t.uid)
	}
	return p.ResourceEq(t.uid)
}

// addLink: permit (principal in/== from, action == call, resource in/== to) when the skill is
// allowed, every data class carried is allowed, the delegation depth is within the limit and the
// act-for mode matches.
func (s *Set) addLink(link muistamov1.AgentLink) error {
	spec := link.Spec
	name := link.Metadata.Name
	if len(spec.AllowedSkills) == 0 {
		return fmt.Errorf("link %q allows no skills: %w", name, ErrInvalid)
	}
	from, err := targetOf(spec.From.Template, spec.From.Clone, "link "+name+" from")
	if err != nil {
		return err
	}
	to, err := targetOf(spec.To.Template, spec.To.Clone, "link "+name+" to")
	if err != nil {
		return err
	}
	depth := 1
	if spec.MaxDelegationDepth != nil {
		depth = *spec.MaxDelegationDepth
	}
	if depth < 1 {
		return fmt.Errorf("link %q: maxDelegationDepth must be at least 1: %w", name, ErrInvalid)
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
	p := to.resource(from.principal(ast.Permit()).ActionEq(types.NewEntityUID(actionType, callAction))).When(cond)
	key := [2]string{from.key, to.key}
	s.links[key] = append(s.links[key], name)
	return s.add(s.cedar, "link/"+name, p, muistamov1.PolicyRuleRef{
		Kind: muistamov1.PolicyRuleRefKindAgentLink, Name: name, Effect: muistamov1.PolicyRuleRefEffectAllow,
		Target: ptr(from.key + " -> " + to.key),
	})
}

func (s *Set) addActionPolicy(p muistamov1.ActionPolicy) error {
	name := p.Metadata.Name
	t, err := targetOf(p.Spec.AppliesTo.Template, p.Spec.AppliesTo.Clone, "action policy "+name)
	if err != nil {
		return err
	}
	if other, ok := s.policies[t.key]; ok {
		return fmt.Errorf("action policies %q and %q both apply to %s; at most one may: %w", other, name, t.key, ErrInvalid)
	}
	s.policies[t.key] = name
	prefix := "action-policy/" + name

	if t.template {
		template := *p.Spec.AppliesTo.Template
		s.modes[template] = muistamov1.ActionPolicySpecModeEnforce
		if p.Spec.Mode != nil {
			if !p.Spec.Mode.Valid() {
				return fmt.Errorf("action policy %q: unknown mode %q: %w", name, *p.Spec.Mode, ErrInvalid)
			}
			s.modes[template] = *p.Spec.Mode
		}
	} else if p.Spec.Default != nil || p.Spec.Mode != nil {
		// A clone's policy only narrows its template's: it has no default and no mode of its own.
		return fmt.Errorf("action policy %q applies to a clone, so it cannot set default or mode: %w", name, ErrInvalid)
	}

	if p.Spec.Default != nil {
		switch *p.Spec.Default {
		case muistamov1.ActionPolicySpecDefaultAllow:
			// Every tool action of this template and its clones; forbids still override it. Never
			// calls: the resource must be a Tool.
			rule := t.principal(ast.Permit()).ResourceIs(toolType)
			if err := s.add(s.cedar, prefix+"/default", rule, muistamov1.PolicyRuleRef{
				Kind: muistamov1.PolicyRuleRefKindActionPolicy, Name: name, Effect: muistamov1.PolicyRuleRefEffectAllow, Target: &t.key,
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
		set := s.cedar
		switch {
		case rule.Effect == muistamov1.ActionPolicySpecRulesEffectAllow && !t.template:
			return fmt.Errorf("action policy %q rule %d: a clone's policy may only deny or monitor, never allow: %w", name, i+1, ErrInvalid)
		case rule.Effect == muistamov1.ActionPolicySpecRulesEffectAllow, rule.Effect == muistamov1.ActionPolicySpecRulesEffectMonitor:
			effect = muistamov1.PolicyRuleRefEffect(rule.Effect)
			policy = ast.Permit()
			if len(when) > 0 {
				policy = policy.When(all(when, proven))
			}
			if len(unless) > 0 {
				policy = policy.Unless(anyOf(unless, notDisproven))
			}
			if !t.template {
				// A clone's monitor rule flags what its template already allows; it never grants.
				set = s.flags
			}
		case rule.Effect == muistamov1.ActionPolicySpecRulesEffectDeny:
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
		policy = t.principal(policy).
			ActionEq(types.NewEntityUID(actionType, types.String(rule.Action))).
			ResourceIs(toolType)
		n := i + 1
		if err := s.add(set, prefix+"/rule/"+strconv.Itoa(n), policy, muistamov1.PolicyRuleRef{
			Kind: muistamov1.PolicyRuleRefKindActionPolicy, Name: name, Rule: &n, Effect: effect, Target: &t.key,
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

func cloneUID(name string) types.EntityUID {
	return types.NewEntityUID(cloneType, types.String(name))
}

// Cedar returns the policy set as Cedar text, ordered by policy id: the decision set, then the
// clone monitor rules that only flag.
func (s *Set) Cedar() string {
	text := string(s.cedar.MarshalCedar())
	if flags := string(s.flags.MarshalCedar()); flags != "" {
		text += "\n\n// Clone monitor rules: evaluated only after an allow, to flag it. They never allow.\n" + flags
	}
	return text
}

// Rules returns every compiled rule, ordered by policy id.
func (s *Set) Rules() []muistamov1.PolicyRuleRef {
	out := make([]muistamov1.PolicyRuleRef, 0, len(s.refs))
	for _, ref := range s.refs {
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b muistamov1.PolicyRuleRef) int { return strings.Compare(a.Id, b.Id) })
	return out
}

// agentUID is the entity a request names: the clone when one is given, which must be a clone of
// the given template, else the template. A request naming only the template is judged as the
// template, so a clone's narrowing rules do not apply to it. Requests are self-asserted only while
// decisions are observe-only; whatever enforces them (the gateway, D28) must take the clone from
// the calling instance's cloneRef, never from the caller.
func (s *Set) agentUID(template string, clone *string, what string) (types.EntityUID, error) {
	if clone == nil {
		return templateUID(template), nil
	}
	if s.clones[*clone] != template {
		return types.EntityUID{}, fmt.Errorf("%s clone %q is not a clone of %s: %w", what, *clone, template, ErrInvalid)
	}
	return cloneUID(*clone), nil
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
		principal, err := s.agentUID(from, req.FromClone, "the caller's")
		if err != nil {
			return out, err
		}
		resource, err := s.agentUID(to, req.ToClone, "the callee's")
		if err != nil {
			return out, err
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
			Principal: principal,
			Action:    types.NewEntityUID(actionType, callAction),
			Resource:  resource,
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
		principal, err := s.agentUID(agent, req.AgentClone, "the agent's")
		if err != nil {
			return out, err
		}
		attrs := types.RecordMap{}
		if req.Attributes != nil {
			for k, v := range *req.Attributes {
				attrs[types.String(k)] = types.Boolean(v)
			}
		}
		creq = cedar.Request{
			Principal: principal,
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

	decision, diag := cedar.Authorize(s.cedar, s.entities, creq)
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
		if err := s.appendMatched(&out, diag.Reasons); err != nil {
			return out, err
		}
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
	// Clone monitor rules: only an allowed request is flagged, and the decision never changes.
	if !deny {
		flagged, flagDiag := cedar.Authorize(s.flags, s.entities, creq)
		if len(flagDiag.Errors) > 0 {
			out.Monitored = true // cannot tell whether a flag applies: flag it rather than miss one
		} else if flagged == cedar.Allow {
			out.Monitored = true
			if err := s.appendMatched(&out, flagDiag.Reasons); err != nil {
				return out, err
			}
		}
	}
	slices.SortFunc(out.MatchedRules, func(a, b muistamov1.PolicyRuleRef) int { return strings.Compare(a.Id, b.Id) })
	if out.Reason == "" {
		out.Reason = s.explain(req, out)
	}
	return out, nil
}

func (s *Set) appendMatched(out *muistamov1.PolicyDecision, reasons []cedar.DiagnosticReason) error {
	for _, r := range reasons {
		ref, ok := s.refs[r.PolicyID]
		if !ok {
			return fmt.Errorf("cedar matched unknown policy %q", r.PolicyID)
		}
		out.MatchedRules = append(out.MatchedRules, ref)
	}
	return nil
}

// keys lists a request end's targets, most specific first: its clone, then its template.
func keys(template string, clone *string) []string {
	if clone != nil {
		return []string{"clone:" + *clone, "template:" + template}
	}
	return []string{"template:" + template}
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
		var names []string
		for _, f := range keys(from, req.FromClone) {
			for _, t := range keys(to, req.ToClone) {
				names = append(names, s.links[[2]string{f, t}]...)
			}
		}
		if len(names) > 0 {
			text = fmt.Sprintf("denied: link %s does not allow this call (skill, data classes, delegation depth or act-for mode)",
				strings.Join(names, ", "))
		} else {
			text = fmt.Sprintf("denied by default: no link lets %s call %s", describe(from, req.FromClone), describe(to, req.ToClone))
		}
	default:
		agent := deref(req.Agent)
		var names []string
		for _, k := range keys(agent, req.AgentClone) {
			if name, ok := s.policies[k]; ok {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			text = fmt.Sprintf("denied by default: no rule in action policy %s allows %s", strings.Join(names, ", "), deref(req.Action))
		} else {
			text = fmt.Sprintf("denied by default: no action policy applies to %s", describe(agent, req.AgentClone))
		}
	}
	if d.Monitored && d.Decision == muistamov1.PolicyDecisionDecisionDeny {
		text += "; the policy is in monitor mode, so this would be reported, not blocked"
	}
	return text
}

func describe(template string, clone *string) string {
	if clone != nil {
		return "clone " + *clone + " of " + template
	}
	return template
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ptr[T any](v T) *T { return &v }

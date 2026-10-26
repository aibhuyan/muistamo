package registry

// HUMAN REVIEW REQUIRED (CLAUDE.md): storage and decisions for the gateway's policy path.
//
// Agent links and action policies are stored whole, with a revision. Every change, and every
// decision, appends signed evidence in the same transaction. A change is refused unless the
// tenant's whole set still compiles, so the stored rules are always a valid Cedar policy set.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/policy"
)

const (
	kindLink   = "AgentLink"
	kindPolicy = "ActionPolicy"
)

// evidencePrefix names each kind's change events: link.created, action-policy.updated, ...
var evidencePrefix = map[string]string{kindLink: "link", kindPolicy: "action-policy"}

type storedDoc struct {
	revision             int
	createdAt, updatedAt time.Time
	updatedBy            string
	body                 []byte
}

func linkRecord(d storedDoc) (muistamov1.AgentLinkRecord, error) {
	rec := muistamov1.AgentLinkRecord{Revision: d.revision, CreatedAt: d.createdAt, UpdatedAt: d.updatedAt, UpdatedBy: d.updatedBy}
	return rec, json.Unmarshal(d.body, &rec.Document)
}

func policyRecord(d storedDoc) (muistamov1.ActionPolicyRecord, error) {
	rec := muistamov1.ActionPolicyRecord{Revision: d.revision, CreatedAt: d.createdAt, UpdatedAt: d.updatedAt, UpdatedBy: d.updatedBy}
	return rec, json.Unmarshal(d.body, &rec.Document)
}

// ApplyLink creates or changes an agent link. It reports whether the link was created.
func (s *Service) ApplyLink(ctx context.Context, actor Actor, doc muistamov1.AgentLink) (muistamov1.AgentLinkRecord, bool, error) {
	if doc.Kind != kindLink {
		return muistamov1.AgentLinkRecord{}, false, fmt.Errorf("kind %q is not AgentLink: %w", doc.Kind, ErrInvalid)
	}
	// A link naming a clone that does not exist yet would hand its rights to whatever clone
	// later takes that name, so both ends must exist (clones are never deleted).
	var clones []string
	for _, end := range []muistamov1.AgentLinkEndpoint{doc.Spec.From, doc.Spec.To} {
		if end.Clone != nil {
			clones = append(clones, *end.Clone)
		}
	}
	d, created, err := s.applyPolicyDocument(ctx, actor, kindLink, doc.Metadata.Name, nil, clones, doc)
	if err != nil {
		return muistamov1.AgentLinkRecord{}, false, err
	}
	rec, err := linkRecord(d)
	return rec, created, err
}

// ApplyActionPolicy creates or changes an action policy. At most one applies to a template.
func (s *Service) ApplyActionPolicy(ctx context.Context, actor Actor, doc muistamov1.ActionPolicy) (muistamov1.ActionPolicyRecord, bool, error) {
	if doc.Kind != kindPolicy {
		return muistamov1.ActionPolicyRecord{}, false, fmt.Errorf("kind %q is not ActionPolicy: %w", doc.Kind, ErrInvalid)
	}
	target := policyTarget{template: doc.Spec.AppliesTo.Template, clone: doc.Spec.AppliesTo.Clone}
	if (target.template == nil) == (target.clone == nil) {
		return muistamov1.ActionPolicyRecord{}, false, fmt.Errorf("appliesTo must name exactly one template or clone: %w", ErrInvalid)
	}
	var clones []string
	if target.clone != nil {
		clones = []string{*target.clone}
	}
	d, created, err := s.applyPolicyDocument(ctx, actor, kindPolicy, doc.Metadata.Name, &target, clones, doc)
	if err != nil {
		return muistamov1.ActionPolicyRecord{}, false, err
	}
	rec, err := policyRecord(d)
	return rec, created, err
}

// policyTarget is what an ActionPolicy applies to: exactly one template or clone.
type policyTarget struct{ template, clone *string }

func (t policyTarget) column() (string, string) {
	if t.template != nil {
		return "template", *t.template
	}
	return "clone", *t.clone
}

func (s *Service) applyPolicyDocument(ctx context.Context, actor Actor, kind, name string, target *policyTarget, clones []string, doc any) (storedDoc, bool, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return storedDoc{}, false, fmt.Errorf("encode %s: %w", kind, err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])

	var out storedDoc
	var created bool
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		current, currentDigest, err := policyDocument(ctx, tx, kind, name, true)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if exists && currentDigest == digest {
			out = current
			return nil
		}
		var template, clone *string
		if target != nil {
			template, clone = target.template, target.clone
			column, value := target.column()
			var other string
			// column is one of two constants, never input.
			err := tx.QueryRow(ctx, `SELECT name FROM policy_documents WHERE kind = 'ActionPolicy' AND `+column+` = $1 AND name <> $2`,
				value, name).Scan(&other)
			if err == nil {
				return fmt.Errorf("action policy %q already applies to %s %q; change that policy instead: %w", other, column, value, ErrConflict)
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("check action policies for %s %q: %w", column, value, err)
			}
		}
		for _, c := range clones {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_clones WHERE name = $1)`, c).Scan(&exists); err != nil {
				return fmt.Errorf("check clone %q: %w", c, err)
			}
			if !exists {
				return fmt.Errorf("clone %q does not exist: %w", c, ErrInvalid)
			}
		}

		var before any
		action := evidencePrefix[kind] + ".created"
		if exists {
			before = json.RawMessage(current.body)
			action = evidencePrefix[kind] + ".updated"
			err = tx.QueryRow(ctx, `
				UPDATE policy_documents SET template = $3, clone = $7, revision = revision + 1, digest = $4, document = $5,
				  updated_at = now(), updated_by = $6
				WHERE kind = $1 AND name = $2
				RETURNING revision, created_at, updated_at, updated_by, document`,
				kind, name, template, digest, body, actor.Name, clone).Scan(&out.revision, &out.createdAt, &out.updatedAt, &out.updatedBy, &out.body)
		} else {
			err = tx.QueryRow(ctx, `
				INSERT INTO policy_documents (tenant_id, kind, name, template, clone, revision, digest, document, updated_by)
				VALUES ($1, $2, $3, $4, $8, 1, $5, $6, $7)
				RETURNING revision, created_at, updated_at, updated_by, document`,
				actor.Tenant, kind, name, template, digest, body, actor.Name, clone).Scan(&out.revision, &out.createdAt, &out.updatedAt, &out.updatedBy, &out.body)
			created = true
		}
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("another action policy already applies to this template or clone: %w", ErrConflict)
			}
			return fmt.Errorf("store %s %q: %w", kind, name, err)
		}
		if _, err := compileStored(ctx, tx); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, action, kind, name, before,
			map[string]any{"revision": out.revision, "document": json.RawMessage(out.body)})
	})
	return out, created, err
}

// GetLink returns an agent link.
func (s *Service) GetLink(ctx context.Context, actor Actor, name string) (muistamov1.AgentLinkRecord, error) {
	d, err := s.getPolicyDocument(ctx, actor, kindLink, name)
	if err != nil {
		return muistamov1.AgentLinkRecord{}, err
	}
	return linkRecord(d)
}

// GetActionPolicy returns an action policy.
func (s *Service) GetActionPolicy(ctx context.Context, actor Actor, name string) (muistamov1.ActionPolicyRecord, error) {
	d, err := s.getPolicyDocument(ctx, actor, kindPolicy, name)
	if err != nil {
		return muistamov1.ActionPolicyRecord{}, err
	}
	return policyRecord(d)
}

func (s *Service) getPolicyDocument(ctx context.Context, actor Actor, kind, name string) (storedDoc, error) {
	var d storedDoc
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		d, _, err = policyDocument(ctx, tx, kind, name, false)
		return err
	})
	return d, err
}

// ListLinks returns every agent link, by name.
func (s *Service) ListLinks(ctx context.Context, actor Actor) ([]muistamov1.AgentLinkRecord, error) {
	docs, err := s.listPolicyDocuments(ctx, actor, kindLink)
	out := make([]muistamov1.AgentLinkRecord, 0, len(docs))
	for _, d := range docs {
		rec, err := linkRecord(d)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, err
}

// ListActionPolicies returns every action policy, by name.
func (s *Service) ListActionPolicies(ctx context.Context, actor Actor) ([]muistamov1.ActionPolicyRecord, error) {
	docs, err := s.listPolicyDocuments(ctx, actor, kindPolicy)
	out := make([]muistamov1.ActionPolicyRecord, 0, len(docs))
	for _, d := range docs {
		rec, err := policyRecord(d)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, err
}

func (s *Service) listPolicyDocuments(ctx context.Context, actor Actor, kind string) ([]storedDoc, error) {
	var out []storedDoc
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT revision, created_at, updated_at, updated_by, document FROM policy_documents
			WHERE kind = $1 ORDER BY name`, kind)
		if err != nil {
			return fmt.Errorf("list %s: %w", kind, err)
		}
		for rows.Next() {
			var d storedDoc
			if err := rows.Scan(&d.revision, &d.createdAt, &d.updatedAt, &d.updatedBy, &d.body); err != nil {
				return fmt.Errorf("scan %s: %w", kind, err)
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteLink removes a link; calls it allowed are denied from then on.
func (s *Service) DeleteLink(ctx context.Context, actor Actor, name string) error {
	return s.deletePolicyDocument(ctx, actor, kindLink, name)
}

// DeleteActionPolicy removes an action policy; the template's actions are denied by default.
func (s *Service) DeleteActionPolicy(ctx context.Context, actor Actor, name string) error {
	return s.deletePolicyDocument(ctx, actor, kindPolicy, name)
}

func (s *Service) deletePolicyDocument(ctx context.Context, actor Actor, kind, name string) error {
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var revision int
		var body []byte
		err := tx.QueryRow(ctx, `DELETE FROM policy_documents WHERE kind = $1 AND name = $2 RETURNING revision, document`,
			kind, name).Scan(&revision, &body)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("delete %s %q: %w", kind, name, err)
		}
		return recordEvidence(ctx, tx, s.signer, actor, evidencePrefix[kind]+".deleted", kind, name,
			map[string]any{"revision": revision, "document": json.RawMessage(body)}, nil)
	})
}

// Decide answers a policy request against the tenant's rules and records the decision as
// evidence. Release 1 is observe mode: nothing is blocked.
func (s *Service) Decide(ctx context.Context, actor Actor, req muistamov1.PolicyDecisionRequest) (muistamov1.PolicyDecision, error) {
	var out muistamov1.PolicyDecision
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		set, err := compileStored(ctx, tx)
		if err != nil {
			return err
		}
		out, err = decide(set, req)
		if err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "policy.decision", "AgentTemplate", requester(req), nil,
			map[string]any{"request": req, "decision": out})
	})
	return out, err
}

// Simulate decides req under the current rules and under the current rules with proposed
// documents replacing those of the same kind and name. It stores nothing and records nothing.
func (s *Service) Simulate(ctx context.Context, actor Actor, in muistamov1.PolicySimulationRequest) (muistamov1.PolicySimulation, error) {
	var out muistamov1.PolicySimulation
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		links, policies, err := loadStored(ctx, tx)
		if err != nil {
			return err
		}
		clones, err := cloneTemplates(ctx, tx)
		if err != nil {
			return err
		}
		current, err := policy.Compile(links, policies, clones)
		if err != nil {
			return fmt.Errorf("stored policies do not compile: %w", err)
		}
		if in.Links != nil {
			links = replaceByName(links, *in.Links, func(l muistamov1.AgentLink) string { return l.Metadata.Name })
		}
		if in.Policies != nil {
			policies = replaceByName(policies, *in.Policies, func(p muistamov1.ActionPolicy) string { return p.Metadata.Name })
		}
		proposed, err := policy.Compile(links, policies, clones)
		if err != nil {
			return fmt.Errorf("proposed rules: %v: %w", err, ErrInvalid)
		}
		if out.Current, err = decide(current, in.Request); err != nil {
			return err
		}
		if out.Proposed, err = decide(proposed, in.Request); err != nil {
			return err
		}
		out.Changed = out.Current.Decision != out.Proposed.Decision || out.Current.WouldBlock != out.Proposed.WouldBlock
		return nil
	})
	return out, err
}

// CompiledPolicies returns the Cedar policy set the tenant's rules compile to.
func (s *Service) CompiledPolicies(ctx context.Context, actor Actor) (muistamov1.CompiledPolicies, error) {
	var out muistamov1.CompiledPolicies
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		set, err := compileStored(ctx, tx)
		if err != nil {
			return err
		}
		out = muistamov1.CompiledPolicies{Cedar: set.Cedar(), Rules: set.Rules()}
		return nil
	})
	return out, err
}

func decide(set *policy.Set, req muistamov1.PolicyDecisionRequest) (muistamov1.PolicyDecision, error) {
	d, err := set.Decide(req)
	if errors.Is(err, policy.ErrInvalid) {
		return d, fmt.Errorf("%v: %w", err, ErrInvalid)
	}
	return d, err
}

func requester(req muistamov1.PolicyDecisionRequest) string {
	if req.Kind == muistamov1.PolicyDecisionRequestKindCall && req.From != nil {
		return *req.From
	}
	if req.Agent != nil {
		return *req.Agent
	}
	return ""
}

func replaceByName[D any](current, proposed []D, name func(D) string) []D {
	out := make([]D, 0, len(current)+len(proposed))
	replaced := map[string]bool{}
	for _, p := range proposed {
		replaced[name(p)] = true
	}
	for _, c := range current {
		if !replaced[name(c)] {
			out = append(out, c)
		}
	}
	return append(out, proposed...)
}

func policyDocument(ctx context.Context, tx pgx.Tx, kind, name string, lock bool) (storedDoc, string, error) {
	q := `SELECT revision, created_at, updated_at, updated_by, document, digest FROM policy_documents WHERE kind = $1 AND name = $2`
	if lock {
		q += ` FOR UPDATE`
	}
	var d storedDoc
	var digest string
	err := tx.QueryRow(ctx, q, kind, name).Scan(&d.revision, &d.createdAt, &d.updatedAt, &d.updatedBy, &d.body, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, "", fmt.Errorf("%s %q: %w", kind, name, ErrNotFound)
	}
	if err != nil {
		return d, "", fmt.Errorf("read %s %q: %w", kind, name, err)
	}
	return d, digest, nil
}

func loadStored(ctx context.Context, tx pgx.Tx) ([]muistamov1.AgentLink, []muistamov1.ActionPolicy, error) {
	rows, err := tx.Query(ctx, `SELECT kind, document FROM policy_documents ORDER BY kind, name`)
	if err != nil {
		return nil, nil, fmt.Errorf("load policies: %w", err)
	}
	defer rows.Close()
	var links []muistamov1.AgentLink
	var policies []muistamov1.ActionPolicy
	for rows.Next() {
		var kind string
		var body []byte
		if err := rows.Scan(&kind, &body); err != nil {
			return nil, nil, fmt.Errorf("scan policy: %w", err)
		}
		switch kind {
		case kindLink:
			var l muistamov1.AgentLink
			if err := json.Unmarshal(body, &l); err != nil {
				return nil, nil, fmt.Errorf("decode stored link: %w", err)
			}
			links = append(links, l)
		case kindPolicy:
			var p muistamov1.ActionPolicy
			if err := json.Unmarshal(body, &p); err != nil {
				return nil, nil, fmt.Errorf("decode stored action policy: %w", err)
			}
			policies = append(policies, p)
		default:
			return nil, nil, fmt.Errorf("stored policy of unknown kind %q", kind)
		}
	}
	return links, policies, rows.Err()
}

// compileStored compiles the tenant's stored rules. A failure is ErrInvalid: inside an apply it
// refuses the change that broke the set.
func compileStored(ctx context.Context, tx pgx.Tx) (*policy.Set, error) {
	links, policies, err := loadStored(ctx, tx)
	if err != nil {
		return nil, err
	}
	clones, err := cloneTemplates(ctx, tx)
	if err != nil {
		return nil, err
	}
	set, err := policy.Compile(links, policies, clones)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, ErrInvalid)
	}
	return set, nil
}

// cloneTemplates maps each of the tenant's clones to its template, for the policy compiler.
func cloneTemplates(ctx context.Context, tx pgx.Tx) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT name, template FROM agent_clones`)
	if err != nil {
		return nil, fmt.Errorf("load clones: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, template string
		if err := rows.Scan(&name, &template); err != nil {
			return nil, err
		}
		out[name] = template
	}
	return out, rows.Err()
}

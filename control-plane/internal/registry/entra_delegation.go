package registry

// HUMAN REVIEW REQUIRED: per-call authorisation of on-behalf-of retrieval (docs/obo-retrieval-
// plan.md, PR B; invariants 1-4). A delegation is decided at the moment of each request, never
// cached: the person's link, their current HR joiner, their agent's state and its identity are
// all read under the same HR privacy fence, person lock and instance lock as the live lifecycle.
// The decision is made twice: once before the exchange with Entra, which then runs holding no
// lock (so a slow provider never stalls the gateway, leavers or erasure), and again after it, in
// the transaction that writes the signed evidence. A leaver, erasure or suspension that lands
// during the exchange is seen by the second decision, which refuses and discards the token.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// GraphResource is the resource every delegation is issued for.
const GraphResource = "https://graph.microsoft.com"

// delegationTimeout bounds the whole request; exchangeTimeout bounds the provider exchange, which
// runs holding no lock.
const (
	delegationTimeout = 15 * time.Second
	exchangeTimeout   = 5 * time.Second
)

// DelegationRequest is what a validated user token establishes: the user's directory and immutable
// object id, under the binding version that validated it. Instance optionally names which of the
// person's agents acts.
type DelegationRequest struct {
	BindingVersion uuid.UUID
	EntraTenant    uuid.UUID
	User           uuid.UUID
	Instance       *string
}

// DelegationExchange obtains the delegated token for the agent identity. It is called at most
// once, between the two decisions, holding no lock; its error is not recorded, only that it
// failed.
type DelegationExchange func(ctx context.Context, agentIdentity uuid.UUID) (token string, expires time.Time, err error)

// ErrDelegationNotConfigured means the control plane holds no Entra binding for the tenant, so it
// cannot validate tokens or exchange them. Nothing is decided or recorded.
var ErrDelegationNotConfigured = errors.New("delegation is not configured for this tenant")

// DelegationRefused is a refusal whose reason is already recorded in signed evidence.
type DelegationRefused struct {
	Reason muistamov1.KnowledgeDelegationRefusalReason
}

func (e *DelegationRefused) Error() string { return "delegation refused: " + string(e.Reason) }

// UseDelegationNonce accepts nonce once per tenant. A nonce already seen is ErrConflict. Nonces
// are kept three times the signature window, so pruning by the database's clock never readmits a
// replay that the service's clock still finds fresh.
func (s *Service) UseDelegationNonce(ctx context.Context, tenant uuid.UUID, nonce string) error {
	return s.db.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM delegation_nonces WHERE seen_at < now() - interval '15 minutes'`); err != nil {
			return fmt.Errorf("prune delegation nonces: %w", err)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO delegation_nonces (tenant_id, nonce) VALUES ($1, $2) ON CONFLICT DO NOTHING`, tenant, nonce)
		if err != nil {
			return fmt.Errorf("record delegation nonce: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("delegation nonce already used: %w", ErrConflict)
		}
		return nil
	})
}

// RefuseDelegation records a refusal decided before any registry state was read, such as a user
// token that failed validation. Nothing from the refused token is recorded.
func (s *Service) RefuseDelegation(ctx context.Context, actor Actor, reason muistamov1.KnowledgeDelegationRefusalReason) error {
	if s.signer == nil {
		return ErrEvidence
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		return recordEvidence(ctx, tx, s.signer, actor, "knowledge.delegation.refused", "KnowledgeDelegation", actor.RequestID, nil,
			map[string]any{"reason": reason})
	})
	if err != nil {
		return fmt.Errorf("record delegation refusal: %w", errors.Join(ErrEvidence, err))
	}
	return &DelegationRefused{Reason: reason}
}

// delegationTarget is what a decision allows: which agent acts, for whom, with which packs.
type delegationTarget struct {
	instance string
	person   string
	agent    uuid.UUID
	packs    []muistamov1.KnowledgePackRef
}

// Delegate decides whether the knowledge service may act for the user through their agent, and
// if so exchanges and returns the delegated token. Every outcome is evidenced before it returns,
// a failed exchange included: a refusal is a *DelegationRefused, and an evidence failure is
// ErrEvidence with nothing issued.
func (s *Service) Delegate(ctx context.Context, actor Actor, req DelegationRequest, exchange DelegationExchange) (muistamov1.KnowledgeDelegation, error) {
	if s.signer == nil {
		return muistamov1.KnowledgeDelegation{}, ErrEvidence
	}
	ctx, cancel := context.WithTimeout(ctx, delegationTimeout)
	defer cancel()
	// First decision. Only a refusal is recorded here; an allowed one is recorded by the second
	// decision, with the exchange's outcome.
	var first delegationTarget
	var refused *DelegationRefused
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		d, err := decideDelegation(ctx, tx, actor, req)
		if err != nil {
			return err
		}
		if d.reason != "" {
			refused = &DelegationRefused{Reason: d.reason}
			return s.recordRefusal(ctx, tx, actor, d.reason, d.trusted)
		}
		first = d.target
		return nil
	})
	if err != nil || refused != nil {
		return muistamov1.KnowledgeDelegation{}, delegationOutcome(err, refused)
	}
	exchangeCtx, cancelExchange := context.WithTimeout(ctx, exchangeTimeout)
	token, expires, exchangeErr := exchange(exchangeCtx, first.agent)
	cancelExchange()
	if exchangeErr == nil && (token == "" || !time.Now().Before(expires)) {
		exchangeErr = errors.New("unusable exchange answer")
	}
	// Second decision, which records the outcome. The token is returned only if the same agent
	// is still allowed to act for the same person.
	var out muistamov1.KnowledgeDelegation
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		d, err := decideDelegation(ctx, tx, actor, req)
		if err != nil {
			return err
		}
		target, trusted, reason := d.target, d.trusted, d.reason
		if reason == "" && (target.instance != first.instance || target.agent != first.agent || target.person != first.person) {
			reason = "identity-not-ready"
		}
		if reason == "" && exchangeErr != nil {
			reason = "exchange-refused"
		}
		if reason != "" {
			refused = &DelegationRefused{Reason: reason}
			return s.recordRefusal(ctx, tx, actor, reason, trusted)
		}
		digest := sha256.Sum256([]byte(token))
		out = muistamov1.KnowledgeDelegation{Instance: target.instance, AgentIdentity: target.agent, Person: target.person, Packs: target.packs, GraphToken: token, ExpiresAt: expires.UTC()}
		detail := map[string]any{"resource": GraphResource, "expiresAt": out.ExpiresAt, "tokenHash": hex.EncodeToString(digest[:8]), "packs": target.packs}
		for key, value := range trusted {
			detail[key] = value
		}
		return recordEvidence(ctx, tx, s.signer, actor, "knowledge.delegation.issued", "KnowledgeDelegation", actor.RequestID, nil, detail)
	})
	if err != nil || refused != nil {
		return muistamov1.KnowledgeDelegation{}, delegationOutcome(err, refused)
	}
	return out, nil
}

func delegationOutcome(err error, refused *DelegationRefused) error {
	switch {
	case err == nil:
		return refused
	case errors.Is(err, ErrEvidence):
		return err
	default:
		return fmt.Errorf("decide delegation: %w", err)
	}
}

func (s *Service) recordRefusal(ctx context.Context, tx pgx.Tx, actor Actor, reason muistamov1.KnowledgeDelegationRefusalReason, trusted map[string]any) error {
	detail := map[string]any{"reason": reason}
	for name, value := range trusted {
		detail[name] = value
	}
	return recordEvidence(ctx, tx, s.signer, actor, "knowledge.delegation.refused", "KnowledgeDelegation", actor.RequestID, nil, detail)
}

type delegationDecision struct {
	target  delegationTarget
	trusted map[string]any
	reason  muistamov1.KnowledgeDelegationRefusalReason
}

// decideDelegation takes the locks and decides. A refusal is a reason with the trusted facts established
// so far, for its evidence; an empty reason allows the target.
func decideDelegation(ctx context.Context, tx pgx.Tx, actor Actor, req DelegationRequest) (delegationDecision, error) {
	trusted := map[string]any{"user": entraUserDigest(actor.Tenant, req.EntraTenant, req.User)}
	refuse := func(reason muistamov1.KnowledgeDelegationRefusalReason) (delegationDecision, error) {
		return delegationDecision{trusted: trusted, reason: reason}, nil
	}
	// Lock order as in the gateway and the live lifecycle: HR privacy, the person, the instance.
	if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
		return delegationDecision{}, err
	}
	// The token was validated with the binding the tenant is enrolled with now, for its directory.
	version, err := store.IdentityEnrollmentVersion(ctx, tx)
	if err != nil {
		return delegationDecision{}, err
	}
	if version == nil {
		return refuse("user-unlinked")
	}
	if *version != req.BindingVersion {
		return refuse("identity-not-ready")
	}
	var enrolled uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT entra_tenant_id FROM entra_bindings WHERE binding_version = $1`, *version).Scan(&enrolled); err != nil {
		return delegationDecision{}, fmt.Errorf("read enrolled binding: %w", err)
	}
	if enrolled != req.EntraTenant {
		return refuse("user-unlinked")
	}
	var person string
	err = tx.QueryRow(ctx, `SELECT person_id FROM person_entra_links
		WHERE entra_tenant_id = $1 AND entra_user_object_id = $2 AND status = 'matched'`, req.EntraTenant, req.User).Scan(&person)
	if errors.Is(err, pgx.ErrNoRows) {
		return refuse("user-unlinked")
	}
	if err != nil {
		return delegationDecision{}, fmt.Errorf("read Entra user link: %w", err)
	}
	if err := lockIdentityHRPerson(ctx, tx, actor.Tenant, person); err != nil {
		return delegationDecision{}, err
	}
	// Read again under the person lock, which every link write holds: the link stands only if
	// its joiner receipt is still the person's latest accepted HR event.
	var current bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM person_entra_links l
		JOIN LATERAL (SELECT receipt_id, type FROM hr_events h WHERE h.person_id = l.person_id AND h.decision IN ('accepted','legacy')
			ORDER BY generation DESC, occurred_at DESC, (type='leaver') DESC, event_id DESC LIMIT 1) latest ON true
		WHERE l.person_id = $1 AND l.status = 'matched' AND l.entra_tenant_id = $2 AND l.entra_user_object_id = $3
		  AND latest.type = 'joiner' AND latest.receipt_id = l.receipt_id)`, person, req.EntraTenant, req.User).Scan(&current)
	if err != nil {
		return delegationDecision{}, fmt.Errorf("check Entra user link: %w", err)
	}
	if !current {
		return refuse("user-unlinked")
	}
	trusted["person"] = person
	// The person's live agents: those whose identity was assigned by one of the person's HR
	// receipts. State is read again under the chosen instance's lock below.
	rows, err := tx.Query(ctx, `SELECT i.instance_name FROM instance_identities i
		JOIN hr_events h ON h.tenant_id = i.tenant_id AND h.receipt_id = i.assignment_receipt_id
		JOIN agent_instances a ON a.tenant_id = i.tenant_id AND a.name = i.instance_name
		WHERE h.person_id = $1 AND i.provider_mode = 'entra' AND a.state = 'active'
		ORDER BY i.instance_name`, person)
	if err != nil {
		return delegationDecision{}, fmt.Errorf("list the person's agents: %w", err)
	}
	active, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return delegationDecision{}, fmt.Errorf("list the person's agents: %w", err)
	}
	var name string
	switch {
	case req.Instance != nil:
		if !slices.Contains(active, *req.Instance) {
			trusted["instance"] = *req.Instance
			return refuse("no-active-agent")
		}
		name = *req.Instance
	case len(active) == 0:
		return refuse("no-active-agent")
	case len(active) > 1:
		return refuse("agent-ambiguous")
	default:
		name = active[0]
	}
	trusted["instance"] = name
	// The instance is the person's by the list above, so this takes the person lock already
	// held. Should its assignment change in between, it locks that other person too and refuses;
	// a resulting lock cycle is broken by PostgreSQL's deadlock detection, failing this request.
	locked, err := identityPersonLock(ctx, tx, actor.Tenant, name)
	if err != nil {
		return delegationDecision{}, err
	}
	if locked != person {
		return refuse("identity-not-ready")
	}
	inst, err := lockInstance(ctx, tx, name)
	if errors.Is(err, ErrNotFound) {
		return refuse("no-active-agent")
	}
	if err != nil {
		return delegationDecision{}, err
	}
	if inst.Document.Spec.State != muistamov1.InstanceStateActive || inst.Document.Spec.Binding.Type != "user" {
		return refuse("no-active-agent")
	}
	if err := checkIdentityTransition(ctx, tx, inst, muistamov1.InstanceStateActive, person); err != nil {
		if errors.Is(err, ErrConflict) {
			return refuse("identity-not-ready")
		}
		return delegationDecision{}, err
	}
	owned, err := identityRow(ctx, tx, name)
	if err != nil {
		return delegationDecision{}, err
	}
	// The agent identity must belong to the enrolled blueprint: only that blueprint can mint the
	// agent's assertion, with the credential the control plane was started with.
	if owned.ProviderId == nil || owned.BindingVersion == nil || *owned.BindingVersion != *version || owned.EntraTenantId == nil || *owned.EntraTenantId != req.EntraTenant {
		return refuse("identity-not-ready")
	}
	agent := *owned.ProviderId
	trusted["agentIdentity"] = agent
	eff, err := gatewayEffectiveSpec(ctx, tx, inst)
	if err != nil {
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) {
			return refuse("no-active-agent")
		}
		return delegationDecision{}, err
	}
	packs := []muistamov1.KnowledgePackRef{}
	if eff.Spec.KnowledgePacks != nil {
		packs = *eff.Spec.KnowledgePacks
	}
	return delegationDecision{target: delegationTarget{instance: name, person: person, agent: agent, packs: packs}, trusted: trusted}, nil
}

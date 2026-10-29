package registry

// HUMAN REVIEW REQUIRED: per-call permissions, key validation and gateway policy path.
// This phase governs model authorization only. MCP is refused until operation-specific
// person rights and initialization ownership can be established. Cedar remains observe-only.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// AuthorizeGateway commits an authorization ledger row and its signed evidence before allow.
// tenant and route come from trusted listener configuration, never from client headers. Secrets
// and raw request attributes are never persisted. An error always discards any allow result.
func (s *Service) AuthorizeGateway(ctx context.Context, tenant uuid.UUID, presented string, req muistamov1.GatewayAuthorizationRequest, route *muistamov1.GatewayModelRoute) (muistamov1.GatewayAuthorizationDecision, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return muistamov1.GatewayAuthorizationDecision{}, fmt.Errorf("gateway request id: %w", err)
	}
	out := muistamov1.GatewayAuthorizationDecision{RequestId: id, Reason: "invalid-request"}
	if s.signer == nil {
		return out, ErrEvidence
	}
	ctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	err = s.db.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		actor := Actor{Tenant: tenant, Name: "gateway:anonymous", RequestID: id.String()}
		trusted := map[string]any{}
		deny := func(reason muistamov1.GatewayAuthorizationDecisionReason) error {
			out.Reason = reason
			detail := map[string]any{"requestId": id, "reason": reason}
			for name, value := range trusted {
				detail[name] = value
			}
			return recordEvidence(ctx, tx, s.signer, actor, "gateway.call.denied", "GatewayRequest", id.String(), nil,
				detail)
		}
		if req.Kind == "mcp" {
			return deny("mcp-not-integrated")
		}
		if req.Kind != "model" || req.Method != "POST" || req.Path != "/v1/chat/completions" || !req.MetadataValid || req.Alias == nil || *req.Alias == "" {
			return deny("invalid-request")
		}
		keyID, secret, err := ParseKey(presented)
		if err != nil {
			return deny("invalid-key")
		}
		var instance string
		var hash []byte
		err = tx.QueryRow(ctx, `SELECT instance,secret_sha256 FROM virtual_keys WHERE tenant_id=$1 AND id=$2`, tenant, keyID).Scan(&instance, &hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return deny("invalid-key")
		}
		if err != nil {
			return fmt.Errorf("read gateway key: %w", err)
		}
		if !KeyMatches(hash, secret) {
			return deny("invalid-key")
		}
		// Same lock order as lifecycle and erasure. The initial key read authenticates only;
		// status and expiry are read again under the key lock after acquiring these fences.
		person, err := identityPersonLock(ctx, tx, tenant, instance)
		if err != nil {
			return err
		}
		inst, err := lockInstance(ctx, tx, instance)
		if err != nil {
			return err
		}
		actor.Name = "gateway:" + instance
		trusted["keyId"], trusted["instance"] = keyID, instance
		binding := inst.Document.Spec.Binding
		if binding.Type != "user" || binding.Ref == "" || len([]rune("dev:"+binding.Ref)) > 320 || strings.TrimSpace(binding.Ref) != binding.Ref || strings.HasPrefix(binding.Ref, "erased:") || unsafeGatewayHeader(binding.Ref) {
			return deny("person-not-established")
		}
		// Explicit development identity mapping, identical to InsecureDevHeaders. This is
		// attribution for the bounded development gateway, never an Entra OBO assertion.
		principal := "dev:" + binding.Ref
		trusted["person"] = principal
		if inst.Document.Spec.CostCentre != nil {
			if unsafeGatewayHeader(*inst.Document.Spec.CostCentre) {
				return deny("invalid-request")
			}
			trusted["costCentre"] = *inst.Document.Spec.CostCentre
		}
		key, err := scanKey(tx.QueryRow(ctx, keyColumns+` WHERE id=$1 FOR UPDATE`, keyID), time.Now())
		if err != nil {
			return err
		}
		if key.Status != "active" || (key.ExpiresAt != nil && !time.Now().Before(*key.ExpiresAt)) {
			return deny("inactive-key")
		}
		if inst.Document.Spec.State != "active" {
			return deny("inactive-instance")
		}
		if err := checkIdentityTransition(ctx, tx, inst, "active", person); err != nil {
			if errors.Is(err, ErrConflict) {
				return deny("identity-not-ready")
			}
			return err
		}
		eff, err := gatewayEffectiveSpec(ctx, tx, inst)
		if err != nil {
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrInvalid) {
				return deny("alias-not-allowed")
			}
			return err
		}
		alias := *req.Alias
		if !slices.Contains(key.Aliases, alias) || eff.Spec.ModelAlias != alias {
			return deny("alias-not-allowed")
		}
		if route == nil || route.Alias != alias {
			return deny("route-not-current")
		}
		// Row SHARE locks keep rollout/model approval changes behind this decision's commit.
		var target string
		var aliasRevision int
		err = tx.QueryRow(ctx, `SELECT target,revision FROM model_aliases WHERE name=$1 FOR SHARE`, alias).Scan(&target, &aliasRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			return deny("route-not-current")
		}
		if err != nil {
			return err
		}
		var revision int
		var status, provider, model, region, currency, input, output string
		var cached *string
		err = tx.QueryRow(ctx, `SELECT revision,approval_status,document->'spec'->>'provider',document->'spec'->>'model',
			document->'spec'->>'region',document->'spec'->'priceSheet'->>'currency',
			(document->'spec'->'priceSheet'->>'inputPerMTok')::numeric(24,12)::text,
			(document->'spec'->'priceSheet'->>'cachedInputPerMTok')::numeric(24,12)::text,
			(document->'spec'->'priceSheet'->>'outputPerMTok')::numeric(24,12)::text
			FROM model_catalogue WHERE name=$1 FOR SHARE`, target).Scan(&revision, &status, &provider, &model, &region, &currency, &input, &cached, &output)
		if errors.Is(err, pgx.ErrNoRows) {
			return deny("route-not-current")
		}
		if err != nil {
			return err
		}
		if status != "approved" || aliasRevision != route.AliasRevision || target != route.CatalogueName || revision != route.ModelRevision || provider != route.Provider || model != route.Model || region != route.Region || currency != "EUR" {
			return deny("route-not-current")
		}
		// Recorded spend only. In-flight and missing usage can overshoot; later ingest/reporting
		// must expose that limit rather than estimating unseen provider usage.
		var within bool
		err = tx.QueryRow(ctx, `SELECT k.budget_currency='EUR' AND coalesce((SELECT sum(u.cost_amount)
			FROM gateway_calls c JOIN usage_records u USING(tenant_id,request_id)
			WHERE c.tenant_id=k.tenant_id AND c.key_id=k.id
			AND c.authorized_at >= (date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
			AND c.authorized_at < ((date_trunc('month',now() AT TIME ZONE 'UTC')+interval '1 month') AT TIME ZONE 'UTC')),0)<k.budget_amount
			FROM virtual_keys k WHERE k.id=$1`, keyID).Scan(&within)
		if err != nil {
			return err
		}
		if !within {
			return deny("budget-reached")
		}
		// Calls that ran without a usage report (aborted streams) are billed by the provider but
		// invisible to the budget: a key is refused once it has more of them this UTC month than
		// its allowance (0: refused after the first).
		// Calls whose usage did arrive no longer count. HUMAN REVIEW REQUIRED.
		var underCap bool
		err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM calls_without_usage w
			JOIN gateway_calls c USING (tenant_id, request_id)
			WHERE c.tenant_id = k.tenant_id AND c.key_id = k.id
			AND c.authorized_at >= (date_trunc('month', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')
			AND c.authorized_at < ((date_trunc('month', now() AT TIME ZONE 'UTC') + interval '1 month') AT TIME ZONE 'UTC')
			AND NOT EXISTS (SELECT 1 FROM usage_records u WHERE u.tenant_id = c.tenant_id AND u.request_id = c.request_id)
			) <= k.max_calls_without_usage
			FROM virtual_keys k WHERE k.id = $1`, keyID).Scan(&underCap)
		if err != nil {
			return err
		}
		if !underCap {
			return deny("calls-without-usage-limit")
		}
		set, err := compileStored(ctx, tx)
		if err != nil {
			return err
		}
		action := "model.invoke"
		observation, err := decide(set, muistamov1.PolicyDecisionRequest{Kind: "action", Agent: &eff.Template, AgentClone: eff.Clone, Action: &action})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gateway_calls(tenant_id,request_id,key_id,instance,person,cost_centre,kind,alias,provider,model,
			price_currency,input_per_mtok,cached_input_per_mtok,output_per_mtok)
			VALUES($1,$2,$3,$4,$5,$6,'model',$7,$8,$9,$10,$11::numeric,$12::numeric,$13::numeric)`, tenant, id, keyID, instance,
			principal, inst.Document.Spec.CostCentre, alias, provider, model, currency, input, cached, output); err != nil {
			return fmt.Errorf("record gateway authorization: %w", err)
		}
		actor.Name = "gateway:" + instance
		out.Allowed, out.Reason, out.KeyId, out.Instance, out.Person, out.CostCentre, out.Policy = true, "allowed", &keyID, &instance, &principal, inst.Document.Spec.CostCentre, &observation
		return recordEvidence(ctx, tx, s.signer, actor, "gateway.call.authorized", "GatewayRequest", id.String(), nil,
			map[string]any{"requestId": id, "keyId": keyID, "instance": instance, "person": principal, "costCentre": inst.Document.Spec.CostCentre,
				"alias": alias, "provider": provider, "model": model, "region": region, "aliasRevision": aliasRevision, "modelRevision": revision,
				"priceSnapshot": map[string]any{"currency": currency, "inputPerMTok": input, "cachedInputPerMTok": cached, "outputPerMTok": output}, "policy": observation})
	})
	if err != nil {
		return muistamov1.GatewayAuthorizationDecision{RequestId: id, Reason: "invalid-request"}, err
	}
	return out, nil
}

func unsafeGatewayHeader(value string) bool {
	return len(value) > 1024 || strings.IndexFunc(value, func(c rune) bool { return c < 0x20 || c == 0x7f }) >= 0
}

// Hold the mutable selectors of a clone's effective version through allow. Template versions
// are immutable; erasure is already excluded by the privacy fence. Missing follow publication
// is refused immediately; a later unlocked read must never turn initial absence into scope.
func gatewayEffectiveSpec(ctx context.Context, tx pgx.Tx, inst muistamov1.AgentInstanceRecord) (muistamov1.EffectiveAgentSpec, error) {
	if inst.Document.Spec.CloneRef != nil {
		var template, sync string
		if err := tx.QueryRow(ctx, `SELECT template,sync FROM agent_clones WHERE name=$1 FOR SHARE`, *inst.Document.Spec.CloneRef).Scan(&template, &sync); err != nil {
			return muistamov1.EffectiveAgentSpec{}, err
		}
		var version int
		if err := tx.QueryRow(ctx, `SELECT version FROM catalogue_published WHERE template=$1 FOR SHARE`, template).Scan(&version); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return muistamov1.EffectiveAgentSpec{}, err
			}
			if sync == "follow" {
				return muistamov1.EffectiveAgentSpec{}, fmt.Errorf("follow clone has no locked publication: %w", ErrConflict)
			}
		}
	}
	return effectiveSpec(ctx, tx, inst.Document.Metadata.Name)
}

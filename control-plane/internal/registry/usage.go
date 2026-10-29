package registry

// Usage metering at provider cost (docs/agentgateway-plan.md, step 5).
//
// HUMAN REVIEW REQUIRED (AGENTS.md): pricing, the usage access filter and batch evidence. Usage is
// priced in SQL from the price snapshot taken when the call was authorized, with the exact
// formula the usage_is_priced_at_cost trigger enforces (00014): no floats and no markup
// (invariant 7). A call without usage is reported as unmetered, never estimated (invariant 8).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// UnmeteredAfter is how long an authorized model call may go without usage before it is reported
// as unmetered. The gateway exports access logs within seconds; the margin covers batching.
const UnmeteredAfter = 15 * time.Minute

// UsageLine is one usage record from the gateway's access-log export, already validated for
// shape by the ingest server. Model is the upstream model the gateway called.
type UsageLine struct {
	RequestID         uuid.UUID
	Model             string
	ResponseModel     string
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
}

// UsageIngest counts what RecordUsage did with a batch.
type UsageIngest struct {
	Accepted    []uuid.UUID
	Duplicate   int // the same usage again: a no-op
	Conflicting int // a different usage for an already metered call: kept as first recorded
	Unmatched   int // no authorized model call with that id and model in this tenant
}

// ingestActor is the evidence actor for usage the gateway reported.
const ingestActor = "gateway:ingest"

// RecordUsage prices and records a batch of usage lines for one tenant, in one transaction with
// one signed gateway.usage.ingested event. If the evidence cannot be written nothing is recorded.
func (s *Service) RecordUsage(ctx context.Context, tenant uuid.UUID, lines []UsageLine) (UsageIngest, error) {
	var out UsageIngest
	batch := uuid.New()
	err := s.db.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		out = UsageIngest{}
		for _, l := range lines {
			if l.InputTokens < 0 || l.CachedInputTokens < 0 || l.OutputTokens < 0 || l.CachedInputTokens > l.InputTokens {
				return fmt.Errorf("usage line %s: invalid token counts: %w", l.RequestID, ErrInvalid)
			}
			// Same formula and rounding as usage_is_priced_at_cost; the trigger re-checks it.
			tag, err := tx.Exec(ctx, `INSERT INTO usage_records (tenant_id, request_id, input_tokens, cached_input_tokens,
				output_tokens, response_model, cost_amount, cost_currency)
				SELECT c.tenant_id, c.request_id, $2, $3, $4, nullif($5, ''),
				       round((($2::bigint - $3::bigint) * c.input_per_mtok
				              + $3::bigint * coalesce(c.cached_input_per_mtok, c.input_per_mtok)
				              + $4::bigint * c.output_per_mtok) / 1000000, 12),
				       c.price_currency
				  FROM gateway_calls c
				 WHERE c.request_id = $1 AND c.kind = 'model' AND c.model = $6
				ON CONFLICT (tenant_id, request_id) DO NOTHING`,
				l.RequestID, l.InputTokens, l.CachedInputTokens, l.OutputTokens, l.ResponseModel, l.Model)
			if err != nil {
				return fmt.Errorf("record usage %s: %w", l.RequestID, err)
			}
			if tag.RowsAffected() == 1 {
				out.Accepted = append(out.Accepted, l.RequestID)
				continue
			}
			var same *bool
			err = tx.QueryRow(ctx, `SELECT input_tokens = $2 AND cached_input_tokens = $3 AND output_tokens = $4
				FROM usage_records WHERE request_id = $1`, l.RequestID, l.InputTokens, l.CachedInputTokens, l.OutputTokens).Scan(&same)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				out.Unmatched++
			case err != nil:
				return fmt.Errorf("check usage %s: %w", l.RequestID, err)
			case *same:
				out.Duplicate++
			default:
				out.Conflicting++
			}
		}
		if len(out.Accepted) == 0 {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT cost_currency, sum(cost_amount)::text FROM usage_records
			WHERE request_id = ANY($1) GROUP BY cost_currency ORDER BY cost_currency`, out.Accepted)
		if err != nil {
			return fmt.Errorf("total batch cost: %w", err)
		}
		cost := map[string]string{}
		for rows.Next() {
			var currency, amount string
			if err := rows.Scan(&currency, &amount); err != nil {
				return fmt.Errorf("total batch cost: %w", err)
			}
			cost[currency] = trimDecimal(amount)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("total batch cost: %w", err)
		}
		ids := make([]string, len(out.Accepted))
		for i, id := range out.Accepted {
			ids[i] = id.String()
		}
		actor := Actor{Tenant: tenant, Name: ingestActor, RequestID: batch.String()}
		return recordEvidence(ctx, tx, s.signer, actor, "gateway.usage.ingested", "UsageBatch", batch.String(), nil,
			map[string]any{"requestIds": ids, "accepted": len(ids), "duplicate": out.Duplicate,
				"conflicting": out.Conflicting, "unmatched": out.Unmatched, "costAtProviderPrices": cost})
	})
	if err != nil {
		return UsageIngest{}, err
	}
	return out, nil
}

// UsageFilter narrows ListUsage. Zero values mean no filter.
type UsageFilter struct {
	Instance  string
	From, To  *time.Time
	Unmetered bool
	Cursor    string
	Limit     int
}

// ListUsage returns authorized calls and their cost, newest first. Gateway administrators see the
// tenant's calls; anyone else only the calls made for them (their own acting identity).
func (s *Service) ListUsage(ctx context.Context, actor Actor, f UsageFilter) (muistamov1.UsagePage, error) {
	page := muistamov1.UsagePage{Items: []muistamov1.UsageRecord{}}
	if f.Limit < 1 || f.Limit > 200 {
		f.Limit = 50
	}
	var afterAt *time.Time
	var afterID uuid.UUID
	if f.Cursor != "" {
		raw, err := decodeCursor(f.Cursor)
		if err != nil {
			return page, err
		}
		at, id, ok := strings.Cut(raw, "|")
		t, terr := time.Parse(time.RFC3339Nano, at)
		u, uerr := uuid.Parse(id)
		if !ok || terr != nil || uerr != nil {
			return page, fmt.Errorf("cursor: %w", ErrInvalid)
		}
		afterAt, afterID = &t, u
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		admin, err := isGatewayAdmin(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT c.request_id, c.key_id, c.instance, c.person, c.cost_centre, c.kind, c.alias,
			       c.provider, c.model, c.mcp_method, c.mcp_tool, c.authorized_at,
			       u.request_id IS NOT NULL, u.input_tokens, u.cached_input_tokens, u.output_tokens,
			       u.cost_amount::text, u.cost_currency, u.recorded_at
			  FROM gateway_calls c LEFT JOIN usage_records u USING (tenant_id, request_id)
			 WHERE ($1 OR c.person = $2)
			   AND ($3 = '' OR c.instance = $3)
			   AND ($4::timestamptz IS NULL OR c.authorized_at >= $4)
			   AND ($5::timestamptz IS NULL OR c.authorized_at < $5)
			   AND (NOT $6 OR (c.kind = 'model' AND u.request_id IS NULL AND c.authorized_at < now() - make_interval(secs => $7)))
			   AND ($8::timestamptz IS NULL OR (c.authorized_at, c.request_id) < ($8, $9))
			 ORDER BY c.authorized_at DESC, c.request_id DESC
			 LIMIT $10`,
			admin, actor.Name, f.Instance, f.From, f.To, f.Unmetered, UnmeteredAfter.Seconds(), afterAt, afterID, f.Limit+1)
		if err != nil {
			return fmt.Errorf("list usage: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var r muistamov1.UsageRecord
			var kind string
			var metered bool
			var in, cached, outTok *int64
			var amount, currency *string
			if err := rows.Scan(&r.RequestId, &r.KeyId, &r.Instance, &r.Person, &r.CostCentre, &kind, &r.Alias,
				&r.Provider, &r.Model, &r.McpMethod, &r.McpTool, &r.AuthorizedAt,
				&metered, &in, &cached, &outTok, &amount, &currency, &r.RecordedAt); err != nil {
				return fmt.Errorf("scan usage: %w", err)
			}
			r.Kind = muistamov1.UsageRecordKind(kind)
			if r.Kind == muistamov1.UsageRecordKindModel {
				r.Metered = &metered
			}
			if metered {
				r.InputTokens, r.CachedInputTokens, r.OutputTokens = intPtr(in), intPtr(cached), intPtr(outTok)
				r.Cost = &muistamov1.Money{Amount: trimDecimal(*amount), Currency: muistamov1.MoneyCurrency(*currency)}
			}
			page.Items = append(page.Items, r)
		}
		return rows.Err()
	})
	if err != nil {
		return muistamov1.UsagePage{Items: []muistamov1.UsageRecord{}}, err
	}
	if len(page.Items) > f.Limit {
		page.Items = page.Items[:f.Limit]
		last := page.Items[f.Limit-1]
		next := encodeCursor(last.AuthorizedAt.UTC().Format(time.RFC3339Nano) + "|" + last.RequestId.String())
		page.Next = &next
	}
	return page, nil
}

func intPtr(v *int64) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}

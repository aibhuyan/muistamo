package registry

// Usage metering at provider cost (docs/agentgateway-plan.md, step 5).
//
// HUMAN REVIEW REQUIRED (AGENTS.md): pricing, the usage access filter and batch evidence. Usage is
// priced in SQL from the price snapshot taken when the call was authorized, with the exact
// formula the usage_is_priced_at_cost trigger enforces (00014): no floats and no markup
// (invariant 7). A call without usage is reported as unmetered, never estimated (invariant 8).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// UnmeteredAfter is how long an authorized model call may go without usage before it is reported
// as unmetered. The gateway exports access logs within seconds; the margin covers batching.
const UnmeteredAfter = 15 * time.Minute

// MaxTokens bounds each token count. Larger values come from a faulty upstream and would overflow
// the price arithmetic; they are refused before pricing, never let to fail a whole batch.
const MaxTokens = 1_000_000_000

// UsageLine is one usage record from the gateway's access-log export, already validated for
// shape by the ingest server. Model is the upstream model the gateway called.
type UsageLine struct {
	RequestID         uuid.UUID
	Model             string
	ResponseModel     string
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
	// UsageMissing marks a call the gateway reports as run but without usage (for example an
	// aborted stream). It is recorded in calls_without_usage, never priced, and its token
	// counts must be zero.
	UsageMissing bool
}

// UsageIngest counts what RecordUsage did with a batch.
type UsageIngest struct {
	Accepted    []uuid.UUID
	Duplicate   int // the same usage again: a no-op
	Conflicting int // a different usage for an already metered call: kept as first recorded
	Unmatched   int // no authorized model call with that id and model in this tenant
	// ConflictingIDs names the calls whose usage was reported differently again.
	ConflictingIDs []uuid.UUID
	// WithoutUsage are the calls newly recorded as run without a usage report.
	WithoutUsage []uuid.UUID
}

// ingestActor is the evidence actor for usage the gateway reported.
const ingestActor = "gateway:ingest"

// RecordUsage prices and records a batch of usage lines for one tenant, in one transaction with
// one signed gateway.usage.ingested event. If the evidence cannot be written nothing is recorded.
// The event carries a digest of every accepted line (id, tokens, cost), so moving tokens or cost
// between calls, and so between people and cost centres, is detectable from the chain.
func (s *Service) RecordUsage(ctx context.Context, tenant uuid.UUID, lines []UsageLine) (UsageIngest, error) {
	for _, l := range lines {
		if l.InputTokens < 0 || l.CachedInputTokens < 0 || l.OutputTokens < 0 || l.CachedInputTokens > l.InputTokens ||
			l.InputTokens > MaxTokens || l.OutputTokens > MaxTokens ||
			(l.UsageMissing && (l.InputTokens != 0 || l.CachedInputTokens != 0 || l.OutputTokens != 0)) {
			return UsageIngest{}, fmt.Errorf("usage line %s: invalid token counts: %w", l.RequestID, ErrInvalid)
		}
	}
	// A fixed order keeps overlapping batches (a retry beside its original) from deadlocking.
	lines = slices.Clone(lines)
	slices.SortFunc(lines, func(a, b UsageLine) int { return strings.Compare(a.RequestID.String(), b.RequestID.String()) })
	var out UsageIngest
	batch := uuid.New()
	err := s.db.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		out = UsageIngest{}
		for _, l := range lines {
			if l.UsageMissing {
				if err := recordWithoutUsage(ctx, tx, l, &out); err != nil {
					return err
				}
				continue
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
				AND response_model IS NOT DISTINCT FROM nullif($5, '')
				FROM usage_records WHERE request_id = $1`, l.RequestID, l.InputTokens, l.CachedInputTokens, l.OutputTokens, l.ResponseModel).Scan(&same)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
				out.Unmatched++
			case err != nil:
				return fmt.Errorf("check usage %s: %w", l.RequestID, err)
			case *same:
				out.Duplicate++
			default:
				out.Conflicting++
				out.ConflictingIDs = append(out.ConflictingIDs, l.RequestID)
			}
		}
		if len(out.Accepted) == 0 && len(out.WithoutUsage) == 0 {
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
		without := make([]string, len(out.WithoutUsage))
		for i, id := range out.WithoutUsage {
			without[i] = id.String()
		}
		digest, err := usageLinesDigest(ctx, tx, out.Accepted)
		if err != nil {
			return err
		}
		actor := Actor{Tenant: tenant, Name: ingestActor, RequestID: batch.String()}
		return recordEvidence(ctx, tx, s.signer, actor, "gateway.usage.ingested", "UsageBatch", batch.String(), nil,
			map[string]any{"requestIds": ids, "accepted": len(ids), "duplicate": out.Duplicate,
				"conflicting": out.Conflicting, "unmatched": out.Unmatched, "costAtProviderPrices": cost,
				"linesSha256": digest, "withoutUsage": without})
	})
	if err != nil {
		return UsageIngest{}, err
	}
	return out, nil
}

// recordWithoutUsage records an authorized model call that ran but reported no usage, once, and
// only for a model call in this tenant whose snapshot model matches. A call that already has
// usage is not counted. HUMAN REVIEW REQUIRED: these calls count toward the key's cap.
func recordWithoutUsage(ctx context.Context, tx pgx.Tx, l UsageLine, out *UsageIngest) error {
	tag, err := tx.Exec(ctx, `INSERT INTO calls_without_usage (tenant_id, request_id)
		SELECT c.tenant_id, c.request_id FROM gateway_calls c
		 WHERE c.request_id = $1 AND c.kind = 'model' AND c.model = $2
		   AND NOT EXISTS (SELECT 1 FROM usage_records u WHERE u.tenant_id = c.tenant_id AND u.request_id = c.request_id)
		ON CONFLICT (tenant_id, request_id) DO NOTHING`, l.RequestID, l.Model)
	if err != nil {
		return fmt.Errorf("record call without usage %s: %w", l.RequestID, err)
	}
	if tag.RowsAffected() == 1 {
		out.WithoutUsage = append(out.WithoutUsage, l.RequestID)
		return nil
	}
	var known bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM calls_without_usage WHERE request_id = $1)
		OR EXISTS (SELECT 1 FROM usage_records WHERE request_id = $1)`, l.RequestID).Scan(&known); err != nil {
		return fmt.Errorf("check call without usage %s: %w", l.RequestID, err)
	}
	if known {
		out.Duplicate++
	} else {
		out.Unmatched++
	}
	return nil
}

// usageLinesDigest is SHA-256 over the accepted lines as recorded, one per line in request id
// order: "request_id|input|cached|output|cost currency". Anyone holding the usage rows can
// recompute it and compare it with the signed evidence.
func usageLinesDigest(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (string, error) {
	rows, err := tx.Query(ctx, `SELECT request_id::text || '|' || input_tokens || '|' || cached_input_tokens || '|' ||
		output_tokens || '|' || cost_amount::text || ' ' || cost_currency
		FROM usage_records WHERE request_id = ANY($1) ORDER BY request_id::text`, ids)
	if err != nil {
		return "", fmt.Errorf("digest usage lines: %w", err)
	}
	recorded, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", fmt.Errorf("digest usage lines: %w", err)
	}
	sum := sha256.Sum256([]byte(strings.Join(recorded, "\n")))
	return hex.EncodeToString(sum[:]), nil
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
			       u.cost_amount::text, u.cost_currency, u.recorded_at,
			       EXISTS (SELECT 1 FROM calls_without_usage w WHERE w.tenant_id = c.tenant_id AND w.request_id = c.request_id)
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
			var missing bool
			if err := rows.Scan(&r.RequestId, &r.KeyId, &r.Instance, &r.Person, &r.CostCentre, &kind, &r.Alias,
				&r.Provider, &r.Model, &r.McpMethod, &r.McpTool, &r.AuthorizedAt,
				&metered, &in, &cached, &outTok, &amount, &currency, &r.RecordedAt, &missing); err != nil {
				return fmt.Errorf("scan usage: %w", err)
			}
			r.Kind = muistamov1.UsageRecordKind(kind)
			if r.Kind == muistamov1.UsageRecordKindModel {
				r.Metered = &metered
				if !metered {
					r.UsageMissing = &missing
				}
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

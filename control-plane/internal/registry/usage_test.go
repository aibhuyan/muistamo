package registry_test

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Usage metering at provider cost (step 5). HUMAN REVIEW REQUIRED: pricing and access.

// meteredFixture prices the fixture model like a real price sheet and authorizes one call.
func meteredFixture(t *testing.T) (fixture, muistamov1.VirtualKeyIssued, uuid.UUID) {
	t.Helper()
	f, req := gatewayFixture(t)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE model_catalogue SET document = jsonb_set(document, '{spec,priceSheet}',
		'{"currency": "EUR", "inputPerMTok": 2.80, "cachedInputPerMTok": 0.28, "outputPerMTok": 14.00}')`)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	return f, issued, authorize(t, f, issued)
}

func authorize(t *testing.T, f fixture, issued muistamov1.VirtualKeyIssued) uuid.UUID {
	t.Helper()
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, &route)
	if err != nil || !d.Allowed {
		t.Fatalf("authorize = %+v, %v", d, err)
	}
	return d.RequestId
}

func line(id uuid.UUID, in, cached, out int64) registry.UsageLine {
	return registry.UsageLine{RequestID: id, Model: "test-model", ResponseModel: "test-model", InputTokens: in, CachedInputTokens: cached, OutputTokens: out}
}

func TestUsageIsPricedExactlyFromTheAuthorizationSnapshot(t *testing.T) {
	f, _, id := meteredFixture(t)
	// A later price change never reprices an authorized call.
	testdb.Exec(t, f.db.OwnerURL, `UPDATE model_catalogue SET document = jsonb_set(document, '{spec,priceSheet,inputPerMTok}', '99')`)
	got, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 1000, 400, 250)})
	if err != nil || len(got.Accepted) != 1 {
		t.Fatalf("record = %+v, %v", got, err)
	}
	page, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list = %+v, %v", page, err)
	}
	r := page.Items[0]
	// (600 x 2.80 + 400 x 0.28 + 250 x 14.00) / 1,000,000 = 0.005292 EUR, exactly.
	if r.Metered == nil || !*r.Metered || r.Cost == nil || r.Cost.Amount != "0.005292" || r.Cost.Currency != "EUR" ||
		*r.InputTokens != 1000 || *r.CachedInputTokens != 400 || *r.OutputTokens != 250 {
		t.Fatalf("usage = %+v cost %+v", r, r.Cost)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action = 'gateway.usage.ingested'
		AND actor = 'gateway:ingest' AND after->'requestIds' ? $1 AND after->'costAtProviderPrices'->>'EUR' = '0.005292'`, id.String()); n != 1 {
		t.Fatalf("batch evidence = %d events, want 1", n)
	}
	// The signed digest binds each call to its tokens and cost: recomputable from the usage rows.
	line := id.String() + "|1000|400|250|0.005292000000 EUR"
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(line)))
	if got := testdb.Scalar(t, f.db.OwnerURL, `SELECT after->>'linesSha256' FROM evidence_events WHERE action = 'gateway.usage.ingested'`); got != want {
		t.Fatalf("lines digest = %s, want %s over %q", got, want, line)
	}
}

func TestUsageIngestRefusesLinesWithoutAnAuthorizedModelCall(t *testing.T) {
	f, issued, id := meteredFixture(t)
	mcp := uuid.New()
	// An MCP call is never metered, even one whose row names the same model.
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind, mcp_method, model)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp', 'tools/call', 'test-model')`, f.actor.Tenant, mcp, issued.Key.Id)
	wrongModel := line(id, 10, 0, 10)
	wrongModel.Model = "another-model"
	before := f.events(t)
	got, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(uuid.New(), 10, 0, 10), wrongModel, line(mcp, 10, 0, 10)})
	if err != nil || len(got.Accepted) != 0 || got.Unmatched != 3 {
		t.Fatalf("forged lines = %+v, %v; want all three unmatched", got, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM usage_records`); n != 0 || f.events(t) != before {
		t.Fatalf("forged lines recorded %d usage rows or wrote evidence", n)
	}
	for _, bad := range []registry.UsageLine{line(id, -1, 0, 1), line(id, 1, 0, -1), line(id, 1, 2, 1),
		line(id, registry.MaxTokens+1, 0, 1), line(id, 1, 0, registry.MaxTokens+1)} {
		if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{bad}); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("invalid counts %+v accepted: %v", bad, err)
		}
	}
}

func TestUsageIngestIsIdempotentAndKeepsTheFirstRecord(t *testing.T) {
	f, _, id := meteredFixture(t)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 1000, 0, 0)}); err != nil {
		t.Fatal(err)
	}
	before := f.events(t)
	otherModel := line(id, 1000, 0, 0)
	otherModel.ResponseModel = "another-response-model"
	got, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 1000, 0, 0), line(id, 5000, 0, 0), otherModel})
	if err != nil || len(got.Accepted) != 0 || got.Duplicate != 1 || got.Conflicting != 2 || len(got.ConflictingIDs) != 2 || f.events(t) != before {
		t.Fatalf("replayed usage = %+v, %v, evidence delta %d", got, err, f.events(t)-before)
	}
	if amount := testdb.Scalar(t, f.db.OwnerURL, `SELECT cost_amount::text FROM usage_records`); amount != "0.002800000000" {
		t.Fatalf("cost after a conflicting duplicate = %s, want the first record's", amount)
	}
}

func TestUsageWithoutEvidenceIsNotRecorded(t *testing.T) {
	f, _, id := meteredFixture(t)
	broken := registry.New(f.conn, failingSigner{f.key})
	if _, err := broken.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 10, 0, 10)}); !errors.Is(err, registry.ErrEvidence) {
		t.Fatalf("usage without evidence = %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM usage_records`); n != 0 {
		t.Fatalf("%d usage rows recorded without evidence", n)
	}
}

func TestUsageIsVisibleToAdministratorsAndToTheCallsOwnPersonOnly(t *testing.T) {
	f, _, id := meteredFixture(t)
	admin := registry.Actor{Tenant: f.actor.Tenant, Name: "dev:gw-admin@example.invalid", RequestID: "admin"}
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, f.actor, []string{admin.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	other := registry.Actor{Tenant: f.actor.Tenant, Name: "dev:person-b@example.invalid", RequestID: "other"}
	for name, c := range map[string]struct {
		actor registry.Actor
		want  int
	}{"administrator": {admin, 1}, "the call's person": {f.actor, 1}, "another person": {other, 0}} {
		page, err := f.svc.ListUsage(t.Context(), c.actor, registry.UsageFilter{})
		if err != nil || len(page.Items) != c.want || (c.want == 1 && page.Items[0].RequestId != id) {
			t.Errorf("%s sees %+v, %v; want %d calls", name, page.Items, err, c.want)
		}
	}
}

func TestUnmeteredCallsAreReportedAfterTheThreshold(t *testing.T) {
	f, issued, old := meteredFixture(t)
	metered := authorize(t, f, issued)
	fresh := authorize(t, f, issued)
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE gateway_calls DISABLE TRIGGER gateway_calls_stamp`)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE gateway_calls SET authorized_at = now() - interval '16 minutes' WHERE request_id = ANY($1)`, []uuid.UUID{old, metered})
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE gateway_calls ENABLE TRIGGER gateway_calls_stamp`)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(metered, 1, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	page, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{Unmetered: true})
	if err != nil || len(page.Items) != 1 || page.Items[0].RequestId != old || *page.Items[0].Metered {
		t.Fatalf("unmetered = %+v, %v; want only the old call without usage", page.Items, err)
	}
	all, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{})
	if err != nil || len(all.Items) != 3 {
		t.Fatalf("all calls = %+v, %v", all.Items, err)
	}
	for _, r := range all.Items {
		if r.RequestId == fresh && (r.Metered == nil || *r.Metered) {
			t.Errorf("fresh call without usage = %+v; want metered false, but not yet reported", r)
		}
	}
}

func TestRecordedSpendReachesTheBudgetCap(t *testing.T) {
	f, req := gatewayFixture(t)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE model_catalogue SET document = jsonb_set(document, '{spec,priceSheet}',
		'{"currency": "EUR", "inputPerMTok": 2.80, "outputPerMTok": 14.00}')`)
	req.MonthlyBudget.Amount = "0.005"
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	id := authorize(t, f, issued)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 1000, 0, 250)}); err != nil {
		t.Fatal(err)
	}
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, &route)
	if err != nil || d.Allowed {
		t.Fatalf("call after recorded spend 0.0063 passed a 0.005 budget: %+v, %v", d, err)
	}
}

func TestUsagePagesNewestFirstWithoutOverlap(t *testing.T) {
	f, issued, first := meteredFixture(t)
	time.Sleep(5 * time.Millisecond)
	second := authorize(t, f, issued)
	time.Sleep(5 * time.Millisecond)
	third := authorize(t, f, issued)
	p1, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{Limit: 2})
	if err != nil || len(p1.Items) != 2 || p1.Next == nil || p1.Items[0].RequestId != third || p1.Items[1].RequestId != second {
		t.Fatalf("page 1 = %+v, %v", p1, err)
	}
	p2, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{Limit: 2, Cursor: *p1.Next})
	if err != nil || len(p2.Items) != 1 || p2.Items[0].RequestId != first || p2.Next != nil {
		t.Fatalf("page 2 = %+v, %v", p2, err)
	}
	if _, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{Cursor: "not-a-cursor!"}); !errors.Is(err, registry.ErrInvalid) {
		t.Fatalf("bad cursor = %v", err)
	}
}

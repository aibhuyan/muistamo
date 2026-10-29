package registry_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Calls that ran without a usage report (aborted streams) cap a key (00016). HUMAN REVIEW REQUIRED.

func missing(id uuid.UUID) registry.UsageLine {
	return registry.UsageLine{RequestID: id, Model: "test-model", UsageMissing: true}
}

func keyWithAllowance(t *testing.T, f fixture, req muistamov1.VirtualKeyRequest, n *int) muistamov1.VirtualKeyIssued {
	t.Helper()
	req.MaxCallsWithoutUsage = n
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func allowed(t *testing.T, f fixture, issued muistamov1.VirtualKeyIssued) (bool, string) {
	t.Helper()
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, &route)
	if err != nil {
		t.Fatal(err)
	}
	return d.Allowed, string(d.Reason)
}

func TestCallsWithoutUsageAreRecordedOnceWithEvidence(t *testing.T) {
	f, issued, id := meteredFixture(t)
	got, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(id)})
	if err != nil || len(got.WithoutUsage) != 1 || len(got.Accepted) != 0 {
		t.Fatalf("record = %+v, %v", got, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action = 'gateway.usage.ingested'
		AND after->'withoutUsage' ? $1`, id.String()); n != 1 {
		t.Fatalf("evidence for the call without usage = %d events", n)
	}
	before := f.events(t)
	again, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(id)})
	if err != nil || len(again.WithoutUsage) != 0 || again.Duplicate != 1 || f.events(t) != before {
		t.Fatalf("repeat = %+v, %v", again, err)
	}
	page, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].UsageMissing == nil || !*page.Items[0].UsageMissing || *page.Items[0].Metered {
		t.Fatalf("listed = %+v, %v", page.Items, err)
	}
	// A line claiming tokens while missing usage is malformed.
	bad := missing(id)
	bad.OutputTokens = 1
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{bad}); !errors.Is(err, registry.ErrInvalid) {
		t.Fatalf("missing usage with tokens = %v", err)
	}
	// An unknown call, an MCP call and a model mismatch are never counted.
	mcp := uuid.New()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind, mcp_method, model)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp', 'tools/call', 'test-model')`, f.actor.Tenant, mcp, issued.Key.Id)
	other := missing(authorize(t, f, issued))
	other.Model = "another-model"
	got, err = f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(uuid.New()), missing(mcp), other})
	if err != nil || len(got.WithoutUsage) != 0 || got.Unmatched != 3 {
		t.Fatalf("forged missing-usage lines = %+v, %v", got, err)
	}
}

func TestCallsWithoutUsageBeyondTheAllowanceRefuseTheKey(t *testing.T) {
	one, zero := 1, 0
	for name, c := range map[string]struct {
		allowance *int
		tolerated int
	}{"default": {nil, registry.DefaultMaxCallsWithoutUsage}, "one": {&one, 1}, "zero": {&zero, 0}} {
		t.Run(name, func(t *testing.T) {
			f, req := gatewayFixture(t)
			issued := keyWithAllowance(t, f, req, c.allowance)
			for i := 0; i <= c.tolerated; i++ {
				if ok, reason := allowed(t, f, issued); !ok {
					t.Fatalf("call %d refused (%s) within an allowance of %d", i+1, reason, c.tolerated)
				}
				call := authorize(t, f, issued)
				if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(call)}); err != nil {
					t.Fatal(err)
				}
			}
			if ok, reason := allowed(t, f, issued); ok || reason != "calls-without-usage-limit" {
				t.Fatalf("after %d calls without usage: allowed %v, reason %q", c.tolerated+1, ok, reason)
			}
		})
	}
}

func TestOnlyThisKeysCallsStillMissingUsageInTheLastDayCount(t *testing.T) {
	f, req := gatewayFixture(t)
	zero := 0
	issued := keyWithAllowance(t, f, req, &zero)
	other := keyWithAllowance(t, f, req, &zero)

	// Another key's call without usage does not count against this key.
	theirs := authorize(t, f, other)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(theirs)}); err != nil {
		t.Fatal(err)
	}
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("another key's call blocked this key: %s", reason)
	}

	// A call without usage more than 24 hours ago no longer counts (rolling window).
	old := authorize(t, f, issued)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(old)}); err != nil {
		t.Fatal(err)
	}
	backdate(t, f, old, "25 hours")
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("a call without usage 25 hours ago blocked this key: %s", reason)
	}

	// A call whose usage arrives after all no longer counts.
	late := authorize(t, f, issued)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(late)}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := allowed(t, f, issued); ok {
		t.Fatal("a call without usage this month did not block an allowance of 0")
	}
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(late, 10, 0, 10)}); err != nil {
		t.Fatal(err)
	}
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("a call whose usage arrived still counts: %s", reason)
	}
}

func TestKeyAllowanceIsValidatedShownAndFixed(t *testing.T) {
	f, req := gatewayFixture(t)
	for _, n := range []int{-1, 1001} {
		bad := n
		req.MaxCallsWithoutUsage = &bad
		if _, err := f.svc.IssueKey(t.Context(), f.actor, req); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("allowance %d accepted: %v", n, err)
		}
	}
	two := 2
	issued := keyWithAllowance(t, f, req, &two)
	if issued.Key.MaxCallsWithoutUsage != 2 {
		t.Fatalf("issued key allowance = %d", issued.Key.MaxCallsWithoutUsage)
	}
	if key, err := f.svc.GetKey(t.Context(), f.actor, issued.Key.Id); err != nil || key.MaxCallsWithoutUsage != 2 {
		t.Fatalf("read key = %+v, %v", key, err)
	}
	// The documented default (contract and 00016) is 10, in the service and in the column.
	def := keyWithAllowance(t, f, req, nil)
	if def.Key.MaxCallsWithoutUsage != 10 || registry.DefaultMaxCallsWithoutUsage != 10 {
		t.Fatalf("default allowance = %d", def.Key.MaxCallsWithoutUsage)
	}
	if d := testdb.Scalar(t, f.db.OwnerURL, `SELECT column_default FROM information_schema.columns
		WHERE table_name = 'virtual_keys' AND column_name = 'max_calls_without_usage'`); d != "10" {
		t.Fatalf("column default = %q, want 10", d)
	}
	err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `UPDATE virtual_keys SET max_calls_without_usage = 1000 WHERE id = $1`, issued.Key.Id)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the server role raised a key's allowance: %v", err)
	}
}

func backdate(t *testing.T, f fixture, id uuid.UUID, ago string) {
	t.Helper()
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE gateway_calls DISABLE TRIGGER gateway_calls_stamp`)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE gateway_calls SET authorized_at = now() - $2::interval WHERE request_id = $1`, id, ago)
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE gateway_calls ENABLE TRIGGER gateway_calls_stamp`)
	// The call's open row and any missing-usage report age with it.
	testdb.Exec(t, f.db.OwnerURL, `UPDATE open_calls SET authorized_at = now() - $2::interval WHERE request_id = $1`, id, ago)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE calls_without_usage SET recorded_at = now() - $2::interval WHERE request_id = $1`, id, ago)
}

// A call still unaccounted 15 minutes after authorization (its export was lost or refused) counts
// like one reported without usage, so the cap fails closed; a fresh one is still in flight.
func TestUnaccountedCallsCountAfterTheThreshold(t *testing.T) {
	f, req := gatewayFixture(t)
	zero := 0
	issued := keyWithAllowance(t, f, req, &zero)
	// An old MCP call carries no tokens and never counts.
	mcp := uuid.New()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind, mcp_method)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp', 'tools/call')`, f.actor.Tenant, mcp, issued.Key.Id)
	backdate(t, f, mcp, "16 minutes")
	fresh := authorize(t, f, issued)
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("a call still in flight, or an MCP call, blocked the key: %s", reason)
	}
	backdate(t, f, fresh, "16 minutes")
	if ok, reason := allowed(t, f, issued); ok || reason != "calls-without-usage-limit" {
		t.Fatalf("a call unaccounted after 16 minutes: allowed %v, reason %q", ok, reason)
	}
	// Its usage arriving late clears it.
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(fresh, 1, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("a metered call still counts: %s", reason)
	}
}

// A call already metered and then reported without usage is contradictory: kept as metered,
// counted as a conflict, never counted against the cap.
func TestAMissingUsageReportForAMeteredCallIsAConflict(t *testing.T) {
	f, issued, id := meteredFixture(t)
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 10, 0, 10)}); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{missing(id)})
	if err != nil || got.Conflicting != 1 || len(got.WithoutUsage) != 0 {
		t.Fatalf("missing usage after usage = %+v, %v", got, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM calls_without_usage`); n != 0 {
		t.Fatalf("a metered call was recorded as without usage")
	}
	_ = issued
}

// The database itself refuses to count an MCP call as having run without usage.
func TestOnlyModelCallsCanBeRecordedWithoutUsage(t *testing.T) {
	f, issued, _ := meteredFixture(t)
	mcp := uuid.New()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind, mcp_method)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp', 'tools/call')`, f.actor.Tenant, mcp, issued.Key.Id)
	err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `INSERT INTO calls_without_usage (tenant_id, request_id) VALUES ($1, $2)`, f.actor.Tenant, mcp)
	if err == nil || !strings.Contains(err.Error(), "are model calls") {
		t.Fatalf("an MCP call was recorded without usage: %v", err)
	}
}

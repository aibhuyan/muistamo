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

// Per-key rate limits (FR-702, 00017). HUMAN REVIEW REQUIRED.

func keyWithLimits(t *testing.T, f fixture, req muistamov1.VirtualKeyRequest, perMinute, inFlight int) muistamov1.VirtualKeyIssued {
	t.Helper()
	req.MaxRequestsPerMinute, req.MaxCallsInFlight = &perMinute, &inFlight
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func settle(t *testing.T, f fixture, id uuid.UUID) {
	t.Helper()
	if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{line(id, 1, 0, 1)}); err != nil {
		t.Fatal(err)
	}
}

func TestRequestsPerMinuteAreLimitedPerKey(t *testing.T) {
	f, req := gatewayFixture(t)
	issued := keyWithLimits(t, f, req, 2, 100)
	other := keyWithLimits(t, f, req, 2, 100)
	for i := 0; i < 2; i++ {
		settle(t, f, authorize(t, f, issued))
	}
	if ok, reason := allowed(t, f, issued); ok || reason != "rate-limited" {
		t.Fatalf("third call within a minute: allowed %v, reason %q", ok, reason)
	}
	// Another key's calls do not count.
	if ok, reason := allowed(t, f, other); !ok {
		t.Fatalf("another key was rate limited: %s", reason)
	}
	// Calls older than the rolling minute free capacity.
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE gateway_calls DISABLE TRIGGER gateway_calls_stamp`)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE gateway_calls SET authorized_at = now() - interval '61 seconds' WHERE key_id = $1`, issued.Key.Id)
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE gateway_calls ENABLE TRIGGER gateway_calls_stamp`)
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("calls older than a minute still limit the key: %s", reason)
	}
}

func TestCallsInFlightAreLimitedUntilIngestSettlesThem(t *testing.T) {
	f, req := gatewayFixture(t)
	issued := keyWithLimits(t, f, req, 6000, 3)
	for range 3 {
		authorize(t, f, issued)
	}
	if ok, reason := allowed(t, f, issued); ok || reason != "too-many-in-flight" {
		t.Fatalf("fourth call with three in flight: allowed %v, reason %q", ok, reason)
	}
}

// Usage, a missing-usage report or a failure each settle a call and free its capacity.
func TestEachIngestOutcomeSettlesACallInFlight(t *testing.T) {
	for name, settleWith := range map[string]func(uuid.UUID) registry.UsageLine{
		"usage":         func(id uuid.UUID) registry.UsageLine { return line(id, 1, 0, 1) },
		"missing usage": missing,
		"failure": func(id uuid.UUID) registry.UsageLine {
			return registry.UsageLine{RequestID: id, Model: "test-model", FailedStatus: 503}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, req := gatewayFixture(t)
			issued := keyWithLimits(t, f, req, 6000, 1)
			pending := authorize(t, f, issued)
			if ok, _ := allowed(t, f, issued); ok {
				t.Fatal("a second call with one in flight was allowed")
			}
			if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{settleWith(pending)}); err != nil {
				t.Fatal(err)
			}
			if ok, reason := allowed(t, f, issued); !ok {
				t.Fatalf("settling with %s did not free capacity: %s", name, reason)
			}
		})
	}
}

func TestCallsUnsettledAfterTheThresholdLeaveTheInFlightCount(t *testing.T) {
	f, req := gatewayFixture(t)
	issued := keyWithLimits(t, f, req, 6000, 1)
	stale := authorize(t, f, issued)
	if ok, _ := allowed(t, f, issued); ok {
		t.Fatal("a second call with one in flight was allowed")
	}
	backdate(t, f, stale, "16 minutes")
	// The stale call now belongs to the calls-without-usage cap (allowance 10), not in flight.
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("a call unsettled after 16 minutes still counts as in flight: %s", reason)
	}
}

func TestFailedCallsAreRecordedAndNeverCountAsUnaccounted(t *testing.T) {
	f, req := gatewayFixture(t)
	zero := 0
	req.MaxCallsWithoutUsage = &zero
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	id := authorize(t, f, issued)
	got, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{{RequestID: id, Model: "test-model", FailedStatus: 500}})
	if err != nil || len(got.Failed) != 1 {
		t.Fatalf("record = %+v, %v", got, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action = 'gateway.usage.ingested' AND after->'failed' ? $1`, id.String()); n != 1 {
		t.Fatalf("failed-call evidence = %d events", n)
	}
	// Regression for #35: an explicit failure older than 15 minutes is not "unaccounted".
	backdate(t, f, id, "16 minutes")
	if ok, reason := allowed(t, f, issued); !ok {
		t.Fatalf("a failed call counted against an allowance of 0: %s", reason)
	}
	page, err := f.svc.ListUsage(t.Context(), f.actor, registry.UsageFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range page.Items {
		if r.RequestId == id && (r.FailedStatus == nil || *r.FailedStatus != 500 || r.Cost != nil) {
			t.Fatalf("listed failed call = %+v", r)
		}
	}
	// Repeated, contradictory, malformed and forged failure reports.
	if again, _ := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{{RequestID: id, Model: "test-model", FailedStatus: 500}}); again.Duplicate != 1 {
		t.Fatalf("repeat = %+v", again)
	}
	metered := authorize(t, f, issued)
	settle(t, f, metered)
	if c, _ := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{{RequestID: metered, Model: "test-model", FailedStatus: 502}}); c.Conflicting != 1 {
		t.Fatalf("failure for a metered call = %+v", c)
	}
	for _, status := range []int{200, 399, 600} {
		if _, err := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{{RequestID: id, Model: "test-model", FailedStatus: status}}); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("failure status %d accepted: %v", status, err)
		}
	}
	other := authorize(t, f, issued)
	if u, _ := f.svc.RecordUsage(t.Context(), f.actor.Tenant, []registry.UsageLine{{RequestID: uuid.New(), Model: "test-model", FailedStatus: 500},
		{RequestID: other, Model: "another-model", FailedStatus: 500}}); u.Unmatched != 2 {
		t.Fatalf("forged failures = %+v", u)
	}
}

func TestOnlyModelCallsCanBeRecordedAsFailed(t *testing.T) {
	f, issued, _ := meteredFixture(t)
	mcp := uuid.New()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind, mcp_method)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp', 'tools/call')`, f.actor.Tenant, mcp, issued.Key.Id)
	err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `INSERT INTO failed_calls (tenant_id, request_id, status_code) VALUES ($1, $2, 500)`, f.actor.Tenant, mcp)
	if err == nil || !strings.Contains(err.Error(), "are model calls") {
		t.Fatalf("an MCP call was recorded as failed: %v", err)
	}
}

func TestRateLimitsAreValidatedShownAndFixed(t *testing.T) {
	f, req := gatewayFixture(t)
	for _, c := range [][2]int{{0, 4}, {6001, 4}, {60, 0}, {60, 101}} {
		if _, err := f.svc.IssueKey(t.Context(), f.actor, withLimits(req, c[0], c[1])); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("limits %v accepted: %v", c, err)
		}
	}
	issued := keyWithLimits(t, f, req, 120, 8)
	if k, err := f.svc.GetKey(t.Context(), f.actor, issued.Key.Id); err != nil || k.MaxRequestsPerMinute != 120 || k.MaxCallsInFlight != 8 {
		t.Fatalf("read key = %+v, %v", k, err)
	}
	req.MaxRequestsPerMinute, req.MaxCallsInFlight = nil, nil
	def, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil || def.Key.MaxRequestsPerMinute != 60 || def.Key.MaxCallsInFlight != 4 {
		t.Fatalf("default limits = %+v, %v", def.Key, err)
	}
	for col, want := range map[string]string{"max_requests_per_minute": "60", "max_calls_in_flight": "4"} {
		if d := testdb.Scalar(t, f.db.OwnerURL, `SELECT column_default FROM information_schema.columns
			WHERE table_name = 'virtual_keys' AND column_name = $1`, col); d != want {
			t.Errorf("%s default = %q, want %s", col, d, want)
		}
		err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `UPDATE virtual_keys SET `+col+` = 100 WHERE id = $1`, issued.Key.Id)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("the server role raised %s: %v", col, err)
		}
	}
}

func withLimits(req muistamov1.VirtualKeyRequest, perMinute, inFlight int) muistamov1.VirtualKeyRequest {
	req.MaxRequestsPerMinute, req.MaxCallsInFlight = &perMinute, &inFlight
	return req
}

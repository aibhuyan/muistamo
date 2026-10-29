package main

import (
	"strings"
	"testing"
	"time"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// A call without usage is pending until the server's 15-minute threshold, then unmetered with an
// honest cost statement: unknown, and possibly incurred.
func TestUsageLineSaysPendingThenUnmetered(t *testing.T) {
	now := time.Now()
	no := false
	fresh := muistamov1.UsageRecord{AuthorizedAt: now.Add(-2 * time.Second), Kind: "model", Metered: &no}
	old := muistamov1.UsageRecord{AuthorizedAt: now.Add(-16 * time.Minute), Kind: "model", Metered: &no}
	if got := usageLine(fresh, now); !strings.Contains(got, "pending") {
		t.Errorf("fresh call = %q, want pending", got)
	}
	if got := usageLine(old, now); !strings.Contains(got, "unmetered: cost unknown, may have been incurred") {
		t.Errorf("old call = %q, want an honest unmetered statement", got)
	}
}

func TestUsageLineSaysWhenACallRanWithoutUsage(t *testing.T) {
	no, yes := false, true
	r := muistamov1.UsageRecord{AuthorizedAt: time.Now(), Kind: "model", Metered: &no, UsageMissing: &yes}
	if got := usageLine(r, time.Now()); !strings.Contains(got, "ran, no usage reported: cost unknown, likely incurred") {
		t.Errorf("aborted call = %q", got)
	}
}

func TestUsageLineSaysWhenACallFailed(t *testing.T) {
	no, status := false, 503
	r := muistamov1.UsageRecord{AuthorizedAt: time.Now(), Kind: "model", Metered: &no, FailedStatus: &status}
	if got := usageLine(r, time.Now()); !strings.Contains(got, "failed (HTTP 503): no cost") {
		t.Errorf("failed call = %q", got)
	}
}

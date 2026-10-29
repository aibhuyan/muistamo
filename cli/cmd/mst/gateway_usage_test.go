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

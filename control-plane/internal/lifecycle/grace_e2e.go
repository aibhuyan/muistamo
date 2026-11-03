//go:build e2e

package lifecycle

// HUMAN REVIEW REQUIRED (AGENTS.md): this file exists only in test builds (`go build -tags e2e`),
// so the separate-binary end-to-end run can watch a leaver's grace period end. Every other build
// has the constant 30 days (grace.go), with no setting to change it.

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// GracePeriod is MUISTAMO_E2E_GRACE_SECONDS, which an e2e build requires.
var GracePeriod = func() time.Duration {
	seconds, err := strconv.Atoi(os.Getenv("MUISTAMO_E2E_GRACE_SECONDS"))
	if err != nil || seconds < 1 {
		panic("e2e build: MUISTAMO_E2E_GRACE_SECONDS must be a positive number of seconds")
	}
	fmt.Fprintf(os.Stderr, "E2E BUILD: the leaver grace period is %ds; never deploy this binary\n", seconds)
	return time.Duration(seconds) * time.Second
}()

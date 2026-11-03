//go:build !e2e

package lifecycle

import "time"

// GracePeriod is how long a leaver's instances stay suspended before retirement.
const GracePeriod = 30 * 24 * time.Hour

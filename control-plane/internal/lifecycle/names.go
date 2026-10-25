package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const maxName = 63

// InstanceName derives a valid object name (lower-case, digits, hyphens, at most 63 characters)
// from a template name, an HR person id and an attempt number. Attempt 1 has no suffix; later
// attempts are used when an earlier instance for the same person is already retired.
func InstanceName(template, personID string, attempt int) string {
	base := sanitise(template + "-" + personID)
	suffix := ""
	if attempt > 1 {
		suffix = "-r" + string(rune('0'+attempt))
	}
	if len(base)+len(suffix) <= maxName {
		return base + suffix
	}
	sum := sha256.Sum256([]byte(template + "\x00" + personID))
	tag := "-" + hex.EncodeToString(sum[:4])
	keep := maxName - len(tag) - len(suffix)
	return strings.TrimRight(base[:keep], "-") + tag + suffix
}

func sanitise(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		switch {
		case ok:
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if out == "" {
		return "instance"
	}
	return out
}

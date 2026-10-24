// Package version reports the mst build version.
package version

// Version is overridden at build time with -ldflags "-X muistamo.dev/muistamo/cli/internal/version.Version=...".
var Version = "dev"

// String returns the line printed by `mst version`.
func String() string {
	return "mst " + Version
}

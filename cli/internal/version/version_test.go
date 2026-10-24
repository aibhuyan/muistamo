package version

import "testing"

func TestString(t *testing.T) {
	if got, want := String(), "mst dev"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

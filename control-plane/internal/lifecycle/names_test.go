package lifecycle

import (
	"regexp"
	"strings"
	"testing"
)

var validName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func TestInstanceNamesAreValidAndStable(t *testing.T) {
	cases := []struct{ template, person string }{
		{"analyst-intern", "E-1001"},
		{"analyst-intern", "person.with+odd@chars"},
		{"analyst-intern", strings.Repeat("x", 120)},
		{"--", "__"},
	}
	for _, c := range cases {
		for attempt := 1; attempt <= 3; attempt++ {
			name := InstanceName(c.template, c.person, attempt)
			if !validName.MatchString(name) {
				t.Errorf("InstanceName(%q, %q, %d) = %q, not a valid object name", c.template, c.person, attempt, name)
			}
			if InstanceName(c.template, c.person, attempt) != name {
				t.Errorf("InstanceName is not deterministic for %q", c.person)
			}
		}
	}
	if InstanceName("analyst-intern", "E-1001", 1) != "analyst-intern-e-1001" {
		t.Fatalf("got %q", InstanceName("analyst-intern", "E-1001", 1))
	}
	long1 := InstanceName("t", strings.Repeat("a", 100)+"1", 1)
	long2 := InstanceName("t", strings.Repeat("a", 100)+"2", 1)
	if long1 == long2 {
		t.Fatal("truncated names for different people collide")
	}
}

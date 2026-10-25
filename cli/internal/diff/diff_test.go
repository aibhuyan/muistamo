package diff

import (
	"strings"
	"testing"
)

func TestJSONReportsFieldChanges(t *testing.T) {
	before := `{"spec":{"purpose":"first","tools":["a","b"],"riskTier":"low"}}`
	after := `{"spec":{"purpose":"second","tools":["a","c"],"autonomy":"read-only"}}`

	changes, err := JSON([]byte(before), []byte(after))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, c := range changes {
		lines = append(lines, c.String())
	}
	got := strings.Join(lines, "\n")
	want := strings.Join([]string{
		`+ spec.autonomy: "read-only"`,
		`~ spec.purpose: "first" -> "second"`,
		`- spec.riskTier: "low"`,
		`~ spec.tools[1]: "b" -> "c"`,
	}, "\n")
	if got != want {
		t.Fatalf("diff:\n%s\nwant:\n%s", got, want)
	}
}

func TestJSONIdenticalDocumentsHaveNoChanges(t *testing.T) {
	doc := []byte(`{"a":{"b":[1,2]}}`)
	changes, err := JSON(doc, doc)
	if err != nil || len(changes) != 0 {
		t.Fatalf("changes = %v, err = %v; want none", changes, err)
	}
}

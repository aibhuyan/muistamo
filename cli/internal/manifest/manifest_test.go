package manifest

import (
	"os"
	"strings"
	"testing"
)

func TestReadValidatesEveryDocument(t *testing.T) {
	template, err := os.ReadFile("../../../contracts/examples/agenttemplate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	instance, err := os.ReadFile("../../../contracts/examples/agentinstance.yaml")
	if err != nil {
		t.Fatal(err)
	}

	docs, err := Read([]byte(string(template) + "---\n" + string(instance)))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 2 || docs[0].Kind != "AgentTemplate" || docs[1].Name != "analyst-intern-person-a" {
		t.Fatalf("docs = %+v", docs)
	}

	bad := strings.Replace(string(template), "purpose:", "surprise: true\n  purpose:", 1)
	if _, err := Read([]byte(string(instance) + "---\n" + bad)); err == nil || !strings.Contains(err.Error(), "document 2") {
		t.Fatalf("err = %v, want document 2 rejected and nothing returned", err)
	}
}

package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// The Python side runs the same examples through the generated Pydantic models
// (contracts/tests/test_examples.py), so both languages are held to one contract.
func TestExamplesValidateAgainstGeneratedTypes(t *testing.T) {
	paths, err := filepath.Glob("examples/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no examples found: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if err := decodeExample(t, path, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUnknownFieldIsRejected(t *testing.T) {
	err := decodeExample(t, "examples/knowledgepack.yaml", func(doc map[string]any) {
		doc["spec"].(map[string]any)["unexpected"] = true
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("err = %v, want rejection of unexpected field", err)
	}
}

func TestUnknownEnumValueIsRejected(t *testing.T) {
	err := decodeExample(t, "examples/knowledgepack.yaml", func(doc map[string]any) {
		doc["spec"].(map[string]any)["layer"] = "galaxy"
	})
	if err == nil || !strings.Contains(err.Error(), "/spec/layer") {
		t.Fatalf("err = %v, want rejection of unknown layer", err)
	}
}

func TestUnknownKindIsRejected(t *testing.T) {
	if err := contracts.Validate([]byte(`{"kind":"Nope"}`)); err == nil {
		t.Fatal("want rejection of unknown kind")
	}
}

// decodeExample validates the document against its schema, then decodes it into the
// generated type, the order production code must follow.
func decodeExample(t *testing.T, path string, mutate func(map[string]any)) error {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if mutate != nil {
		mutate(doc)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encode %s: %v", path, err)
	}
	if err := contracts.Validate(body); err != nil {
		return err
	}

	var target json.Unmarshaler
	switch kind := doc["kind"]; kind {
	case "AgentTemplate":
		target = &muistamov1.AgentTemplate{}
	case "AgentInstance":
		target = &muistamov1.AgentInstance{}
	case "KnowledgePack":
		target = &muistamov1.KnowledgePack{}
	default:
		t.Fatalf("%s: unknown kind %v", path, kind)
	}
	return target.UnmarshalJSON(body)
}

// Package contracts validates documents against the JSON Schemas in contracts/schemas.
//
// The generated types in gen/go/muistamov1 check required fields, enums, constants and
// patterns, but not additionalProperties: false. Validate first, then decode into the
// generated types, so Go rejects exactly what the Python models reject.
package contracts

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schemas
var schemaFS embed.FS

const baseURL = "https://muistamo.dev/schemas/v1/"

// kinds maps each YAML kind to its schema file under schemas/.
var kinds = map[string]string{
	"AgentTemplate": "agenttemplate.json",
	"AgentInstance": "agentinstance.json",
	"KnowledgePack": "knowledgepack.json",
}

var compiled = mustCompile()

// Validate checks a JSON document against the schema for its kind.
func Validate(document []byte) error {
	var envelope struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	schema, ok := compiled[envelope.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", envelope.Kind)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("decode %s: %w", envelope.Kind, err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("validate %s: %w", envelope.Kind, err)
	}
	return nil
}

func mustCompile() map[string]*jsonschema.Schema {
	compiler := jsonschema.NewCompiler()
	err := fs.WalkDir(schemaFS, "schemas", func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := schemaFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		return compiler.AddResource(baseURL+strings.TrimPrefix(path, "schemas/"), doc)
	})
	if err != nil {
		panic(fmt.Errorf("load contract schemas: %w", err))
	}

	out := make(map[string]*jsonschema.Schema, len(kinds))
	for kind, file := range kinds {
		schema, err := compiler.Compile(baseURL + file)
		if err != nil {
			panic(fmt.Errorf("compile %s schema: %w", kind, err))
		}
		out[kind] = schema
	}
	return out
}

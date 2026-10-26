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
	"AgentTemplate":      "agenttemplate.json",
	"AgentInstance":      "agentinstance.json",
	"KnowledgePack":      "knowledgepack.json",
	"KnowledgeSource":    "knowledgesource.json",
	"AgentLink":          "agentlink.json",
	"ActionPolicy":       "actionpolicy.json",
	"AgentClone":         "agentclone.json",
	"ModelCatalogueItem": "modelcatalogueitem.json",
	"ModelAlias":         "modelalias.json",
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
	file, ok := kinds[envelope.Kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", envelope.Kind)
	}
	return ValidateAgainst(file, document)
}

// ValidateAgainst checks a JSON document against one schema file, named relative to
// contracts/schemas (for example "instancetransition.json").
func ValidateAgainst(file string, document []byte) error {
	schema, ok := compiled[file]
	if !ok {
		return fmt.Errorf("unknown schema %q", file)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(document))
	if err != nil {
		return fmt.Errorf("decode document: %w", err)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("validate against %s: %w", file, err)
	}
	return nil
}

func mustCompile() map[string]*jsonschema.Schema {
	compiler := jsonschema.NewCompiler()
	var files []string
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
		file := strings.TrimPrefix(path, "schemas/")
		files = append(files, file)
		return compiler.AddResource(baseURL+file, doc)
	})
	if err != nil {
		panic(fmt.Errorf("load contract schemas: %w", err))
	}

	out := make(map[string]*jsonschema.Schema, len(files))
	for _, file := range files {
		schema, err := compiler.Compile(baseURL + file)
		if err != nil {
			panic(fmt.Errorf("compile schema %s: %w", file, err))
		}
		out[file] = schema
	}
	return out
}

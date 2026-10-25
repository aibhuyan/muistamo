// Package manifest reads Muistamo YAML manifests and validates them against contracts/.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/goccy/go-yaml"

	"muistamo.dev/muistamo/contracts"
)

// Document is one validated manifest.
type Document struct {
	Kind string
	Name string
	// JSON is the document exactly as the server will receive it.
	JSON []byte
}

// Read parses every YAML document in src (separated by ---) and validates each against its
// kind's schema. Nothing is returned unless every document is valid.
func Read(src []byte) ([]Document, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(src))
	var docs []Document
	for i := 1; ; i++ {
		var raw map[string]any
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: parse YAML: %w", i, err)
		}
		if raw == nil {
			continue
		}
		body, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("document %d: encode JSON: %w", i, err)
		}
		if err := contracts.Validate(body); err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		var head struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &head); err != nil {
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		docs = append(docs, Document{Kind: head.Kind, Name: head.Metadata.Name, JSON: body})
	}
	if len(docs) == 0 {
		return nil, errors.New("no documents found")
	}
	return docs, nil
}

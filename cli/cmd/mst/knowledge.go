package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/cli/internal/manifest"
)

// knowledgeCall sends a request to the knowledge service with the development identity headers.
// Bodies are contract-validated documents (manifest.Read), sent exactly as validated.
func (o *options) knowledgeCall(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if o.tenant == "" || o.actor == "" {
		return 0, nil, fmt.Errorf("no tenant or actor: pass --tenant and --actor (MST_TENANT, MST_ACTOR)")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(o.knowledgeServer, "/")+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Muistamo-Tenant", o.tenant)
	req.Header.Set("X-Muistamo-Actor", o.actor)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	return res.StatusCode, out, err
}

// knowledgeKinds maps the kinds the knowledge service owns to their collection paths.
var knowledgeKinds = map[string]string{
	"KnowledgePack":   "/v1/knowledge/packs/",
	"KnowledgeSource": "/v1/knowledge/sources/",
}

func isKnowledgeKind(kind string) bool { _, ok := knowledgeKinds[kind]; return ok }

func applyKnowledge(cmd *cobra.Command, opts *options, doc manifest.Document) error {
	if doc.Kind == "KnowledgeSource" {
		return applySource(cmd, opts, doc)
	}
	status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodPut, knowledgeKinds[doc.Kind]+url.PathEscape(doc.Name), doc.JSON)
	if err != nil {
		return err
	}
	var rec struct {
		LatestVersion string `json:"latestVersion"`
	}
	switch status {
	case http.StatusCreated:
		_ = json.Unmarshal(body, &rec)
		cmd.Printf("%s/%s: created (content version %s; content changes only through proposals)\n", doc.Kind, doc.Name, rec.LatestVersion)
	case http.StatusOK:
		_ = json.Unmarshal(body, &rec)
		cmd.Printf("%s/%s: applied (content version %s)\n", doc.Kind, doc.Name, rec.LatestVersion)
	default:
		return problem(status, body)
	}
	return nil
}

func applySource(cmd *cobra.Command, opts *options, doc manifest.Document) error {
	status, body, err := opts.knowledgeCall(cmd.Context(), http.MethodPut, knowledgeKinds[doc.Kind]+url.PathEscape(doc.Name), doc.JSON)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusCreated:
		cmd.Printf("%s/%s: created (run a sync to index it)\n", doc.Kind, doc.Name)
	case http.StatusOK:
		cmd.Printf("%s/%s: applied\n", doc.Kind, doc.Name)
	default:
		return problem(status, body)
	}
	return nil
}

func fetchKnowledge(ctx context.Context, opts *options, doc manifest.Document) ([]byte, error) {
	status, body, err := opts.knowledgeCall(ctx, http.MethodGet, knowledgeKinds[doc.Kind]+url.PathEscape(doc.Name), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, problem(status, body)
	}
	var rec struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, fmt.Errorf("decode pack: %w", err)
	}
	return rec.Document, nil
}

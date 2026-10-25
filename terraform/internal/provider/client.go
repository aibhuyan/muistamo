package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// errNotFound means the object does not exist on the server.
var errNotFound = errors.New("not found")

// client calls the control plane and the knowledge service. Until real authentication exists it
// sends the development identity headers, which the services accept only when started with
// MUISTAMO_INSECURE_DEV_TENANT_HEADER=true.
type client struct {
	controlPlane, knowledge string
	tenant, actor           string
	http                    *http.Client
}

func newClient(controlPlane, knowledge, tenant, actor string) *client {
	return &client{
		controlPlane: strings.TrimRight(controlPlane, "/"),
		knowledge:    strings.TrimRight(knowledge, "/"),
		tenant:       tenant,
		actor:        actor,
		http:         &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *client) do(ctx context.Context, method, base, path string, body []byte) (int, []byte, error) {
	if base == "" {
		return 0, nil, fmt.Errorf("no service URL configured for %s", path)
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Muistamo-Tenant", c.tenant)
	req.Header.Set("X-Muistamo-Actor", c.actor)
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	out, err := io.ReadAll(res.Body)
	return res.StatusCode, out, err
}

// apiError turns an RFC 9457 problem response into an error.
func apiError(status int, body []byte) error {
	if status == http.StatusNotFound {
		return errNotFound
	}
	var p struct {
		Title  string  `json:"title"`
		Detail *string `json:"detail"`
	}
	if err := json.Unmarshal(body, &p); err != nil || p.Title == "" {
		return fmt.Errorf("server returned %d", status)
	}
	if p.Detail != nil {
		return fmt.Errorf("%d %s: %s", status, p.Title, *p.Detail)
	}
	return fmt.Errorf("%d %s", status, p.Title)
}

// kind describes how one resource type is stored.
type kind struct {
	name       string // YAML kind, e.g. AgentTemplate
	service    func(*client) string
	collection string // e.g. /v1/templates/
	// document extracts the stored YAML document from a GET or PUT response body.
	document func(body []byte) (json.RawMessage, error)
	// version extracts the computed version, or "" when the kind has none.
	version func(body []byte) string
	// deletable kinds are deleted on destroy: keeping them would keep granting what they allow.
	// Others are history the product keeps, and destroy only forgets them.
	deletable bool
}

func (c *client) put(ctx context.Context, k kind, name string, doc []byte) ([]byte, error) {
	status, body, err := c.do(ctx, http.MethodPut, k.service(c), k.collection+url.PathEscape(name), doc)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, apiError(status, body)
	}
	return body, nil
}

func (c *client) get(ctx context.Context, k kind, name string) ([]byte, error) {
	status, body, err := c.do(ctx, http.MethodGet, k.service(c), k.collection+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiError(status, body)
	}
	return body, nil
}

// delete removes an object. One that is already gone counts as deleted.
func (c *client) delete(ctx context.Context, k kind, name string) error {
	status, body, err := c.do(ctx, http.MethodDelete, k.service(c), k.collection+url.PathEscape(name), nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return apiError(status, body)
	}
	return nil
}

func recordDocument(body []byte) (json.RawMessage, error) {
	var rec struct {
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(body, &rec); err != nil || len(rec.Document) == 0 {
		return nil, fmt.Errorf("unexpected response: %w", err)
	}
	return rec.Document, nil
}

var (
	templateKind = kind{
		name:       "AgentTemplate",
		service:    func(c *client) string { return c.controlPlane },
		collection: "/v1/templates/",
		document:   recordDocument,
		version: func(body []byte) string {
			var rec struct {
				Version int `json:"version"`
			}
			_ = json.Unmarshal(body, &rec)
			if rec.Version == 0 {
				return ""
			}
			return fmt.Sprint(rec.Version)
		},
	}
	packKind = kind{
		name:       "KnowledgePack",
		service:    func(c *client) string { return c.knowledge },
		collection: "/v1/knowledge/packs/",
		document:   recordDocument,
		version: func(body []byte) string {
			var rec struct {
				LatestVersion string `json:"latestVersion"`
			}
			_ = json.Unmarshal(body, &rec)
			return rec.LatestVersion
		},
	}
	sourceKind = kind{
		name:       "KnowledgeSource",
		service:    func(c *client) string { return c.knowledge },
		collection: "/v1/knowledge/sources/",
		document:   recordDocument,
		version:    func([]byte) string { return "" },
	}
	linkKind = kind{
		name:       "AgentLink",
		service:    func(c *client) string { return c.controlPlane },
		collection: "/v1/links/",
		document:   recordDocument,
		version:    revision,
		deletable:  true,
	}
	actionPolicyKind = kind{
		name:       "ActionPolicy",
		service:    func(c *client) string { return c.controlPlane },
		collection: "/v1/action-policies/",
		document:   recordDocument,
		version:    revision,
		deletable:  true,
	}
)

func revision(body []byte) string {
	var rec struct {
		Revision int `json:"revision"`
	}
	_ = json.Unmarshal(body, &rec)
	if rec.Revision == 0 {
		return ""
	}
	return fmt.Sprint(rec.Revision)
}

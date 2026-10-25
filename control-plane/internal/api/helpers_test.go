package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

type harness struct {
	db  testdb.DB
	key evidence.LocalKey
	url string
}

func newHarness(t *testing.T, resolver api.TenantResolver) harness {
	t.Helper()
	db := testdb.New(t)
	conn, err := store.Open(context.Background(), db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	srv := httptest.NewServer(api.Handler(registry.New(conn, key), resolver, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return harness{db: db, key: key, url: srv.URL}
}

func (h harness) tenant(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id, err := store.CreateTenant(context.Background(), h.db.OwnerURL, name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type response struct {
	status int
	etag   string
	body   map[string]any
	raw    string
}

// call sends a request as tenant (no auth headers when tenant is uuid.Nil).
func (h harness) call(t *testing.T, tenant uuid.UUID, method, path, body string, headers ...string) response {
	t.Helper()
	req, err := http.NewRequest(method, h.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tenant != uuid.Nil {
		req.Header.Set("X-Muistamo-Tenant", tenant.String())
		req.Header.Set("X-Muistamo-Actor", "person-a@example.invalid")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	out := response{status: res.StatusCode, etag: res.Header.Get("ETag"), raw: string(raw)}
	_ = json.Unmarshal(raw, &out.body)
	return out
}

const templateJSON = `{"apiVersion":"muistamo.dev/v1","kind":"AgentTemplate",
 "metadata":{"name":"analyst-intern"},
 "spec":{"purpose":"Support interns","modelAlias":"reasoning-default"}}`

const instanceJSON = `{"apiVersion":"muistamo.dev/v1","kind":"AgentInstance",
 "metadata":{"name":"analyst-intern-person-a"},
 "spec":{"templateRef":{"name":"analyst-intern","version":"1"},
         "binding":{"type":"user","ref":"person-a@example.invalid"},"state":"requested"}}`

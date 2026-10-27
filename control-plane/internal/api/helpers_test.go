package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
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
	return newHarnessWithHR(t, resolver, nil)
}

// newHarnessWithHR serves HR events through the real intake with dispatcher (nil: HR disabled).
func newHarnessWithHR(t *testing.T, resolver api.TenantResolver, dispatcher lifecycle.Dispatcher) harness {
	t.Helper()
	db := testdb.New(t)
	conn, err := store.Open(context.Background(), db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	var hr api.HRIntake
	if dispatcher != nil {
		hr = &lifecycle.Intake{DB: conn, Signer: key, Dispatcher: dispatcher}
	}
	srv := httptest.NewServer(api.Handler(registry.New(conn, key), resolver, hr, slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return harness{db: db, key: key, url: srv.URL}
}

// hrSecret gives tenant an HR secret and returns it.
func (h harness) hrSecret(t *testing.T, tenant uuid.UUID) []byte {
	t.Helper()
	secret := []byte("mhr_test-only-not-a-secret-" + tenant.String())
	if err := store.SetHRSecret(context.Background(), h.db.OwnerURL, tenant, secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

// postHR sends an HR event for tenant, signed with secret at time at.
func (h harness) postHR(t *testing.T, tenant uuid.UUID, secret []byte, at time.Time, body string) response {
	t.Helper()
	return h.call(t, tenant, http.MethodPost, "/v1/hr/events", body, "X-Muistamo-Signature", api.Sign(secret, []byte(body), at))
}

func hrEvent(id, kind, personID string) string {
	return `{"id":"` + id + `","type":"` + kind + `","occurredAt":"2026-10-25T09:00:00Z",` +
		`"person":{"id":"` + personID + `","email":"person-a@example.invalid","jobCode":"ANALYST_INTERN"}}`
}

// fakeDispatcher records dispatches instead of starting workflows.
type fakeDispatcher struct {
	mu    sync.Mutex
	calls []string
	fail  error
	check func(context.Context, lifecycle.Scope, muistamov1.HREvent)
}

func (d *fakeDispatcher) Dispatch(ctx context.Context, scope lifecycle.Scope, event muistamov1.HREvent) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.check != nil {
		d.check(ctx, scope, event)
	}
	if d.fail != nil {
		return "", d.fail
	}
	d.calls = append(d.calls, scope.Tenant.String()+"/"+event.Id)
	return string(event.Type) + "-" + scope.Tenant.String() + "-" + event.Id, nil
}

func (d *fakeDispatcher) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func (h harness) tenant(t *testing.T, name string) uuid.UUID {
	t.Helper()
	id, err := store.CreateTenant(context.Background(), h.db.OwnerURL, name)
	if err != nil {
		t.Fatal(err)
	}
	// Templates in these tests use reasoning-default; publication needs it on an approved model.
	testdb.ApprovedModelAlias(t, h.db.OwnerURL, id, "reasoning-default")
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

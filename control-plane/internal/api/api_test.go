package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
)

func TestDenyAllRefusesEveryAPICall(t *testing.T) {
	h := newHarness(t, api.DenyAll{})
	tenant := h.tenant(t, "acme")

	if got := h.call(t, uuid.Nil, http.MethodGet, "/healthz", ""); got.status != http.StatusOK {
		t.Fatalf("healthz = %d, want 200 without auth", got.status)
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/templates", ""},
		{http.MethodPut, "/v1/templates/analyst-intern", templateJSON},
		{http.MethodGet, "/v1/instances", ""},
	} {
		if got := h.call(t, tenant, c.method, c.path, c.body); got.status != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401 with DenyAll even with dev headers", c.method, c.path, got.status)
		}
	}
}

func TestDevHeadersRequireTenantAndActor(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	tenant := h.tenant(t, "acme")

	if got := h.call(t, uuid.Nil, http.MethodGet, "/v1/templates", ""); got.status != http.StatusUnauthorized {
		t.Fatalf("no headers = %d, want 401", got.status)
	}
	if got := h.call(t, uuid.New(), http.MethodGet, "/v1/templates", ""); got.status != http.StatusUnauthorized {
		t.Fatalf("unknown tenant = %d, want 401", got.status)
	}
	if got := h.call(t, tenant, http.MethodGet, "/v1/templates", "", "X-Muistamo-Actor", ""); got.status != http.StatusUnauthorized {
		t.Fatalf("no actor = %d, want 401", got.status)
	}
}

func TestTemplateApplyOverHTTP(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	tenant := h.tenant(t, "acme")

	got := h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-intern", templateJSON)
	if got.status != http.StatusCreated || got.etag != `"1"` {
		t.Fatalf("first apply = %d etag %s, want 201 \"1\": %s", got.status, got.etag, got.raw)
	}
	if got = h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusOK || got.etag != `"1"` {
		t.Fatalf("identical apply = %d etag %s, want 200 \"1\"", got.status, got.etag)
	}

	unknown := strings.Replace(templateJSON, `"purpose"`, `"surprise":true,"purpose"`, 1)
	if got = h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-intern", unknown); got.status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown field = %d, want 422: %s", got.status, got.raw)
	}
	if got = h.call(t, tenant, http.MethodPut, "/v1/templates/other-name", templateJSON); got.status != http.StatusUnprocessableEntity {
		t.Fatalf("path and metadata.name differ = %d, want 422", got.status)
	}
	if got = h.call(t, tenant, http.MethodGet, "/v1/templates/analyst-intern/versions/2", ""); got.status != http.StatusNotFound {
		t.Fatalf("missing version = %d, want 404", got.status)
	}
}

func TestInstanceTransitionsOverHTTP(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	tenant := h.tenant(t, "acme")
	h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-intern", templateJSON)

	created := h.call(t, tenant, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON)
	if created.status != http.StatusCreated {
		t.Fatalf("create instance = %d: %s", created.status, created.raw)
	}
	path := "/v1/instances/analyst-intern-person-a/transitions"

	if got := h.call(t, tenant, http.MethodPost, path, `{"to":"active"}`); got.status != http.StatusPreconditionRequired {
		t.Fatalf("no If-Match = %d, want 428", got.status)
	}
	if got := h.call(t, tenant, http.MethodPost, path, `{"to":"active"}`, "If-Match", `"9"`); got.status != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match = %d, want 412", got.status)
	}
	if got := h.call(t, tenant, http.MethodPost, path, `{"to":"retired"}`, "If-Match", created.etag); got.status != http.StatusConflict {
		t.Fatalf("requested to retired = %d, want 409", got.status)
	}
	active := h.call(t, tenant, http.MethodPost, path, `{"to":"active"}`, "If-Match", created.etag)
	if active.status != http.StatusOK || active.etag != `"2"` {
		t.Fatalf("to active = %d etag %s, want 200 \"2\": %s", active.status, active.etag, active.raw)
	}
	if got := h.call(t, tenant, http.MethodPost, path, `{"to":"galaxy"}`, "If-Match", active.etag); got.status != http.StatusUnprocessableEntity {
		t.Fatalf("unknown state = %d, want 422", got.status)
	}
}

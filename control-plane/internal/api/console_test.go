package api_test

// HUMAN REVIEW REQUIRED: which routes a console caller reaches (docs/control-plane-console-plan.md).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
)

type fixedResolver struct {
	name  string
	calls int
}

func (f *fixedResolver) Resolve(*http.Request) (uuid.UUID, string, error) {
	f.calls++
	return uuid.MustParse("11111111-1111-4111-8111-111111111111"), f.name, nil
}

func (f *fixedResolver) ResolveConsole(r *http.Request) (uuid.UUID, string, uuid.UUID, error) {
	tenant, name, err := f.Resolve(r)
	return tenant, name, uuid.MustParse("c0c0c0c0-0000-4000-8000-0000000c0501"), err
}

func request(method, path string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestConsoleCallersReachOnlyTheListedRoutes(t *testing.T) {
	bearer := map[string]string{"Authorization": "Bearer obviously-fake-console-token"}
	for _, r := range []*http.Request{
		request(http.MethodGet, "/v1/catalogue/requests", bearer),
		request(http.MethodGet, "/v1/catalogue/requests?state=pending", bearer),
		request(http.MethodPost, "/v1/catalogue/requests/"+uuid.NewString()+"/decision", bearer),
	} {
		console, dev := &fixedResolver{name: "entra:x"}, &fixedResolver{name: "dev:x"}
		_, actor, err := api.WithConsole{Console: console, Fallback: dev}.Resolve(r)
		if err != nil || actor != "entra:x" || dev.calls != 0 {
			t.Fatalf("%s %s = %q %v", r.Method, r.URL, actor, err)
		}
	}
	for _, r := range []*http.Request{
		request(http.MethodGet, "/v1/instances", bearer),
		request(http.MethodPost, "/v1/virtual-keys", bearer),
		request(http.MethodPost, "/v1/catalogue/requests", bearer), // filing, not deciding
		request(http.MethodGet, "/v1/catalogue/requests/"+uuid.NewString(), bearer),
		request(http.MethodPost, "/v1/catalogue/requests/x/y/decision", bearer),
		request(http.MethodPost, "/v1/privacy/erasures", bearer),
		// Percent-encoded: decoded it looks like a listed route, but no route matches by decoding.
		request(http.MethodPost, "/v1/catalogue/requests/%63"+uuid.NewString()[1:]+"/decision", bearer),
	} {
		console, dev := &fixedResolver{name: "entra:x"}, &fixedResolver{name: "dev:x"}
		if _, _, err := (api.WithConsole{Console: console, Fallback: dev}).Resolve(r); err == nil || console.calls != 0 || dev.calls != 0 {
			t.Fatalf("%s %s reached a resolver: %v", r.Method, r.URL, err)
		}
	}
}

func TestATokenIsNeverCombinedWithDevelopmentHeaders(t *testing.T) {
	console, dev := &fixedResolver{name: "entra:x"}, &fixedResolver{name: "dev:x"}
	r := request(http.MethodGet, "/v1/catalogue/requests", map[string]string{
		"Authorization":     "Bearer obviously-fake-console-token",
		"X-Muistamo-Tenant": uuid.NewString(),
		"X-Muistamo-Actor":  "someone@example.invalid",
	})
	if _, _, err := (api.WithConsole{Console: console, Fallback: dev}).Resolve(r); err == nil || console.calls+dev.calls != 0 {
		t.Fatalf("a request with two identities was resolved: %v", err)
	}
	// Without a token, the other resolver decides as before.
	if _, actor, err := (api.WithConsole{Console: console, Fallback: dev}).Resolve(request(http.MethodGet, "/v1/instances", nil)); err != nil || actor != "dev:x" {
		t.Fatalf("fallback = %q %v", actor, err)
	}
}

type failing struct{}

func (failing) ResolveConsole(*http.Request) (uuid.UUID, string, uuid.UUID, error) {
	return uuid.Nil, "", uuid.Nil, errors.New("refused")
}

func TestARefusedConsoleTokenNeverFallsBack(t *testing.T) {
	dev := &fixedResolver{name: "dev:x"}
	r := request(http.MethodGet, "/v1/catalogue/requests", map[string]string{"Authorization": "Bearer bad"})
	if _, _, err := (api.WithConsole{Console: failing{}, Fallback: dev}).Resolve(r); err == nil || dev.calls != 0 {
		t.Fatalf("a refused token fell back: %v", err)
	}
}

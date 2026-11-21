package api_test

// HUMAN REVIEW REQUIRED: which routes a console caller reaches (docs/control-plane-console-plan.md).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
		// The management screens: reads of agents and templates, and the caller's own roles.
		request(http.MethodGet, "/v1/console/access", bearer),
		request(http.MethodGet, "/v1/instances", bearer),
		request(http.MethodGet, "/v1/instances?cursor=YQ&limit=50", bearer),
		request(http.MethodGet, "/v1/instances/analyst-intern-hr-20418", bearer),
		request(http.MethodGet, "/v1/templates", bearer),
		request(http.MethodGet, "/v1/templates/analyst-intern", bearer),
		request(http.MethodGet, "/v1/events", bearer),
		request(http.MethodGet, "/v1/events?afterSeq=40&limit=50", bearer),
		// People and HR events: the feed, and a person by HR id.
		request(http.MethodGet, "/v1/hr/receipts", bearer),
		request(http.MethodGet, "/v1/hr/receipts?cursor=YQ&limit=50", bearer),
		request(http.MethodGet, "/v1/people/HR-20418", bearer),
		request(http.MethodGet, "/v1/people/a.person_2-x", bearer),
		request(http.MethodGet, "/v1/people/"+strings.Repeat("a", 200), bearer),
	} {
		console, dev := &fixedResolver{name: "entra:x"}, &fixedResolver{name: "dev:x"}
		_, actor, err := api.WithConsole{Console: console, Fallback: dev}.Resolve(r)
		if err != nil || actor != "entra:x" || dev.calls != 0 {
			t.Fatalf("%s %s = %q %v", r.Method, r.URL, actor, err)
		}
	}
	for _, r := range []*http.Request{
		request(http.MethodPost, "/v1/virtual-keys", bearer),
		// Reads only, of one record by its name, and nothing beneath it.
		request(http.MethodPost, "/v1/instances", bearer),
		request(http.MethodPost, "/v1/templates", bearer),
		request(http.MethodHead, "/v1/templates", bearer),
		request(http.MethodPut, "/v1/instances/analyst-intern-hr-20418", bearer),
		request(http.MethodPut, "/v1/templates/analyst-intern", bearer),
		request(http.MethodDelete, "/v1/templates/analyst-intern", bearer),
		request(http.MethodPost, "/v1/instances/analyst-intern-hr-20418/transitions", bearer),
		request(http.MethodGet, "/v1/instances/analyst-intern-hr-20418/effective", bearer),
		request(http.MethodGet, "/v1/templates/analyst-intern/versions/1", bearer),
		request(http.MethodGet, "/v1/templates/analyst-intern/clones", bearer),
		request(http.MethodPost, "/v1/console/access", bearer),
		request(http.MethodGet, "/v1/console/access/x", bearer),
		request(http.MethodGet, "/v1/console", bearer),
		// Not a name by the contract's pattern: upper case, a dot, a trailing hyphen, empty, too long.
		request(http.MethodGet, "/v1/instances/Analyst", bearer),
		request(http.MethodGet, "/v1/instances/a.b", bearer),
		request(http.MethodGet, "/v1/templates/analyst-", bearer),
		request(http.MethodGet, "/v1/instances/", bearer),
		request(http.MethodGet, "/v1/templates/"+strings.Repeat("a", 64), bearer),
		request(http.MethodGet, "/v1/instances/%61nalyst", bearer),
		// The other management reads are not opened yet, and the evidence log is read-only.
		request(http.MethodPost, "/v1/events", bearer),
		request(http.MethodGet, "/v1/events/40", bearer),
		// The HR webhook and HR writes; nothing beneath a person; an HR id outside the pattern.
		request(http.MethodGet, "/v1/hr/events", bearer),
		request(http.MethodPost, "/v1/hr/events", bearer),
		request(http.MethodPost, "/v1/hr/receipts", bearer),
		request(http.MethodGet, "/v1/hr/receipts/ev-1", bearer),
		request(http.MethodGet, "/v1/people", bearer),
		request(http.MethodGet, "/v1/people/", bearer),
		request(http.MethodPut, "/v1/people/HR-20418", bearer),
		request(http.MethodGet, "/v1/people/HR-20418/entra-link", bearer),
		request(http.MethodGet, "/v1/people/-HR", bearer),
		request(http.MethodGet, "/v1/people/HR%2F1", bearer),
		request(http.MethodGet, "/v1/people/HR%201", bearer),
		request(http.MethodGet, "/v1/people/HR+1", bearer),
		request(http.MethodGet, "/v1/people/a@corp", bearer),
		request(http.MethodGet, "/v1/people/a%40corp", bearer),
		request(http.MethodGet, "/v1/people/"+strings.Repeat("a", 201), bearer),
		request(http.MethodGet, "/v1/action-policies", bearer),
		request(http.MethodGet, "/v1/usage", bearer),
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
	if _, actor, err := (api.WithConsole{Console: console, Fallback: dev}).Resolve(request(http.MethodGet, "/v1/virtual-keys", nil)); err != nil || actor != "dev:x" {
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

package entra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

const fakeSecret = "obviously-fake-test-secret&+%= /"
const fakeToken = "obviously-fake-test-access-token"

var testTenant = uuid.MustParse("11111111-1111-4111-8111-111111111111")
var testCreate = uuid.MustParse("88888888-8888-4888-8888-888888888888")
var testIdentity = uuid.MustParse("99999999-9999-4999-8999-999999999999")

func binding() muistamov1.EntraIdentityBinding {
	return muistamov1.EntraIdentityBinding{
		TenantId: testTenant.String(), BindingVersion: "22222222-2222-4222-8222-222222222222",
		EntraTenantId:        "33333333-3333-4333-8333-333333333333",
		BlueprintAppId:       "44444444-4444-4444-8444-444444444444",
		BlueprintObjectId:    "55555555-5555-4555-8555-555555555555",
		BlueprintPrincipalId: "66666666-6666-4666-8666-666666666666",
		SponsorUserIds:       []string{"77777777-7777-4777-8777-777777777777"},
		CredentialRef:        "entra-development", CredentialVersion: "version-1",
	}
}

func reference() Reference { return Reference{ID: testIdentity, CreationID: testCreate} }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(r *http.Request, status int, body any) *http.Response {
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}
}

func owned(enabled bool) map[string]any {
	return map[string]any{
		"id": testIdentity.String(), "agentIdentityBlueprintId": binding().BlueprintAppId,
		"servicePrincipalType": "ServiceIdentity", "tags": []string{"muistamo:" + testTenant.String() + ":" + testCreate.String()},
		"accountEnabled": enabled,
	}
}

type fakeGraph struct {
	mu          sync.Mutex
	calls       []string
	enabled     bool
	deleted     bool
	staleEnable int
	staleDelete int
	read404     int
	mutate      func(*http.Request, map[string]any) (int, any)
	// users answers the employeeId lookup; like Graph, the filter ignores case.
	users []map[string]any
}

func (f *fakeGraph) transport(t *testing.T) roundTripFunc {
	t.Helper()
	return func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Host+r.URL.Path)
		if r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Fragment != "" {
			t.Fatalf("unsafe URL: %s", r.URL.Redacted())
		}
		if r.URL.Host == "login.microsoftonline.com" {
			if r.Method != "POST" || r.URL.Path != "/"+binding().EntraTenantId+"/oauth2/v2.0/token" {
				t.Fatal("incorrect token endpoint")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			form, err := url.ParseQuery(string(body))
			if err != nil {
				t.Fatal(err)
			}
			if form.Get("client_secret") != fakeSecret || form.Get("client_id") != binding().BlueprintAppId || form.Get("scope") != "https://graph.microsoft.com/.default" || form.Get("grant_type") != "client_credentials" {
				t.Fatalf("incorrect token form keys")
			}
			return response(r, 200, map[string]any{"access_token": fakeToken, "token_type": "Bearer", "expires_in": 3600}), nil
		}
		if r.URL.Host != "graph.microsoft.com" || (!strings.HasPrefix(r.URL.Path, "/v1.0/servicePrincipals/") && r.URL.Path != "/v1.0/users") {
			t.Fatal("incorrect Graph endpoint")
		}
		if r.Header.Get("Authorization") != "Bearer "+fakeToken {
			t.Fatal("incorrect authorization")
		}
		if r.URL.Path == "/v1.0/users" {
			q := r.URL.Query()
			if r.Method != "GET" || r.Header.Get("ConsistencyLevel") != "eventual" || q.Get("$count") != "true" || q.Get("$select") != "id,employeeId" {
				t.Fatal("unsafe user lookup")
			}
			if f.mutate != nil {
				if status, body := f.mutate(r, nil); status != 0 {
					return response(r, status, body), nil
				}
			}
			want := strings.TrimSuffix(strings.TrimPrefix(q.Get("$filter"), "employeeId eq '"), "'")
			found := []any{}
			for _, u := range f.users {
				if strings.EqualFold(fmt.Sprint(u["employeeId"]), want) {
					found = append(found, u)
				}
			}
			return response(r, 200, map[string]any{"value": found, "@odata.count": len(found)}), nil
		}
		if _, err := uuid.Parse(r.Header.Get("client-request-id")); err != nil {
			t.Fatal("missing correlation id")
		}
		if r.Method == "GET" && r.URL.Query().Get("$filter") == "" && r.Header.Get("ConsistencyLevel") != "" {
			t.Fatal("eventual consistency header on direct read")
		}
		var payload map[string]any
		if r.Body != nil && r.Body != http.NoBody {
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
		}
		if f.mutate != nil {
			if status, body := f.mutate(r, payload); status != 0 {
				return response(r, status, body), nil
			}
		}
		switch r.Method {
		case "POST":
			if payload["accountEnabled"] != false || payload["agentIdentityBlueprintId"] != binding().BlueprintAppId {
				t.Fatal("unsafe create")
			}
			if payload["displayName"] != "muistamo-"+testCreate.String() || payload["@odata.type"] != "#microsoft.graph.agentIdentity" {
				t.Fatal("incorrect create marker/name")
			}
			if fmt.Sprint(payload["sponsors@odata.bind"]) != "[https://graph.microsoft.com/v1.0/users/"+binding().SponsorUserIds[0]+"]" {
				t.Fatal("incorrect sponsor")
			}
			return response(r, 201, owned(false)), nil
		case "PATCH":
			if len(payload) != 1 {
				t.Fatal("unexpected identity mutation")
			}
			f.enabled = payload["accountEnabled"].(bool)
			return response(r, 204, nil), nil
		case "DELETE":
			f.deleted = true
			return response(r, 204, nil), nil
		case "GET":
			if r.URL.Query().Get("$filter") != "" {
				if r.Header.Get("ConsistencyLevel") != "eventual" || !strings.Contains(r.URL.Query().Get("$filter"), "muistamo:"+testTenant.String()+":"+testCreate.String()) {
					t.Fatal("unscoped discovery")
				}
				return response(r, 200, map[string]any{"value": []any{owned(f.enabled)}}), nil
			}
			if f.read404 > 0 {
				f.read404--
				return response(r, 404, nil), nil
			}
			if f.deleted {
				if f.staleDelete > 0 {
					f.staleDelete--
				} else {
					return response(r, 404, nil), nil
				}
			}
			enabled := f.enabled
			if enabled && f.staleEnable > 0 {
				f.staleEnable--
				enabled = false
			}
			return response(r, 200, owned(enabled)), nil
		}
		t.Fatalf("unexpected method: %s", r.Method)
		return nil, nil
	}
}

func testClient(t *testing.T, f *fakeGraph) *Client {
	t.Helper()
	c, err := New(binding(), func(_ context.Context, ref, version string) (string, error) {
		if ref != "entra-development" || version != "version-1" {
			t.Fatal("credential resolver scope changed")
		}
		return fakeSecret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = f.transport(t)
	c.pause = func(ctx context.Context) error { return ctx.Err() }
	return c
}

func countMethod(calls []string, method string) int {
	n := 0
	for _, call := range calls {
		if strings.HasPrefix(call, method+" graph.microsoft.com") {
			n++
		}
	}
	return n
}

func TestProviderLifecycleAndPropagation(t *testing.T) {
	f := &fakeGraph{read404: 2, staleEnable: 2, staleDelete: 2}
	c := testClient(t, f)
	ctx := context.Background()
	created, err := c.CreateDisabled(ctx, testTenant, testCreate)
	if err != nil || created.Ref != reference() || created.Enabled {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	discovered, err := c.FindCreated(ctx, testTenant, testCreate)
	if err != nil || discovered.Ref != reference() {
		t.Fatalf("discovery=%+v err=%v", discovered, err)
	}
	if got, err := c.SetEnabled(ctx, testTenant, reference(), true, uuid.New()); err != nil || !got.Enabled {
		t.Fatalf("enable=%+v err=%v", got, err)
	}
	if got, err := c.SetEnabled(ctx, testTenant, reference(), false, uuid.New()); err != nil || got.Enabled {
		t.Fatalf("disable=%+v err=%v", got, err)
	}
	if err := c.Delete(ctx, testTenant, reference(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if countMethod(f.calls, "POST") != 1 || countMethod(f.calls, "PATCH") != 2 || countMethod(f.calls, "DELETE") != 1 {
		t.Fatalf("write retries: %v", f.calls)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", c, c), fakeToken) {
		t.Fatal("client formatting leaks token")
	}
}

func TestProviderRejectsForeignScopeBeforeCredentials(t *testing.T) {
	for _, action := range []string{"create", "inspect", "discover", "enable", "delete"} {
		t.Run(action, func(t *testing.T) {
			f := &fakeGraph{}
			c := testClient(t, f)
			ctx := context.Background()
			tenant := uuid.New()
			var err error
			switch action {
			case "create":
				_, err = c.CreateDisabled(ctx, tenant, testCreate)
			case "inspect":
				_, err = c.Inspect(ctx, tenant, reference())
			case "discover":
				_, err = c.FindCreated(ctx, tenant, testCreate)
			case "enable":
				_, err = c.SetEnabled(ctx, tenant, reference(), true, uuid.New())
			case "delete":
				err = c.Delete(ctx, tenant, reference(), uuid.New())
			}
			if !errors.Is(err, ErrScope) || len(f.calls) != 0 {
				t.Fatalf("err=%v calls=%v", err, f.calls)
			}
		})
	}
}

func TestProviderOwnershipRefusesMutation(t *testing.T) {
	for _, change := range []string{"id", "blueprint", "type", "tags", "enabled missing", "enabled string"} {
		for _, action := range []string{"enable", "disable", "delete"} {
			t.Run(change+"/"+action, func(t *testing.T) {
				f := &fakeGraph{mutate: func(r *http.Request, _ map[string]any) (int, any) {
					if r.Method != "GET" {
						return 0, nil
					}
					doc := owned(false)
					switch change {
					case "id":
						doc["id"] = uuid.New().String()
					case "blueprint":
						doc["agentIdentityBlueprintId"] = uuid.New().String()
					case "type":
						doc["servicePrincipalType"] = "Application"
					case "tags":
						doc["tags"] = []string{"foreign"}
					case "enabled missing":
						delete(doc, "accountEnabled")
					case "enabled string":
						doc["accountEnabled"] = "false"
					}
					return 200, doc
				}}
				c := testClient(t, f)
				var err error
				if action == "delete" {
					err = c.Delete(context.Background(), testTenant, reference(), uuid.New())
				} else {
					_, err = c.SetEnabled(context.Background(), testTenant, reference(), action == "enable", uuid.New())
				}
				if err == nil || countMethod(f.calls, "PATCH")+countMethod(f.calls, "DELETE") != 0 {
					t.Fatalf("err=%v calls=%v", err, f.calls)
				}
			})
		}
	}
}

func TestProviderCreateUncertaintyNeverRetries(t *testing.T) {
	for _, status := range []int{200, 400, 403, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := &fakeGraph{mutate: func(r *http.Request, _ map[string]any) (int, any) {
				if r.Method == "POST" {
					return status, map[string]any{"error": map[string]any{"code": fakeSecret, "message": fakeToken}}
				}
				return 0, nil
			}}
			c := testClient(t, f)
			_, err := c.CreateDisabled(context.Background(), testTenant, testCreate)
			if err == nil || countMethod(f.calls, "POST") != 1 {
				t.Fatalf("err=%v calls=%v", err, f.calls)
			}
			wantUncertain := status == 200 || status >= 500
			if errors.Is(err, ErrUncertain) != wantUncertain {
				t.Fatalf("uncertain=%v want %v: %v", errors.Is(err, ErrUncertain), wantUncertain, err)
			}
			if strings.Contains(err.Error(), fakeSecret) || strings.Contains(err.Error(), fakeToken) {
				t.Fatal("provider error leaks data")
			}
		})
	}
}

func TestProviderCandidateSurvivesUnverifiedCreate(t *testing.T) {
	for _, scenario := range []string{"read404", "wrong blueprint", "missing marker", "malformed property"} {
		t.Run(scenario, func(t *testing.T) {
			f := &fakeGraph{read404: 100}
			if scenario != "read404" {
				f.read404 = 0
				f.mutate = func(r *http.Request, _ map[string]any) (int, any) {
					if scenario == "malformed property" && r.Method == "POST" {
						d := owned(false)
						d["tags"] = "not-an-array"
						return 201, d
					}
					if scenario == "wrong blueprint" && r.Method == "POST" {
						d := owned(false)
						d["agentIdentityBlueprintId"] = uuid.New().String()
						return 201, d
					}
					if scenario == "missing marker" && r.Method == "GET" {
						d := owned(false)
						delete(d, "tags")
						return 200, d
					}
					return 0, nil
				}
			}
			c := testClient(t, f)
			candidate, err := c.CreateDisabled(context.Background(), testTenant, testCreate)
			if !errors.Is(err, ErrUncertain) || candidate.Ref.ID != testIdentity || countMethod(f.calls, "POST") != 1 {
				t.Fatalf("candidate=%+v err=%v calls=%v", candidate, err, f.calls)
			}
			if countMethod(f.calls, "PATCH")+countMethod(f.calls, "DELETE") != 0 {
				t.Fatal("cleanup without durable authorization")
			}
			if len(f.calls) > 9 {
				t.Fatal("unbounded read polling")
			}
		})
	}
}

func TestProviderMutationNeedsStateProofAndNeverRetries(t *testing.T) {
	for _, scenario := range []string{"patch500", "patch403", "patch refused changed", "stale enabled", "delete500", "delete404", "delete refused hidden", "delete remains", "delete enabled", "delete foreign"} {
		t.Run(scenario, func(t *testing.T) {
			f := &fakeGraph{}
			f.mutate = func(r *http.Request, _ map[string]any) (int, any) {
				if scenario == "patch refused changed" && r.Method == "PATCH" {
					f.enabled = true // Desired state alone cannot replace our successful write receipt.
					return 500, nil
				}
				if scenario == "patch500" && r.Method == "PATCH" {
					return 500, nil
				}
				if scenario == "patch403" && r.Method == "PATCH" {
					return 403, nil
				}
				if scenario == "delete500" && r.Method == "DELETE" {
					return 500, nil
				}
				if scenario == "delete404" && r.Method == "DELETE" {
					return 404, nil
				}
				if scenario == "delete refused hidden" && r.Method == "DELETE" {
					f.deleted = true // Visibility disappears after refusal; no successful delete receipt.
					return 403, nil
				}
				if r.Method == "GET" {
					if scenario == "stale enabled" {
						return 200, owned(false)
					}
					if scenario == "delete remains" {
						return 200, owned(false)
					}
					if scenario == "delete enabled" {
						return 200, owned(true)
					}
					if scenario == "delete foreign" && f.deleted {
						d := owned(false)
						d["tags"] = []string{"foreign"}
						return 200, d
					}
				}
				return 0, nil
			}
			c := testClient(t, f)
			var err error
			if strings.HasPrefix(scenario, "delete") {
				err = c.Delete(context.Background(), testTenant, reference(), uuid.New())
			} else {
				_, err = c.SetEnabled(context.Background(), testTenant, reference(), true, uuid.New())
			}
			if err == nil {
				t.Fatal("unverified operation reported success")
			}
			if countMethod(f.calls, "PATCH") > 1 || countMethod(f.calls, "DELETE") > 1 || len(f.calls) > 10 {
				t.Fatalf("unbounded calls: %v", f.calls)
			}
			if scenario == "delete enabled" && countMethod(f.calls, "DELETE") != 0 {
				t.Fatal("deleted enabled identity")
			}
			if scenario == "stale enabled" || scenario == "delete remains" {
				if !errors.Is(err, ErrUncertain) {
					t.Fatalf("lost uncertainty: %v", err)
				}
			}
		})
	}
}

func TestProviderDiscoveryCannotAuthorizeUnknownOrPartialMatches(t *testing.T) {
	for _, scenario := range []string{"none", "multiple", "nextLink", "foreign", "missing value", "denied", "count multiple", "count zero", "count string", "count null"} {
		t.Run(scenario, func(t *testing.T) {
			f := &fakeGraph{mutate: func(r *http.Request, _ map[string]any) (int, any) {
				if r.URL.Query().Get("$filter") == "" {
					return 0, nil
				}
				d := map[string]any{"value": []any{owned(false)}}
				switch scenario {
				case "count multiple":
					d["@odata.count"] = 2
				case "count zero":
					d["@odata.count"] = 0
				case "count string":
					d["@odata.count"] = "1"
				case "count null":
					d["@odata.count"] = nil
				case "none":
					d["value"] = []any{}
				case "multiple":
					d["value"] = []any{owned(false), owned(false)}
				case "nextLink":
					d["@odata.nextLink"] = "https://attacker.invalid/steal"
				case "foreign":
					row := owned(false)
					row["tags"] = []string{"foreign"}
					d["value"] = []any{row}
				case "missing value":
					delete(d, "value")
				case "denied":
					return 403, nil
				}
				return 200, d
			}}
			c := testClient(t, f)
			_, err := c.FindCreated(context.Background(), testTenant, testCreate)
			if err == nil || countMethod(f.calls, "GET") != 1 || countMethod(f.calls, "POST") != 0 {
				t.Fatalf("err=%v calls=%v", err, f.calls)
			}
		})
	}
}

func TestProviderConfigurationAndCancellation(t *testing.T) {
	for _, field := range []string{"tenant", "version", "directory", "app", "object", "principal", "sponsor", "no resolver"} {
		t.Run(field, func(t *testing.T) {
			b := binding()
			resolve := SecretResolver(func(context.Context, string, string) (string, error) {
				t.Fatal("resolved invalid configuration")
				return "", nil
			})
			switch field {
			case "tenant":
				b.TenantId = uuid.Nil.String()
			case "version":
				b.BindingVersion = uuid.Nil.String()
			case "directory":
				b.EntraTenantId = "common"
			case "app":
				b.BlueprintAppId = uuid.Nil.String()
			case "object":
				b.BlueprintObjectId = uuid.Nil.String()
			case "principal":
				b.BlueprintPrincipalId = uuid.Nil.String()
			case "sponsor":
				b.SponsorUserIds = []string{uuid.Nil.String()}
			case "no resolver":
				resolve = nil
			}
			if _, err := New(b, resolve); !errors.Is(err, ErrConfiguration) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	f := &fakeGraph{}
	c := testClient(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CreateDisabled(ctx, testTenant, testCreate); !errors.Is(err, context.Canceled) || len(f.calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, f.calls)
	}
}

func TestProviderCredentialFailuresStayPrivate(t *testing.T) {
	c, err := New(binding(), func(context.Context, string, string) (string, error) { return "", errors.New(fakeSecret) })
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("HTTP after resolver failure"); return nil, nil })
	if _, err := c.Inspect(context.Background(), testTenant, reference()); err == nil || strings.Contains(err.Error(), fakeSecret) {
		t.Fatalf("err=%v", err)
	}
	for _, body := range []any{map[string]any{"error": fakeSecret}, map[string]any{"access_token": fakeToken, "token_type": "Bearer", "expires_in": 0}, map[string]any{"access_token": fakeToken, "token_type": "Basic", "expires_in": 3600}, map[string]any{"access_token": "line\nbreak", "token_type": "Bearer", "expires_in": 3600}} {
		f := &fakeGraph{}
		c := testClient(t, f)
		c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "login.microsoftonline.com" {
				t.Fatal("Graph after failed token")
			}
			return response(r, 200, body), nil
		})
		if _, err := c.Inspect(context.Background(), testTenant, reference()); err == nil || strings.Contains(err.Error(), fakeSecret) || strings.Contains(err.Error(), fakeToken) {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestProviderCacheIsBoundToImmutableConfiguration(t *testing.T) {
	b := binding()
	original := b.SponsorUserIds[0]
	c, err := New(b, func(context.Context, string, string) (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	b.SponsorUserIds[0] = uuid.New().String()
	if c.binding.SponsorUserIds[0] != original {
		t.Fatal("caller changed pinned sponsor")
	}
	f := &fakeGraph{}
	c.http.Transport = f.transport(t)
	c.pause = func(ctx context.Context) error { return ctx.Err() }
	for range 2 {
		if _, err := c.Inspect(context.Background(), testTenant, reference()); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.calls) != 3 {
		t.Fatalf("token not reused within binding: %v", f.calls)
	}
	c.expiry = time.Now().Add(-time.Second)
	if _, err := c.Inspect(context.Background(), testTenant, reference()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 5 {
		t.Fatalf("expired token reused: %v", f.calls)
	}
}

// Only a binary built with the e2e tag (e2e_transport.go) can send these requests anywhere but
// Microsoft's own hosts.
func TestShippedBuildsCannotRedirectMicrosoftHosts(t *testing.T) {
	if e2eTransport != nil {
		t.Fatal("a build without the e2e tag has a transport override")
	}
	c, err := New(binding(), func(context.Context, string, string) (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	if c.http.Transport != nil {
		t.Fatal("the default client has a custom transport")
	}
}

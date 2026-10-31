package entra

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

type adapterFixture struct {
	svc     *registry.Service
	actor   registry.Actor
	client  *Client
	adapter *Adapter
	db      testdb.DB
	conn    *store.DB
	key     evidence.LocalKey
	name    string
	graph   *adapterGraph
}
type adapterGraph struct {
	mu                          sync.Mutex
	calls                       []string
	creation                    uuid.UUID
	enabled, exists, loseCreate bool
	users                       []map[string]any // the employeeId lookup's directory
	usersStatus                 int              // when set, the lookup answers this status
}

func (g *adapterGraph) transport(t *testing.T) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.calls = append(g.calls, r.Method+" "+r.URL.Path)
		if r.URL.Host == "login.microsoftonline.com" {
			return response(r, 200, map[string]any{"access_token": fakeToken, "token_type": "Bearer", "expires_in": 3600}), nil
		}
		data := func() map[string]any {
			return map[string]any{"id": testIdentity.String(), "agentIdentityBlueprintId": binding().BlueprintAppId, "servicePrincipalType": "ServiceIdentity", "tags": []string{marker(testTenant, g.creation)}, "accountEnabled": g.enabled}
		}
		switch r.Method {
		case http.MethodPost:
			var body struct {
				Tags    []string `json:"tags"`
				Enabled bool     `json:"accountEnabled"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if len(body.Tags) != 1 || body.Enabled {
				t.Error("create was not disabled and correlated")
			}
			parts := strings.Split(body.Tags[0], ":")
			g.creation = uuid.MustParse(parts[len(parts)-1])
			g.exists = true
			g.enabled = false
			if g.loseCreate {
				return nil, errors.New("artificial lost POST response")
			}
			return response(r, 201, data()), nil
		case http.MethodGet:
			if r.URL.Path == "/v1.0/users" {
				if g.usersStatus != 0 {
					return response(r, g.usersStatus, map[string]any{"error": map[string]string{"code": "Authorization_RequestDenied"}}), nil
				}
				want := strings.TrimSuffix(strings.TrimPrefix(r.URL.Query().Get("$filter"), "employeeId eq '"), "'")
				found := []any{}
				for _, u := range g.users {
					if strings.EqualFold(fmt.Sprint(u["employeeId"]), want) {
						found = append(found, u)
					}
				}
				return response(r, 200, map[string]any{"@odata.count": len(found), "value": found}), nil
			}
			if strings.Contains(r.URL.Path, "servicePrincipals/microsoft.graph.agentIdentity") {
				values := []any{}
				if g.exists {
					values = append(values, data())
				}
				return response(r, 200, map[string]any{"@odata.count": len(values), "value": values}), nil
			}
			if !g.exists {
				return response(r, 404, map[string]any{"error": map[string]string{"code": "Request_ResourceNotFound"}}), nil
			}
			return response(r, 200, data()), nil
		case http.MethodPatch:
			var body map[string]bool
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			g.enabled = body["accountEnabled"]
			return response(r, 204, nil), nil
		case http.MethodDelete:
			g.exists = false
			return response(r, 204, nil), nil
		}
		t.Errorf("unexpected provider call %s", r.URL)
		return response(r, 500, nil), nil
	}
}

func setupAdapter(t *testing.T) adapterFixture {
	return setupAdapterSeed(t, true)
}

func setupAdapterSeed(t *testing.T, seed bool) adapterFixture {
	t.Helper()
	ctx := context.Background()
	db := testdb.New(t)
	testdb.Exec(t, db.OwnerURL, `INSERT INTO tenants(id,name) VALUES($1,'acme')`, testTenant)
	testdb.ApprovedModelAlias(t, db.OwnerURL, testTenant, "reasoning-default")
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	svc := registry.New(conn, key)
	actor := registry.Actor{Tenant: testTenant, Name: "operator:test", RequestID: "adapter-test"}
	b := binding()
	if _, _, err := svc.RegisterIdentityBinding(ctx, actor, b); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollIdentityTenant(ctx, actor, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	var template muistamov1.AgentTemplate
	template.ApiVersion = "muistamo.dev/v1"
	template.Kind = "AgentTemplate"
	template.Metadata.Name = "analyst"
	template.Spec.Purpose = "adapter test"
	template.Spec.ModelAlias = "reasoning-default"
	if !seed {
		codes := []string{"INTERN"}
		template.Spec.Assignment = &struct {
			HrJobCodes *[]string `json:"hrJobCodes,omitempty"`
		}{HrJobCodes: &codes}
		risk := muistamov1.AgentTemplateSpecRiskTierLow
		template.Spec.RiskTier = &risk
	}
	published, _, err := svc.ApplyTemplate(ctx, actor, template)
	if err != nil {
		t.Fatal(err)
	}
	if !seed {
		if _, err := svc.RequestPublication(ctx, actor, "analyst", published.Version); err != nil {
			t.Fatal(err)
		}
	}
	if seed {
		seedAdapterHR(t, conn, key, actor, "join", "joiner", 1)
	}
	var doc muistamov1.AgentInstance
	doc.ApiVersion = "muistamo.dev/v1"
	doc.Kind = "AgentInstance"
	doc.Metadata.Name = "analyst-person"
	doc.Spec.TemplateRef.Name = "analyst"
	doc.Spec.TemplateRef.Version = "1"
	doc.Spec.Binding.Type = "user"
	doc.Spec.Binding.Ref = "person@example.invalid"
	doc.Spec.State = "requested"
	if seed {
		if _, _, err := svc.CreateEntraInstance(ctx, actor, doc, "join", 1, uuid.MustParse(b.BindingVersion)); err != nil {
			t.Fatal(err)
		}
	}
	c, err := New(b, func(context.Context, string, string) (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	g := &adapterGraph{}
	c.http = &http.Client{Transport: g.transport(t)}
	c.pause = func(context.Context) error { return nil }
	a, err := NewAdapter(svc, c)
	if err != nil {
		t.Fatal(err)
	}
	return adapterFixture{svc: svc, actor: actor, client: c, adapter: a, db: db, conn: conn, key: key, name: doc.Metadata.Name, graph: g}
}

func seedAdapterHR(t *testing.T, db *store.DB, key evidence.LocalKey, actor registry.Actor, id, kind string, gen int64) {
	t.Helper()
	var event muistamov1.HREvent
	event.Id = id
	event.Type = muistamov1.HREventType(kind)
	event.OccurredAt = time.Date(2026, 10, 27, 9, 0, int(gen), 0, time.UTC)
	event.Person.Id = "HR-PERSON"
	event.Person.Email = "person@example.invalid"
	event.Person.JobCode = "INTERN"
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InTenant(context.Background(), actor.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version) VALUES($1,$2,$3,$4,'',$5,$6,$7,'accepted','pending','entra',(SELECT binding_version FROM identity_enrollments))`, actor.Tenant, id, kind, event.Person.Id, raw, event.OccurredAt, gen); err != nil {
			return err
		}
		_, err := evidence.Append(context.Background(), tx, key, evidence.Entry{Tenant: actor.Tenant, Actor: "hris:test", RequestID: id, Action: "hr.event.received", SubjectKind: "HRPerson", SubjectName: event.Person.Id, After: map[string]any{"eventId": id, "type": kind, "generation": gen, "decision": "accepted", "identityMode": "entra", "identityBindingVersion": binding().BindingVersion}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAdapterJournaledLifecycle(t *testing.T) {
	f := setupAdapter(t)
	upstream := f.graph.transport(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Error("provider request did not use HTTPS")
			w.WriteHeader(500)
			return
		}
		r.URL.Scheme, r.URL.Host = "https", r.Host
		response, err := upstream.RoundTrip(r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		defer func() { _ = response.Body.Close() }()
		w.WriteHeader(response.StatusCode)
		if response.StatusCode != 204 {
			_, _ = io.Copy(w, response.Body)
		}
	}))
	defer server.Close()
	routeHTTPS(t, f.client, server)
	ctx := context.Background()
	for _, action := range []muistamov1.IdentityOperationStatusAction{"create", "enable"} {
		if _, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, action); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, f.name, "active"); err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, f.name, "suspended"); err != nil {
		t.Fatal(err)
	}
	for _, action := range []muistamov1.IdentityOperationStatusAction{"disable", "delete"} {
		if _, err := f.adapter.Apply(ctx, f.actor, f.name, "leave", 2, action); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, f.name, "retired"); err != nil {
		t.Fatal(err)
	}
	events, err := f.svc.ListEvents(ctx, f.actor, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidencechain.Verify(events, map[string]ed25519.PublicKey{f.key.KeyID(): f.key.Public()}); err != nil {
		t.Fatalf("adapter evidence chain failed: %v", err)
	}
	intents, results := 0, 0
	for _, event := range events {
		if event.Action == "identity.operation.intent" {
			intents++
		}
		if event.Action == "identity.operation.succeeded" {
			results++
		}
	}
	if intents != 4 || results != 4 {
		t.Fatalf("adapter evidence incomplete: intents=%d results=%d", intents, results)
	}
	effects := map[string]int{}
	for _, call := range f.graph.calls {
		if strings.Contains(call, " /v1.0/") {
			effects[strings.Fields(call)[0]]++
		}
	}
	if effects["POST"] != 1 || effects["PATCH"] != 2 || effects["DELETE"] != 1 {
		t.Fatalf("unexpected lifecycle effects: %v", f.graph.calls)
	}
	t.Logf("verified %d signed adapter lifecycle events over loopback HTTPS and real PostgreSQL", len(events))
}

func TestAdapterLostCreateResponseReconcilesWithoutAnotherPost(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	f.graph.loseCreate = true
	op, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create")
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("lost create not quarantined: %v", err)
	}
	if _, err := f.adapter.Reconcile(ctx, f.actor, op.Id); err != nil {
		t.Fatal(err)
	}
	posts := 0
	for _, call := range f.graph.calls {
		if strings.HasPrefix(call, "POST /v1.0/") {
			posts++
		}
	}
	if posts != 1 {
		t.Fatalf("recovery made %d creates", posts)
	}
}

func TestAdapterMissingHistoricalBindingMakesNoRequest(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	f.client.binding.CredentialVersion = "different-version"
	if _, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create"); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("changed binding accepted: %v", err)
	}
	if len(f.graph.calls) != 0 {
		t.Fatalf("mismatched binding contacted provider: %v", f.graph.calls)
	}
}

func TestAdapterLateEnableInvalidatesEarlierDisableConfirmation(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	create, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	enable, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, f.name, "join", 1, "enable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.MarkIdentityIndeterminate(ctx, f.actor, enable.Id, "uncertain"); err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, f.name, "suspended"); err != nil {
		t.Fatal(err)
	}
	disable, err := f.adapter.Apply(ctx, f.actor, f.name, "leave", 2, "disable")
	if !errors.Is(err, ErrUncertain) {
		t.Fatalf("disable falsely settled an outstanding enable: %v", err)
	}
	f.graph.mu.Lock()
	f.graph.enabled = true
	f.graph.mu.Unlock()
	if err := f.svc.CommitIdentityResult(ctx, f.actor, enable.Id, create.CreationId, testIdentity, "enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.confirmGlobalState(ctx, f.actor, disable); !errors.Is(err, ErrUncertain) {
		t.Fatalf("old disable falsely confirmed after late enable: %v", err)
	}
	corrective, err := f.adapter.Apply(ctx, f.actor, f.name, "leave", 2, "disable")
	if err != nil || corrective.Id == disable.Id {
		t.Fatalf("corrective disable failed: %+v %v", corrective, err)
	}
}

func TestAdapterCurrentStateDoesNotSettleUnknownPatch(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	if _, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create"); err != nil {
		t.Fatal(err)
	}
	op, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, f.name, "join", 1, "enable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.MarkIdentityIndeterminate(ctx, f.actor, op.Id, "uncertain"); err != nil {
		t.Fatal(err)
	}
	f.graph.mu.Lock()
	f.graph.enabled = true
	before := len(f.graph.calls)
	f.graph.mu.Unlock()
	if _, err := f.adapter.Reconcile(ctx, f.actor, op.Id); !errors.Is(err, ErrUncertain) {
		t.Fatalf("current state settled unknown PATCH: %v", err)
	}
	f.graph.mu.Lock()
	defer f.graph.mu.Unlock()
	if len(f.graph.calls) != before {
		t.Fatal("uncertain PATCH reconciliation made provider requests")
	}
}

func TestAdapterReconciliationRechecksConcurrentCandidate(t *testing.T) {
	f := setupAdapter(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	f.graph.loseCreate = true
	op, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create")
	if !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	original := f.client.http.Transport
	f.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "servicePrincipals/microsoft.graph.agentIdentity") {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return original.RoundTrip(r)
	})
	finished := make(chan error, 1)
	go func() { _, err := f.adapter.Reconcile(ctx, f.actor, op.Id); finished <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if err := f.svc.MarkIdentityIndeterminate(ctx, f.actor, op.Id, "uncertain", uuid.New()); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-finished; !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("reconciliation ignored concurrently retained candidate: %v", err)
	}
	status, err := f.svc.IdentityStatus(ctx, f.actor, f.name)
	if err != nil || status.ProviderId != nil {
		t.Fatalf("conflicting candidate bound ownership: %+v %v", status, err)
	}
}

func TestAdapterConfirmationRefusesPendingConflictingIntent(t *testing.T) {
	f := setupAdapter(t)
	ctx := context.Background()
	create, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, f.name, "join", 1, "enable"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.adapter.Reconcile(ctx, f.actor, create.Id); !errors.Is(err, ErrUncertain) {
		t.Fatalf("pending intent did not invalidate global confirmation: %v", err)
	}
}

type adapterFailAfterIntent struct {
	evidence.LocalKey
	count atomic.Int32
}

func (s *adapterFailAfterIntent) Sign(data []byte) ([]byte, error) {
	if s.count.Add(1) > 1 {
		return nil, errors.New("artificial persistent signer outage")
	}
	return s.LocalKey.Sign(data)
}

func TestAdapterPersistenceFailureRetainsUncertainClassification(t *testing.T) {
	f := setupAdapter(t)
	svc := registry.New(f.conn, &adapterFailAfterIntent{LocalKey: f.key})
	a, err := NewAdapter(svc, f.client)
	if err != nil {
		t.Fatal(err)
	}
	op, err := a.Apply(context.Background(), f.actor, f.name, "join", 1, "create")
	if !errors.Is(err, ErrUncertain) || !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("persistence failure lost may-have-executed status: %v", err)
	}
	stored, err := f.svc.IdentityOperation(context.Background(), f.actor, op.Id)
	if err != nil || stored.State != "pending" {
		t.Fatalf("uncertain result was not retained: %+v %v", stored, err)
	}
}

func TestAdapterCancellationBoundsProviderAndRetainsIntent(t *testing.T) {
	f := setupAdapter(t)
	entered := make(chan struct{})
	f.client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := f.adapter.Apply(ctx, f.actor, f.name, "join", 1, "create"); finished <- err }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("provider request did not start")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, ErrUncertain) {
			t.Fatalf("cancelled original invocation lost uncertainty: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("provider deadline did not bound cancellation")
	}
}

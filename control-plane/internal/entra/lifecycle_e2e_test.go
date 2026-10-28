package entra

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/protobuf/proto"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/signature"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// Exercise the production HTTP handler, new named workflows/activities, real Temporal and
// PostgreSQL, fixed-host Graph client over verified loopback TLS, and offline evidence verifier.
func TestAdapterEntraLifecycleEndToEnd(t *testing.T) {
	f := setupAdapterSeed(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	upstream := f.graph.transport(t)
	graph := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	defer graph.Close()
	routeHTTPS(t, f.client, graph)
	address := os.Getenv("MUISTAMO_TEST_TEMPORAL_ADDRESS")
	if address == "" {
		address = "127.0.0.1:7233"
	}
	temporal, err := client.Dial(client.Options{HostPort: address})
	if err != nil {
		t.Fatalf("Temporal unavailable: %v", err)
	}
	defer temporal.Close()
	queue := "muistamo-entra-test-" + uuid.NewString()
	w := worker.New(temporal, queue, worker.Options{})
	w.RegisterWorkflow(lifecycle.EntraHRDispatch)
	w.RegisterWorkflow(lifecycle.EntraJoiner)
	w.RegisterWorkflow(lifecycle.EntraLeaver)
	w.RegisterActivity(&lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: &lifecycle.Simulated{}})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	intake := &lifecycle.Intake{DB: f.conn, Signer: f.key, Dispatcher: lifecycle.TemporalDispatcher{Client: temporal, TaskQueue: queue}}
	secret := []byte("obviously-fake-hr-signing-key-at-least-32-bytes")
	if err := store.SetHRSecret(ctx, f.db.OwnerURL, f.actor.Tenant, secret); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler(f.svc, api.InsecureDevHeaders{}, intake, slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer server.Close()
	at := time.Now().UTC().Truncate(time.Second)
	person := "LIVE-EMPLOYEE"
	var workflows []string
	post := func(id string, kind muistamov1.HREventType, offset int64) muistamov1.HREventAccepted {
		t.Helper()
		var event muistamov1.HREvent
		event.Id, event.Type, event.OccurredAt = id, kind, at.Add(time.Duration(offset)*time.Second)
		event.Person.Id, event.Person.Email, event.Person.JobCode = person, "private-person@example.invalid", "INTERN"
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/hr/events", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Muistamo-Tenant", f.actor.Tenant.String())
		req.Header.Set("X-Muistamo-Actor", "operator:test")
		req.Header.Set("X-Muistamo-Signature", signature.Sign(secret, raw, time.Now()))
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 202 {
			t.Fatalf("HR intake status=%d: %s", res.StatusCode, body)
		}
		var accepted muistamov1.HREventAccepted
		if err := json.Unmarshal(body, &accepted); err != nil {
			t.Fatal(err)
		}
		route, err := f.svc.IdentityRoute(ctx, f.actor, id)
		if err != nil {
			t.Fatal(err)
		}
		workflows = append(workflows, lifecycle.EntraDispatchWorkflowID(muistamov1.EntraLifecycleRef{TenantId: f.actor.Tenant, ReceiptId: route.ReceiptId}), accepted.WorkflowId)
		return accepted
	}
	name := lifecycle.InstanceName("analyst", person, 1)
	wait := func(state muistamov1.InstanceState, generation int64) {
		t.Helper()
		for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); {
			record, err := f.svc.GetInstance(ctx, f.actor, name)
			if err == nil && record.Document.Spec.State == state {
				owned, err := f.svc.IdentityStatus(ctx, f.actor, name)
				if err == nil && (generation == 0 || (owned.EnabledGeneration != nil && *owned.EnabledGeneration == generation)) {
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("live instance never reached %s generation %d", state, generation)
	}
	post("live-join", "joiner", 0)
	wait("active", 1)
	post("live-leave", "leaver", 1)
	wait("suspended", 0)
	// Observe completion of the leaver's initial disable/coverage/setup steps before
	// exercising the ordinary rehire path. Rapid supersession has separate fence tests.
	setupDone := false
	for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); {
		events, err := f.svc.ListEvents(ctx, f.actor, 0, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if event.Action == "hr.event.setup-completed" && event.Subject.Name == "live-leave" {
				setupDone = true
			}
		}
		if setupDone {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !setupDone {
		t.Fatal("leaver initial setup did not finish")
	}
	post("live-rehire", "joiner", 2)
	wait("active", 3)
	for _, id := range workflows {
		if err := temporal.GetWorkflow(ctx, id, "").Get(ctx, nil); err != nil {
			t.Fatalf("live workflow %s failed: %v", id, err)
		}
		iterator := temporal.GetWorkflowHistory(ctx, id, "", false, enums.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
		for iterator.HasNext() {
			event, err := iterator.Next()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := proto.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			for _, private := range []string{"private-person@example.invalid", "obviously-fake-test-secret", fakeToken} {
				if bytes.Contains(raw, []byte(private)) {
					t.Fatalf("live history exposed private HR or credential input: workflow=%s", id)
				}
			}
		}
	}
	events, err := f.svc.ListEvents(ctx, f.actor, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidencechain.Verify(events, map[string]ed25519.PublicKey{f.key.KeyID(): f.key.Public()}); err != nil {
		t.Fatalf("live lifecycle evidence failed verification: %v", err)
	}
	counts := map[string]int{}
	for _, event := range events {
		counts[event.Action]++
	}
	if counts["hr.event.setup-completed"] != 3 || counts["identity.operation.intent"] != 4 || counts["personal-layer.review-not-opened"] != 1 {
		t.Fatalf("live lifecycle evidence incomplete: %v", counts)
	}
	posts := 0
	f.graph.mu.Lock()
	for _, call := range f.graph.calls {
		if len(call) >= 11 && call[:11] == "POST /v1.0/" {
			posts++
		}
	}
	f.graph.mu.Unlock()
	if posts != 1 {
		t.Fatalf("rehire issued %d creates", posts)
	}
	t.Logf("verified %d signed live lifecycle events across HTTP, Temporal, PostgreSQL and loopback HTTPS; histories omit HR email/credentials, retain identifiers; gateway remains simulated and knowledge review not integrated", len(events))
}

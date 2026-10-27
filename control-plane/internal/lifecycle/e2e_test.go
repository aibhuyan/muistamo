package lifecycle_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// TestJoinerLeaverRehireEndToEnd runs the real workflows on the compose Temporal server against
// a real database. The 30-day retirement path is covered by the time-skipping unit tests.
func TestJoinerLeaverRehireEndToEnd(t *testing.T) {
	address := os.Getenv("MUISTAMO_TEST_TEMPORAL_ADDRESS")
	if address == "" {
		address = "127.0.0.1:7233"
	}
	temporal, err := client.Dial(client.Options{HostPort: address})
	if err != nil {
		t.Fatalf("Temporal unreachable at MUISTAMO_TEST_TEMPORAL_ADDRESS (run make dev): %v", err)
	}
	defer temporal.Close()

	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f.template(t, "analyst-intern", "ANALYST_INTERN")

	queue := "muistamo-lifecycle-test-" + uuid.NewString()
	w := worker.New(temporal, queue, worker.Options{})
	w.RegisterWorkflow(lifecycle.Joiner)
	w.RegisterWorkflow(lifecycle.Leaver)
	w.RegisterWorkflow(lifecycle.HRDispatch)
	w.RegisterActivity(f.acts)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	conn, err := store.Open(ctx, f.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	intake := &lifecycle.Intake{DB: conn, Signer: f.key, Dispatcher: lifecycle.TemporalDispatcher{Client: temporal, TaskQueue: queue}}
	reader := registry.Actor{Tenant: f.scope.Tenant, Name: "test", RequestID: "test"}
	personID := "E-" + uuid.NewString()[:8]
	event := func(id string, kind muistamov1.HREventType) muistamov1.HREvent {
		var e muistamov1.HREvent
		e.Id, e.Type, e.OccurredAt = id, kind, time.Now()
		e.Person.Id, e.Person.Email, e.Person.JobCode = personID, "person-a@example.invalid", "ANALYST_INTERN"
		return e
	}
	accept := func(e muistamov1.HREvent) string {
		t.Helper()
		receipt, err := intake.Accept(ctx, f.scope.Tenant, "hris:test", "req-"+e.Id, e)
		if err != nil {
			t.Fatalf("accept %s: %v", e.Id, err)
		}
		return receipt.WorkflowId
	}
	waitFor := func(name string, state muistamov1.InstanceState) {
		t.Helper()
		for ctx.Err() == nil {
			rec, err := f.svc.GetInstance(ctx, reader, name)
			if err == nil && rec.Document.Spec.State == state {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s never reached %s", name, state)
	}

	// Joiner: an instance with an identity, active well inside the one-hour target (J2).
	start := time.Now()
	var instances []string
	if err := temporal.GetWorkflow(ctx, accept(event("join-1", muistamov1.HREventTypeJoiner)), "").Get(ctx, &instances); err != nil {
		t.Fatalf("joiner: %v", err)
	}
	if len(instances) != 1 {
		t.Fatalf("joiner instances = %v", instances)
	}
	name := instances[0]
	waitFor(name, muistamov1.InstanceStateActive)
	t.Logf("joiner event to active instance: %s", time.Since(start).Round(time.Millisecond))

	// Leaver: suspended and revoked promptly; the workflow then waits out the grace period.
	start = time.Now()
	leaverID := accept(event("leave-1", muistamov1.HREventTypeLeaver))
	waitFor(name, muistamov1.InstanceStateSuspended)
	for ctx.Err() == nil && !slices.Contains(f.simulated.Recorded(), "revoke "+name) {
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("leaver event to suspended and revoked: %s", time.Since(start).Round(time.Millisecond))

	// Rehire inside the grace period signals the waiting leaver workflow instead of a new joiner.
	if id := accept(event("join-2", muistamov1.HREventTypeJoiner)); id != leaverID {
		t.Fatalf("rehire went to %s, want the waiting leaver workflow %s", id, leaverID)
	}
	var result lifecycle.LeaverResult
	if err := temporal.GetWorkflow(ctx, leaverID, "").Get(ctx, &result); err != nil || !result.Rehired {
		t.Fatalf("leaver result = %+v, %v; want rehired", result, err)
	}
	waitFor(name, muistamov1.InstanceStateActive)

	events, err := f.svc.ListEvents(ctx, reader, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidencechain.Verify(events, map[string]ed25519.PublicKey{f.key.KeyID(): f.key.Public()}); err != nil {
		t.Fatalf("evidence chain: %v", err)
	}
	var actions []string
	for _, e := range events {
		actions = append(actions, e.Action)
	}
	for _, want := range []string{"hr.event.received", "instance.created", "identity.provisioned", "credentials.revoked", "personal-layer.review-not-opened", "identity.enabled"} {
		if !slices.Contains(actions, want) {
			t.Errorf("evidence lacks %s: %v", want, actions)
		}
	}
}

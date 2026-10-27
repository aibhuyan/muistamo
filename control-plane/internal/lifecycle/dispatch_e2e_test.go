package lifecycle_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

type pausedHRActivities struct {
	*lifecycle.Activities
	joiner           bool
	entered, release chan struct{}
}

func (a *pausedHRActivities) pause(ctx context.Context) error {
	close(a.entered)
	select {
	case <-a.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *pausedHRActivities) MatchTemplates(ctx context.Context, scope lifecycle.Scope, code string) ([]registry.TemplateVersionRef, error) {
	if a.joiner {
		if err := a.pause(ctx); err != nil {
			return nil, err
		}
	}
	return a.Activities.MatchTemplates(ctx, scope, code)
}

func (a *pausedHRActivities) OpenPersonalLayerReview(ctx context.Context, scope lifecycle.Scope, person lifecycle.Person, instances []string) (lifecycle.ReviewOpened, error) {
	if !a.joiner {
		if err := a.pause(ctx); err != nil {
			return lifecycle.ReviewOpened{}, err
		}
	}
	return a.Activities.OpenPersonalLayerReview(ctx, scope, person, instances)
}

func TestHRDispatchedChildBlocksErasure(t *testing.T) {
	for _, joiner := range []bool{true, false} {
		name := "manager-leaver"
		if joiner {
			name = "own-joiner"
		}
		t.Run(name, func(t *testing.T) {
			address := os.Getenv("MUISTAMO_TEST_TEMPORAL_ADDRESS")
			if address == "" {
				address = "127.0.0.1:7233"
			}
			c, err := client.Dial(client.Options{HostPort: address})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			f := setup(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
				t.Fatal(err)
			}
			acts := &pausedHRActivities{Activities: f.acts, joiner: joiner, entered: make(chan struct{}), release: make(chan struct{})}
			queue := "hr-erasure-" + uuid.NewString()
			w := worker.New(c, queue, worker.Options{})
			w.RegisterWorkflow(lifecycle.Joiner)
			w.RegisterWorkflow(lifecycle.Leaver)
			w.RegisterWorkflow(lifecycle.HRDispatch)
			w.RegisterActivity(acts)
			if err := w.Start(); err != nil {
				t.Fatal(err)
			}
			defer w.Stop()
			released := false
			defer func() {
				if !released {
					close(acts.release)
				}
			}()
			e := intakeEvent("paused", muistamov1.HREventTypeJoiner, 0)
			email := e.Person.Email
			if !joiner {
				e.Type = muistamov1.HREventTypeLeaver
				email = "manager@example.invalid"
				e.Person.ManagerEmail = &email
			}
			in := newIntake(t, f, lifecycle.TemporalDispatcher{Client: c, TaskQueue: queue})
			r, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "paused", e)
			if err != nil || r.DispatchState != "dispatched" {
				t.Fatalf("handoff: %+v %v", r, err)
			}
			select {
			case <-acts.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var req muistamov1.ErasureRequest
			req.Id = uuid.New()
			req.Reason = "test retirement"
			req.Subject.Email = email
			req.Subject.Identities = []string{"dev:" + email}
			if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); !errors.Is(err, registry.ErrConflict) {
				t.Fatalf("erasure passed a dispatched child holding personal data: %v", err)
			}
			close(acts.release)
			released = true
			if err := c.GetWorkflow(ctx, r.WorkflowId, "").Get(ctx, nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase-after-setup"}, req); err != nil {
				t.Fatalf("completed setup did not release privacy fence: %v", err)
			}
		})
	}
}

func TestHRClosedHandoffCannotStartAnotherExecution(t *testing.T) {
	address := os.Getenv("MUISTAMO_TEST_TEMPORAL_ADDRESS")
	if address == "" {
		address = "127.0.0.1:7233"
	}
	c, err := client.Dial(client.Options{HostPort: address})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	f := setup(t)
	f.template(t, "analyst", "INTERN")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	queue := "hr-dispatch-test-" + uuid.NewString()
	w := worker.New(c, queue, worker.Options{})
	w.RegisterWorkflow(lifecycle.Joiner)
	w.RegisterWorkflow(lifecycle.Leaver)
	w.RegisterWorkflow(lifecycle.HRDispatch)
	w.RegisterActivity(f.acts)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	defer w.Stop()
	in := newIntake(t, f, lifecycle.TemporalDispatcher{Client: c, TaskQueue: queue})
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 3}
	e := intakeEvent("join", muistamov1.HREventTypeJoiner, 0)
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "first", e); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("result persistence did not fail: %v", err)
	}
	workflowID := lifecycle.JoinerWorkflowID(f.scope.Tenant, e.Id)
	var names []string
	if err := c.GetWorkflow(ctx, workflowID, "").Get(ctx, &names); err != nil {
		t.Fatal(err)
	}
	before, err := c.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil {
		t.Fatal(err)
	}
	in.Signer = f.key
	// A newer accepted leaver must not prevent read-only reconciliation of the old result.
	firstLeave := intakeEvent("leave-first", muistamov1.HREventTypeLeaver, 1)
	r1, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "leave1", firstLeave)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CancelWorkflow(context.Background(), r1.WorkflowId, "") }()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "retry", e); err != nil {
		t.Fatal(err)
	}
	after, err := c.DescribeWorkflowExecution(ctx, workflowID, "")
	if err != nil {
		t.Fatal(err)
	}
	if before.WorkflowExecutionInfo.Execution.RunId != after.WorkflowExecutionInfo.Execution.RunId {
		t.Fatal("pending handoff retry started a second closed joiner execution")
	}
	laterLeave := intakeEvent("leave-later", muistamov1.HREventTypeLeaver, 2)
	r2, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "leave2", laterLeave)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CancelWorkflow(context.Background(), r2.WorkflowId, "") }()
	if r1.WorkflowId == r2.WorkflowId {
		t.Fatal("a later accepted leaver reused an older snapshot")
	}
	// Both leaver snapshots must receive the rehire once, even if the DB result write is lost.
	rehire := intakeEvent("rehire", muistamov1.HREventTypeJoiner, 3)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 3}
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "rehire", rehire); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("rehire result failure=%v", err)
	}
	for _, id := range []string{r1.WorkflowId, r2.WorkflowId} {
		var result lifecycle.LeaverResult
		if err := c.GetWorkflow(ctx, id, "").Get(ctx, &result); err != nil || !result.Rehired {
			t.Fatalf("rehire snapshot %s: %+v %v", id, result, err)
		}
	}
	in.Signer = f.key
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "rehire-retry", rehire); err != nil {
		t.Fatal(err)
	}
	_, err = c.DescribeWorkflowExecution(ctx, lifecycle.JoinerWorkflowID(f.scope.Tenant, rehire.Id), "")
	var absent *serviceerror.NotFound
	if !errors.As(err, &absent) {
		t.Fatalf("ambiguous rehire retry started a new joiner: %v", err)
	}
}

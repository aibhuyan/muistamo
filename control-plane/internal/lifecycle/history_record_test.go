//go:build recordhistory

package lifecycle_test

// Records real Temporal histories of the live (Entra) workflows for the replay test
// (history_replay_test.go). Not part of any normal test run: it needs a Temporal server.
//
//	MUISTAMO_RECORD_DIR=control-plane/internal/lifecycle/testdata/histories \
//	MUISTAMO_RECORD_SET=current MUISTAMO_E2E_GRACE_SECONDS=2 \
//	go test -tags 'recordhistory e2e' -run TestRecordHistories ./control-plane/internal/lifecycle/
//
// Activities are stubs registered under the workflows' activity names, so this file compiles
// against older trees too: to record what an earlier release left in flight, copy it into a
// worktree at that commit and run it there without the e2e tag (MUISTAMO_RECORD_SET=<name>).
// Histories hold only fixed test identifiers.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"google.golang.org/protobuf/encoding/protojson"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

var (
	recordRef    = muistamov1.EntraLifecycleRef{TenantId: uuid.MustParse("11111111-1111-4111-8111-111111111111"), ReceiptId: uuid.MustParse("22222222-2222-4222-8222-222222222222")}
	recordRehire = muistamov1.EntraLifecycleRef{TenantId: recordRef.TenantId, ReceiptId: uuid.MustParse("33333333-3333-4333-8333-333333333333")}
)

type ref = muistamov1.EntraLifecycleRef

// stubs registers every live activity a release may call, by name, with fixed results.
func stubs(w worker.Worker, instances []string, kept bool) {
	none := func(context.Context, ref) error { return nil }
	named := func(context.Context, ref, string) error { return nil }
	for _, name := range []string{"EntraRecordReviewCoverage", "EntraSettleSetup", "EntraLinkUser", "EntraUnlinkUser", "EntraFenceReview", "EntraRecordFenceFailure"} {
		w.RegisterActivityWithOptions(none, activity.RegisterOptions{Name: name})
	}
	for _, name := range []string{"EntraDisable", "EntraRevoke", "EntraRetire", "EntraCreate", "EntraEnable", "EntraActivate"} {
		w.RegisterActivityWithOptions(named, activity.RegisterOptions{Name: name})
	}
	w.RegisterActivityWithOptions(func(context.Context, ref) ([]string, error) { return instances, nil }, activity.RegisterOptions{Name: "EntraPrepareLeaver"})
	w.RegisterActivityWithOptions(func(context.Context, ref, ref) error { return nil }, activity.RegisterOptions{Name: "EntraConfirmRehire"})
	w.RegisterActivityWithOptions(func(context.Context, ref) (lifecycle.ReviewOpened, error) {
		return lifecycle.ReviewOpened{ID: "entra-leaver:" + recordRef.ReceiptId.String(), Opened: true}, nil
	}, activity.RegisterOptions{Name: "EntraOpenReview"})
	w.RegisterActivityWithOptions(func(context.Context, ref, string) (lifecycle.ReviewState, error) {
		if kept {
			return lifecycle.ReviewState{Deadline: time.Now().Add(30 * 24 * time.Hour)}, nil
		}
		return lifecycle.ReviewState{Closed: true}, nil
	}, activity.RegisterOptions{Name: "EntraExpireReview"})
	w.RegisterActivityWithOptions(func(context.Context, ref) ([]registry.TemplateVersionRef, error) {
		return []registry.TemplateVersionRef{{Name: "analyst", Version: 1}}, nil
	}, activity.RegisterOptions{Name: "EntraMatchTemplates"})
	w.RegisterActivityWithOptions(func(context.Context, ref, registry.TemplateVersionRef) (string, error) {
		return "analyst-e-1001", nil
	}, activity.RegisterOptions{Name: "EntraEnsureInstance"})
}

func TestRecordHistories(t *testing.T) {
	dir, set := os.Getenv("MUISTAMO_RECORD_DIR"), os.Getenv("MUISTAMO_RECORD_SET")
	if dir == "" || set == "" {
		t.Fatal("set MUISTAMO_RECORD_DIR and MUISTAMO_RECORD_SET")
	}
	// A fixed identity: the default names this machine, which has no place in the repository.
	c, err := client.Dial(client.Options{HostPort: "127.0.0.1:7233", Identity: "history-recorder"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()

	scenarios := []struct {
		name      string
		workflow  any
		instances []string
		kept      bool
		// until reports the history is ready to record; signal, if set, runs once the leaver waits.
		until  func([]*historypb.HistoryEvent) bool
		signal bool
	}{
		{name: "leaver-in-grace", workflow: lifecycle.EntraLeaver, instances: []string{"one"}, until: timers(1)},
		{name: "leaver-rehired-in-grace", workflow: lifecycle.EntraLeaver, instances: []string{"one"}, until: completed, signal: true},
		{name: "joiner", workflow: lifecycle.EntraJoiner, until: completed},
	}
	if set == "current" {
		// Grace elapses (e2e build, short grace); the decider kept the layer, so the run waits.
		scenarios = append(scenarios, struct {
			name      string
			workflow  any
			instances []string
			kept      bool
			until     func([]*historypb.HistoryEvent) bool
			signal    bool
		}{name: "leaver-waiting-for-a-kept-review", workflow: lifecycle.EntraLeaver, kept: true, until: timers(2)})
	}
	for _, s := range scenarios {
		queue := "history-record-" + uuid.NewString()
		w := worker.New(c, queue, worker.Options{Identity: "history-recorder"})
		w.RegisterWorkflow(lifecycle.EntraLeaver)
		w.RegisterWorkflow(lifecycle.EntraJoiner)
		stubs(w, s.instances, s.kept)
		if err := w.Start(); err != nil {
			t.Fatal(err)
		}
		id := "history-" + set + "-" + s.name + "-" + uuid.NewString()
		run, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue}, s.workflow, recordRef)
		if err != nil {
			t.Fatal(err)
		}
		if s.signal {
			wait(t, c, id, timers(1))
			if err := c.SignalWorkflow(ctx, id, run.GetRunID(), lifecycle.EntraRehiredSignal, recordRehire); err != nil {
				t.Fatal(err)
			}
		}
		events := wait(t, c, id, s.until)
		raw, err := protojson.MarshalOptions{Indent: "  "}.Marshal(&historypb.History{Events: events})
		if err != nil {
			t.Fatal(err)
		}
		// Sticky task queues are named after the host; replay does not depend on the name.
		if host, err := os.Hostname(); err == nil && host != "" {
			raw = bytes.ReplaceAll(raw, []byte(host), []byte("recorder-host"))
			if bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(host))) {
				t.Fatalf("the history still names this machine")
			}
		}
		if err := os.WriteFile(filepath.Join(dir, set+"-"+s.name+".json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = c.TerminateWorkflow(ctx, id, "", "history recorded")
		w.Stop()
		t.Logf("recorded %s-%s: %d events", set, s.name, len(events))
	}
}

func wait(t *testing.T, c client.Client, id string, until func([]*historypb.HistoryEvent) bool) []*historypb.HistoryEvent {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		var events []*historypb.HistoryEvent
		it := c.GetWorkflowHistory(context.Background(), id, "", false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
		for it.HasNext() {
			e, err := it.Next()
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, e)
		}
		if until(events) {
			return events
		}
	}
	t.Fatalf("%s did not reach the state to record", id)
	return nil
}

// timers is ready once n timers have started and the last workflow task has completed, so the
// workflow is waiting on the latest one.
func timers(n int) func([]*historypb.HistoryEvent) bool {
	return func(events []*historypb.HistoryEvent) bool {
		started := 0
		for _, e := range events {
			if e.GetEventType() == enumspb.EVENT_TYPE_TIMER_STARTED {
				started++
			}
		}
		return started >= n && len(events) > 0 && events[len(events)-1].GetEventType() == enumspb.EVENT_TYPE_TIMER_STARTED
	}
}

func completed(events []*historypb.HistoryEvent) bool {
	return len(events) > 0 && events[len(events)-1].GetEventType() == enumspb.EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED
}

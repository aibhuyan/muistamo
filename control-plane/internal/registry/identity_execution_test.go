package registry_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

type identityNthSigner struct {
	evidence.LocalKey
	count  atomic.Int32
	failAt int32
}

type identityGateSigner struct {
	evidence.LocalKey
	entered, release chan struct{}
}

func (s *identityGateSigner) Sign(data []byte) ([]byte, error) {
	close(s.entered)
	<-s.release
	return s.LocalKey.Sign(data)
}

func (s *identityNthSigner) Sign(data []byte) ([]byte, error) {
	if s.count.Add(1) == s.failAt {
		return nil, errors.New("fake result signer failure")
	}
	return s.LocalKey.Sign(data)
}

func TestIdentityExecutionCallsProviderOnceUnderConcurrency(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	var calls atomic.Int32
	provider := func(_ context.Context, op muistamov1.IdentityOperationStatus, owned muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		if op.CreationId != op.Id || owned.CreationId == nil || *owned.CreationId != op.Id {
			t.Error("provider invoked without original durable creation marker")
		}
		calls.Add(1)
		return uuid.New(), "disabled", nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := f.svc.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", provider)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("provider called %d times for one committed intent", calls.Load())
	}
}

func TestIdentityExecutionResultFailureNeverRepeatsMutation(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	var calls int
	broken := registry.New(f.conn, &identityNthSigner{LocalKey: f.key, failAt: 2})
	provider := func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		calls++
		return uuid.New(), "disabled", nil
	}
	op, called, err := broken.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", provider)
	if !called || !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("result-signing failure was not surfaced: called=%v err=%v", called, err)
	}
	if stored, err := f.svc.IdentityOperation(ctx, f.actor, op.Id); err != nil || stored.State != "pending" {
		t.Fatalf("lost result was not pending: %+v %v", stored, err)
	}
	if _, called, err := f.svc.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", provider); err != nil || called {
		t.Fatalf("uncertain intent replayed provider: called=%v err=%v", called, err)
	}
	if calls != 1 {
		t.Fatalf("mutation repeated after result loss: %d", calls)
	}
}

func TestIdentityExecutionCrashRetainsConsumedIntent(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	calls := 0
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected artificial callback crash")
			}
		}()
		_, _, _ = f.svc.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
			calls++
			panic("artificial crash after provider effect")
		})
	}()
	if _, called, err := f.svc.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		calls++
		return uuid.New(), "disabled", nil
	}); err != nil || called {
		t.Fatalf("crashed invocation was started again: called=%v err=%v", called, err)
	}
	if calls != 1 {
		t.Fatalf("crash caused another mutation: %d", calls)
	}
}

func TestIdentityExecutionIntentFailureMakesNoProviderCall(t *testing.T) {
	f, _, r := liveIdentity(t)
	broken := registry.New(f.conn, &identityNthSigner{LocalKey: f.key, failAt: 1})
	_, called, err := broken.RunIdentityMutation(context.Background(), f.actor, r.Document.Metadata.Name, "join", 1, "create", func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		t.Error("provider called without persisted signed intent")
		return uuid.New(), "disabled", nil
	})
	if called || !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned intent permitted execution: called=%v err=%v", called, err)
	}
}

func TestIdentityExecutionCallbackHasBoundedDeadline(t *testing.T) {
	f, _, r := liveIdentity(t)
	_, called, err := f.svc.RunIdentityMutation(context.Background(), f.actor, r.Document.Metadata.Name, "join", 1, "create", func(ctx context.Context, _ muistamov1.IdentityOperationStatus, _ muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Error("provider callback lacks bounded overall deadline")
		}
		return uuid.New(), "disabled", nil
	})
	if !called || err != nil {
		t.Fatalf("bounded callback: called=%v err=%v", called, err)
	}
}

func TestIdentityExecutionFencesLeaverThroughProviderResult(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	mutation := make(chan error, 1)
	go func() {
		_, _, err := f.svc.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", func(ctx context.Context, _ muistamov1.IdentityOperationStatus, _ muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
			close(entered)
			select {
			case <-release:
				return uuid.New(), "disabled", nil
			case <-ctx.Done():
				return uuid.Nil, "", ctx.Err()
			}
		})
		mutation <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var event muistamov1.HREvent
	event.Id, event.Type, event.OccurredAt = "leave", "leaver", time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	event.Person.Id, event.Person.Email, event.Person.JobCode = "HR-PERSON", "person-a@example.invalid", "INTERN"
	intake := lifecycle.Intake{DB: f.conn, Signer: f.key}
	accepted := make(chan error, 1)
	go func() { _, err := intake.Accept(ctx, f.actor.Tenant, "hris:test", "leave", event); accepted <- err }()
	monitor, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	defer func() { _ = monitor.Close(context.Background()) }()
	// Observe the actual database wait rather than assuming the intake goroutine was
	// scheduled during a fixed sleep. This also makes removal of the person lock detectable.
	waited := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-accepted:
			close(release)
			t.Fatalf("leaver escaped provider-result fence: %v", err)
		default:
		}
		if err := monitor.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%')`).Scan(&waited); err != nil {
			close(release)
			t.Fatal(err)
		}
		if waited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if !waited {
		t.Fatal("leaver never reached the provider-result lock fence")
	}
	if err := <-mutation; err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatalf("leaver was not accepted after provider result: %v", err)
	}
	if _, called, err := f.svc.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "enable", func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		t.Error("superseded joiner called provider")
		return uuid.New(), "enabled", nil
	}); called || !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("superseded joiner authorized: called=%v err=%v", called, err)
	}
}

func TestIdentityExecutionRechecksHRAfterReservation(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	gate := &identityGateSigner{LocalKey: f.key, entered: make(chan struct{}), release: make(chan struct{})}
	guarded := registry.New(f.conn, gate)
	finished := make(chan error, 1)
	var calls atomic.Int32
	go func() {
		_, _, err := guarded.RunIdentityMutation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create", func(context.Context, muistamov1.IdentityOperationStatus, muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
			calls.Add(1)
			return uuid.Nil, "", errors.New("superseded provider callback must not run")
		})
		finished <- err
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var event muistamov1.HREvent
	event.Id, event.Type, event.OccurredAt = "leave", "leaver", time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	event.Person.Id, event.Person.Email, event.Person.JobCode = "HR-PERSON", "person-a@example.invalid", "INTERN"
	intake := lifecycle.Intake{DB: f.conn, Signer: f.key}
	accepted := make(chan error, 1)
	go func() { _, err := intake.Accept(ctx, f.actor.Tenant, "hris:test", "leave", event); accepted <- err }()
	monitor, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		close(gate.release)
		t.Fatal(err)
	}
	defer func() { _ = monitor.Close(context.Background()) }()
	waited := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if err := monitor.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%')`).Scan(&waited); err != nil {
			close(gate.release)
			t.Fatal(err)
		}
		if waited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Intake is queued on the reservation's person lock before execution can reacquire it.
	close(gate.release)
	if !waited {
		t.Fatal("leaver never queued behind the reservation")
	}
	if err := <-accepted; !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatalf("leaver acceptance failed: %v", err)
	}
	if err := <-finished; !errors.Is(err, registry.ErrConflict) || calls.Load() != 0 {
		t.Fatalf("superseded reservation reached provider: calls=%d err=%v", calls.Load(), err)
	}
}

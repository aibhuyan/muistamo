package lifecycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

type intakeRecorder struct {
	mu     sync.Mutex
	fail   bool
	scopes []lifecycle.Scope
	events []muistamov1.HREvent
}

func (d *intakeRecorder) Dispatch(_ context.Context, scope lifecycle.Scope, event muistamov1.HREvent) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return "", errors.New("fake workflow outage")
	}
	d.scopes = append(d.scopes, scope)
	d.events = append(d.events, event)
	return "workflow-" + scope.EventID, nil
}

func TestIntakeErasureFenceSeparatesPeopleAndTenants(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	ctx := context.Background()
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "manager retirement"
	req.Subject.Email = "manager@example.invalid"
	req.Subject.Identities = []string{"dev:manager@example.invalid"}
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); err != nil {
		t.Fatal(err)
	}
	e := intakeEvent("leave", muistamov1.HREventTypeLeaver, 0)
	e.Person.ManagerEmail = &req.Subject.Email
	r, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "leave", e)
	if err != nil || r.Decision != "accepted" || len(d.events) != 1 || d.events[0].Person.ManagerEmail != nil {
		t.Fatalf("erased manager reference was retained or lost leaver: %+v %v", r, err)
	}
	other, err := store.CreateTenant(ctx, f.db.OwnerURL, "other")
	if err != nil {
		t.Fatal(err)
	}
	e.Id = "other"
	e.Person.Email = req.Subject.Email
	e.Person.ManagerEmail = nil
	r, err = in.Accept(ctx, other, "hris:test", "other", e)
	if err != nil || r.Decision != "accepted" {
		t.Fatalf("another tenant inherited a privacy fence: %+v %v", r, err)
	}
}

func TestIntakeErasureFenceAllowsNewerRehire(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	ctx := context.Background()
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = "person-a@example.invalid"
	req.Subject.Identities = []string{"dev:person-a@example.invalid"}
	person := "HR-1001"
	req.Subject.HrPersonId = &person
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); err != nil {
		t.Fatal(err)
	}
	old := intakeEvent("old", muistamov1.HREventTypeJoiner, 0)
	if r, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "old", old); err != nil || r.Decision != "ignored" {
		t.Fatalf("old data reintroduced: %+v %v", r, err)
	}
	fresh := old
	fresh.Id = "fresh"
	fresh.OccurredAt = time.Now().Add(time.Second)
	if r, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "fresh", fresh); err != nil || r.Decision != "accepted" || len(d.scopes) != 1 {
		t.Fatalf("fresh rehire blocked: %+v %v", r, err)
	}
}

type intakeSigner struct {
	evidence.LocalKey
	count, failAt int
}

type pausedErasureSigner struct {
	evidence.LocalKey
	entered, release chan struct{}
}

func (s *pausedErasureSigner) Sign(digest []byte) ([]byte, error) {
	close(s.entered)
	<-s.release
	return s.LocalKey.Sign(digest)
}

func TestIntakeFirstEventCannotRacePastErasure(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	appURL, err := url.Parse(f.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	application := "hr-race-" + uuid.NewString()
	query := appURL.Query()
	query.Set("application_name", application)
	appURL.RawQuery = query.Encode()
	raceDB, err := store.Open(ctx, appURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raceDB.Close()
	in.DB = raceDB
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	gate := &pausedErasureSigner{LocalKey: f.key, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(gate.release) })
	svc := registry.New(in.DB, gate)
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = "person-a@example.invalid"
	req.Subject.Identities = []string{"dev:person-a@example.invalid"}
	person := "HR-1001"
	req.Subject.HrPersonId = &person
	erased := make(chan error, 1)
	go func() {
		_, _, err := svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req)
		erased <- err
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("erasure did not reach commit barrier")
	}
	type result struct {
		receipt muistamov1.HREventAccepted
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		r, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "concurrent", intakeEvent("first", muistamov1.HREventTypeJoiner, 0))
		accepted <- result{r, err}
	}()
	// Observe the competing transaction blocked in PostgreSQL before releasing erasure.
	// This also exposes the unsafe interleaving if both privacy locks are removed: intake
	// advances to its evidence write and waits on erasure's chain-head transaction instead.
	observer, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(ctx) }()
	blocked := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := observer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock')`, application).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("concurrent intake did not reach the erasure transaction barrier")
	}
	release.Do(func() { close(gate.release) })
	if err := <-erased; err != nil {
		t.Fatal(err)
	}
	r := <-accepted
	if r.err != nil || r.receipt.Decision != "ignored" || len(d.scopes) != 0 {
		t.Fatalf("pre-erasure first event escaped fence: %+v %v scopes=%+v", r.receipt, r.err, d.scopes)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE payload::text LIKE '%person-a@example.invalid%'`); n != 0 {
		t.Fatal("erased email returned in ignored event payload")
	}
}

func (s *intakeSigner) Sign(digest []byte) ([]byte, error) {
	s.count++
	if s.count == s.failAt {
		return nil, errors.New("fake signing failure")
	}
	return s.LocalKey.Sign(digest)
}

func intakeEvent(id string, kind muistamov1.HREventType, seconds int) muistamov1.HREvent {
	var e muistamov1.HREvent
	e.Id = id
	e.Type = kind
	e.OccurredAt = time.Date(2026, 10, 27, 9, 0, seconds, 0, time.UTC)
	e.Person.Id = "HR-1001"
	e.Person.Email = "person-a@example.invalid"
	e.Person.JobCode = "INTERN"
	return e
}

func newIntake(t *testing.T, f fixture, d lifecycle.Dispatcher) *lifecycle.Intake {
	t.Helper()
	db, err := store.Open(context.Background(), f.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return &lifecycle.Intake{DB: db, Signer: f.key, Dispatcher: d}
}

func TestIntakeEvidenceFailurePreventsDispatch(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 1}
	_, err := in.Accept(context.Background(), f.scope.Tenant, "hris:test", "req", intakeEvent("join", muistamov1.HREventTypeJoiner, 0))
	if !errors.Is(err, evidence.ErrNotRecorded) || len(d.scopes) != 0 {
		t.Fatalf("err=%v dispatches=%d", err, len(d.scopes))
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events`); n != 0 {
		t.Fatal("unsigned HR decision committed")
	}
}

func TestIntakeDispatchIntentFailurePreventsHandoff(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 2}
	_, err := in.Accept(context.Background(), f.scope.Tenant, "hris:test", "req", intakeEvent("join", muistamov1.HREventTypeJoiner, 0))
	if !errors.Is(err, evidence.ErrNotRecorded) || len(d.scopes) != 0 {
		t.Fatalf("unsigned handoff intent reached dispatcher: %v %+v", err, d.scopes)
	}
}

func TestIntakeErasureRefusesUnresolvedHandoff(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatal(err)
	}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = "person-a@example.invalid"
	req.Subject.Identities = []string{"dev:person-a@example.invalid"}
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); err == nil {
		t.Fatal("erasure claimed completion despite an unresolved external handoff")
	}
}

func TestIntakeSetupCompletionRequiresEvidenceAndMatchingReceipt(t *testing.T) {
	f := setup(t)
	in := newIntake(t, f, &intakeRecorder{})
	ctx := context.Background()
	e := intakeEvent("setup", muistamov1.HREventTypeLeaver, 0)
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "setup", e); err != nil {
		t.Fatal(err)
	}
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "workflow:test", RequestID: "setup"}
	if err := f.svc.SettleHRSetup(ctx, actor, e.Id, 2); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("wrong generation settled: %v", err)
	}
	failed := registry.New(in.DB, &intakeSigner{LocalKey: f.key, failAt: 1})
	if err := failed.SettleHRSetup(ctx, actor, e.Id, 1); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned setup succeeded: %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE setup_completed_at IS NOT NULL`); n != 0 {
		t.Fatal("failed evidence released erasure fence")
	}
	if err := f.svc.SettleHRSetup(ctx, actor, e.Id, 1); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SettleHRSetup(ctx, actor, e.Id, 1); err != nil {
		t.Fatal(err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='hr.event.setup-completed'`); n != 1 {
		t.Fatalf("setup evidence count=%d", n)
	}
	if err := in.DB.InTenant(ctx, f.scope.Tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE hr_events SET setup_completed_at=NULL WHERE event_id='setup'`)
		return err
	}); err == nil {
		t.Fatal("completed setup reset")
	}
}

func TestIntakeLegacyErasureRequiresReconciliation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	e := intakeEvent("legacy", muistamov1.HREventTypeJoiner, 0)
	payload, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close(ctx) }()
	if _, err := owner.Exec(ctx, `INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at) VALUES($1,$2,'joiner',$3,'legacy-workflow',$4,$5)`, f.scope.Tenant, e.Id, e.Person.Id, payload, e.OccurredAt); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = e.Person.Email
	req.Subject.Identities = []string{"dev:" + e.Person.Email}
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("legacy workflow with unknown setup passed erasure: %v", err)
	}
}

func TestIntakeAttemptMarkerCannotReset(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatal(err)
	}
	err := in.DB.InTenant(ctx, f.scope.Tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE hr_events SET dispatch_attempted_at=NULL WHERE event_id='join'`)
		return err
	})
	if err == nil {
		t.Fatal("application role reset a durable handoff attempt")
	}
}

func TestIntakeErasureByHRKeyCancelsUnattemptedWork(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 2}
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatal(err)
	}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = "old-alias@example.invalid"
	req.Subject.Identities = []string{"dev:old-alias@example.invalid"}
	person := "HR-1001"
	req.Subject.HrPersonId = &person
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); err != nil {
		t.Fatal(err)
	}
	in.Signer = f.key
	if out, err := in.RetryPending(ctx, f.scope.Tenant, "operator:test", "retry", 100); err != nil || len(out) != 0 || len(d.scopes) != 0 {
		t.Fatalf("erased HR-key work replayed: %+v %v", out, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE payload->'person'->>'email'='person-a@example.invalid'`); n != 0 {
		t.Fatal("HR-key erasure left the employee's stored email")
	}
}

func TestIntakeResolvedAliasCannotEraseAnActiveManualInstance(t *testing.T) {
	f := setup(t)
	f.template(t, "analyst", "INTERN")
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 2}
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatal(err)
	}
	var doc muistamov1.AgentInstance
	doc.ApiVersion = muistamov1.AgentInstanceApiVersionMuistamoDevv1
	doc.Kind = muistamov1.AgentInstanceKindAgentInstance
	doc.Metadata.Name = "manual-person"
	doc.Spec.TemplateRef.Name = "analyst"
	doc.Spec.TemplateRef.Version = "1"
	doc.Spec.Binding.Type = muistamov1.AgentInstanceSpecBindingTypeUser
	doc.Spec.Binding.Ref = "person-a@example.invalid"
	doc.Spec.State = muistamov1.InstanceStateRequested
	if _, _, err := f.svc.ApplyInstance(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:seed", RequestID: "seed"}, doc, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = "old-alias@example.invalid"
	req.Subject.Identities = []string{"dev:old-alias@example.invalid"}
	person := "HR-1001"
	req.Subject.HrPersonId = &person
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("active resolved alias escaped erasure check: %v", err)
	}
}

func TestIntakeResultEvidenceFailureStaysPending(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 3}
	_, err := in.Accept(context.Background(), f.scope.Tenant, "hris:test", "req", intakeEvent("join", muistamov1.HREventTypeJoiner, 0))
	if !errors.Is(err, evidence.ErrNotRecorded) || len(d.scopes) != 1 {
		t.Fatalf("err=%v dispatches=%d", err, len(d.scopes))
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE dispatch_state='pending'`); n != 1 {
		t.Fatal("unsigned handoff result reported as dispatched")
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='hr.event.received'`); n != 1 {
		t.Fatal("committed acceptance was lost")
	}
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 1}
	if receipts, err := in.RetryPending(context.Background(), f.scope.Tenant, "operator:test", "retry", 100); err == nil || len(receipts) != 0 {
		t.Fatalf("uncommitted success leaked in recovery output: %+v %v", receipts, err)
	}
}

func TestIntakeCommitFailurePublishesNoRecoverySuccess(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	ctx := context.Background()
	db, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	if _, err := db.Exec(ctx, `CREATE FUNCTION reject_dispatch_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.dispatch_state='dispatched' THEN RAISE EXCEPTION 'fake deferred commit failure'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER reject_dispatch_commit AFTER UPDATE ON hr_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_dispatch_commit()`); err != nil {
		t.Fatal(err)
	}
	if receipt, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "req", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); err == nil || receipt.DispatchState == "dispatched" {
		t.Fatalf("commit-uncertain success=%+v %v", receipt, err)
	}
	if out, err := in.RetryPending(ctx, f.scope.Tenant, "operator:test", "retry", 100); err == nil || len(out) != 0 {
		t.Fatalf("uncommitted recovery output=%+v %v", out, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='hr.event.dispatched'`); n != 0 {
		t.Fatal("failed result commit left success evidence")
	}
}

func TestIntakeLegacyFractionalTimestampLeaverWinsTie(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	ctx := context.Background()
	legacy := intakeEvent("legacy", muistamov1.HREventTypeJoiner, 0)
	legacy.OccurredAt = legacy.OccurredAt.Add(900 * time.Nanosecond)
	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close(ctx) }()
	if _, err := db.Exec(ctx, `INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at) VALUES($1,'legacy','joiner',$2,'legacy-workflow',$3,($3::jsonb->>'occurredAt')::timestamptz)`, f.scope.Tenant, legacy.Person.Id, payload); err != nil {
		t.Fatal(err)
	}
	leaver := legacy
	leaver.Id = "leave"
	leaver.Type = muistamov1.HREventTypeLeaver
	r, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "leave", leaver)
	if err != nil || r.Decision != "accepted" || len(d.scopes) != 1 {
		t.Fatalf("equal source time lost leaver precedence: %+v %v", r, err)
	}
}

func TestIntakePendingHandoffSurvivesRestart(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	if _, err := in.Accept(context.Background(), f.scope.Tenant, "hris:test", "req", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatalf("err=%v", err)
	}
	recovered := &intakeRecorder{}
	restarted := newIntake(t, f, recovered)
	receipts, err := restarted.RetryPending(context.Background(), f.scope.Tenant, "operator:test", "retry", 100)
	if err != nil || len(receipts) != 1 || receipts[0].DispatchState != "dispatched" || len(recovered.scopes) != 1 || recovered.scopes[0].Generation != 1 {
		t.Fatalf("receipts=%+v scopes=%+v err=%v", receipts, recovered.scopes, err)
	}
	if again, err := restarted.RetryPending(context.Background(), f.scope.Tenant, "operator:test", "retry-again", 100); err != nil || len(again) != 0 {
		t.Fatalf("replayed completed handoff: %+v %v", again, err)
	}
}

func TestIntakeSupersededPendingJoinerNeverDispatches(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 2}
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatal(err)
	}
	d.fail = false
	in.Signer = f.key
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r2", intakeEvent("leave", muistamov1.HREventTypeLeaver, 1)); err != nil {
		t.Fatal(err)
	}
	out, err := in.RetryPending(ctx, f.scope.Tenant, "operator:test", "retry", 100)
	if err != nil || len(out) != 1 || out[0].DispatchState != "cancelled" || len(d.scopes) != 1 || d.scopes[0].EventID != "leave" {
		t.Fatalf("out=%+v scopes=%+v err=%v", out, d.scopes, err)
	}
}

func TestIntakeRehireWaitsForPendingLeaver(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("leave", muistamov1.HREventTypeLeaver, 0)); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatal(err)
	}
	d.fail = false
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r2", intakeEvent("rehire", muistamov1.HREventTypeJoiner, 1)); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatalf("rehire overtook pending leaver: %v", err)
	}
	if _, err := in.RetryPending(ctx, f.scope.Tenant, "operator:test", "retry", 100); err != nil {
		t.Fatal(err)
	}
	if len(d.scopes) != 2 || d.scopes[0].EventID != "leave" || d.scopes[1].EventID != "rehire" {
		t.Fatalf("handoff order=%+v", d.scopes)
	}
}

func TestIntakeConcurrentEqualJoinersHaveOneGeneration(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	var group sync.WaitGroup
	for i := range 6 {
		group.Go(func() {
			if _, err := in.Accept(context.Background(), f.scope.Tenant, "hris:test", fmt.Sprint(i), intakeEvent(fmt.Sprint(i), muistamov1.HREventTypeJoiner, 0)); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if len(d.scopes) != 1 {
		t.Fatalf("dispatches=%d", len(d.scopes))
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE decision='accepted' AND generation=1`); n != 1 {
		t.Fatal("concurrent decisions did not serialize")
	}
}

func TestIntakeErasureCancelsPendingWork(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 2}
	ctx := context.Background()
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "r1", intakeEvent("join", muistamov1.HREventTypeJoiner, 0)); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatal(err)
	}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "test retirement"
	req.Subject.Email = "person-a@example.invalid"
	req.Subject.Identities = []string{"dev:person-a@example.invalid"}
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); err != nil {
		t.Fatal(err)
	}
	d.fail = false
	in.Signer = f.key
	if out, err := in.RetryPending(ctx, f.scope.Tenant, "operator:test", "retry", 100); err != nil || len(out) != 0 || len(d.scopes) != 0 {
		t.Fatalf("erased work replayed: %+v %v", out, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE dispatch_state='cancelled'`); n != 1 {
		t.Fatal("pending job was not cancelled by erasure")
	}
}

func TestIntakeManagerErasurePreservesSubordinateLeaver(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	in.Signer = &intakeSigner{LocalKey: f.key, failAt: 2}
	ctx := context.Background()
	e := intakeEvent("leave", muistamov1.HREventTypeLeaver, 0)
	manager := "manager@example.invalid"
	e.Person.ManagerEmail = &manager
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "leave", e); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatal(err)
	}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "manager retirement"
	req.Subject.Email = manager
	req.Subject.Identities = []string{"dev:" + manager}
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); err != nil {
		t.Fatal(err)
	}
	d.fail = false
	in.Signer = f.key
	out, err := in.RetryPending(ctx, f.scope.Tenant, "operator:test", "retry", 100)
	if err != nil || len(out) != 1 || out[0].DispatchState != "dispatched" || len(d.scopes) != 1 {
		t.Fatalf("manager erasure lost another person's leaver: %+v %v", out, err)
	}
	if len(d.events) != 1 || d.events[0].Person.ManagerEmail != nil {
		t.Fatal("erased manager was forwarded as a decider instead of allowing fallback")
	}
}

func TestIntakeManagerErasureRefusesCapturedHandoff(t *testing.T) {
	f := setup(t)
	d := &intakeRecorder{fail: true}
	in := newIntake(t, f, d)
	ctx := context.Background()
	e := intakeEvent("leave", muistamov1.HREventTypeLeaver, 0)
	manager := "manager@example.invalid"
	e.Person.ManagerEmail = &manager
	if _, err := in.Accept(ctx, f.scope.Tenant, "hris:test", "leave", e); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatal(err)
	}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.scope.Tenant, []string{"operator:dpo"}); err != nil {
		t.Fatal(err)
	}
	var req muistamov1.ErasureRequest
	req.Id = uuid.New()
	req.Reason = "manager retirement"
	req.Subject.Email = manager
	req.Subject.Identities = []string{"dev:" + manager}
	if _, _, err := f.svc.Erase(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "operator:dpo", RequestID: "erase"}, req); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("captured manager data escaped erasure guard: %v", err)
	}
}

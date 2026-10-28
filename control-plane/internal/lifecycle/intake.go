package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

var (
	// ErrNoSecret means the tenant has no HR secret, so no HR event can be authenticated.
	ErrNoSecret = errors.New("tenant has no HR secret")
	// ErrDispatch means the workflow engine could not take the event; the HRIS should retry.
	ErrDispatch = errors.New("workflow engine unavailable")
	// ErrHandoffUncertain requires reconciliation rather than another blind workflow start.
	ErrHandoffUncertain = errors.New("HR handoff requires operator reconciliation")
)

// Dispatcher hands an HR event to the right workflow. It must be idempotent per event.
type Dispatcher interface {
	Dispatch(ctx context.Context, scope Scope, event muistamov1.HREvent) (workflowID string, err error)
}

// Intake receives authenticated HR events.
type Intake struct {
	DB         *store.DB
	Signer     evidence.Signer
	Dispatcher Dispatcher
}

// Secret returns the tenant's HR secret.
func (in *Intake) Secret(ctx context.Context, tenant uuid.UUID) ([]byte, error) {
	var secret []byte
	err := in.DB.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT secret FROM hr_webhook_secrets`).Scan(&secret)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoSecret
		}
		return err
	})
	return secret, err
}

// Accept commits the HR decision and signed receipt BEFORE dispatching. Pending handoffs survive
// errors/restarts and a redelivery retries them. Completed/ignored events do not dispatch again.
// This is acceptance ordering; the live worker must also consume/fence the recorded generation.
func (in *Intake) Accept(ctx context.Context, tenant uuid.UUID, actor, requestID string, event muistamov1.HREvent) (muistamov1.HREventAccepted, error) {
	var receipt muistamov1.HREventAccepted
	payload, err := json.Marshal(event)
	if err != nil || contracts.ValidateAgainst("hrevent.json", payload) != nil {
		return receipt, errors.New("invalid HR event")
	}
	err = in.DB.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		ownKeys := []string{store.HRFenceKey(tenant, "hr-person", event.Person.Id), store.HRFenceKey(tenant, "identifier", event.Person.Email)}
		managerKeys := []string{}
		if event.Person.ManagerEmail != nil {
			managerKeys = append(managerKeys, store.HRFenceKey(tenant, "identifier", *event.Person.ManagerEmail))
		}
		before, err := store.HRFenceTime(ctx, tx, ownKeys)
		if err != nil {
			return err
		}
		managerBefore, err := store.HRFenceTime(ctx, tx, managerKeys)
		if err != nil {
			return err
		}
		if err := store.LockHRPrivacy(ctx, tx, tenant, false); err != nil {
			return err
		}
		// Use the same PostgreSQL parser as legacy backfill, including fractional rounding.
		var occurred time.Time
		if err := tx.QueryRow(ctx, `SELECT $1::timestamptz`, event.OccurredAt.UTC().Format(time.RFC3339Nano)).Scan(&occurred); err != nil {
			return fmt.Errorf("normalize HR source time: %w", err)
		}
		after, err := store.HRFenceTime(ctx, tx, ownKeys)
		if err != nil {
			return err
		}
		privacyBlocked := hrSourceErased(occurred, before, after)
		managerAfter, err := store.HRFenceTime(ctx, tx, managerKeys)
		if err != nil {
			return err
		}
		if hrSourceErased(occurred, managerBefore, managerAfter) {
			event.Person.ManagerEmail = nil
		}
		if privacyBlocked {
			payload = []byte(`{}`)
		} else {
			payload, err = json.Marshal(event)
			if err != nil {
				return err
			}
		}
		if err := lockHRPerson(ctx, tx, tenant, event.Person.Id); err != nil {
			return err
		}
		stored, err := hrReceipt(ctx, tx, event.Id)
		if err == nil {
			receipt = stored
			receipt.Duplicate = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("look up HR receipt: %w", err)
		}
		latest, err := latestHRDecision(ctx, tx, event.Person.Id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		receipt = muistamov1.HREventAccepted{EventId: event.Id, Decision: muistamov1.HREventAcceptedDecisionAccepted, DispatchState: muistamov1.HREventAcceptedDispatchStatePending, Generation: latest.generation + 1}
		if privacyBlocked || (err == nil && (occurred.Before(latest.occurred) || (occurred.Equal(latest.occurred) && (event.Type != muistamov1.HREventTypeLeaver || latest.kind == "leaver")))) {
			receipt.Decision = muistamov1.HREventAcceptedDecisionIgnored
			receipt.DispatchState = muistamov1.HREventAcceptedDispatchStateIgnored
			receipt.Generation = latest.generation
		}
		version, err := store.IdentityEnrollmentVersion(ctx, tx)
		if err != nil {
			return err
		}
		mode := "simulated"
		if version != nil {
			mode = "entra"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO hr_events (tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version)
			VALUES ($1,$2,$3,$4,'',$5,$6,$7,$8,$9,$10,$11)`,
			tenant, event.Id, string(event.Type), event.Person.Id, payload, occurred, receipt.Generation, string(receipt.Decision), string(receipt.DispatchState), mode, version); err != nil {
			return fmt.Errorf("record HR event: %w", err)
		}
		afterDecision := map[string]any{"eventId": event.Id, "type": event.Type, "generation": receipt.Generation, "decision": receipt.Decision, "dispatchState": receipt.DispatchState, "identityMode": mode, "identityBindingVersion": version}
		if privacyBlocked {
			afterDecision["reason"] = "source predates erasure boundary"
		} else {
			afterDecision["jobCode"] = event.Person.JobCode
		}
		_, err = evidence.Append(ctx, tx, in.Signer, evidence.Entry{
			Tenant: tenant, Actor: actor, Action: "hr.event.received", RequestID: requestID,
			SubjectKind: "HRPerson", SubjectName: event.Person.Id,
			After: afterDecision,
		})
		return err
	})
	if err != nil {
		return receipt, err
	}
	if receipt.DispatchState != muistamov1.HREventAcceptedDispatchStatePending {
		return receipt, nil
	}
	duplicate := receipt.Duplicate
	receipt, err = in.dispatchPending(ctx, tenant, actor, requestID, event.Id)
	receipt.Duplicate = duplicate
	return receipt, err
}

func hrSourceErased(occurred time.Time, before, after *time.Time) bool {
	return after != nil && (!occurred.After(*after) || before == nil || !before.Equal(*after))
}

func lockHRPerson(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, person string) error {
	// Hash collisions only serialize unrelated people; they never authorize another tenant.
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant.String()+"/"+person)
	if err != nil {
		return fmt.Errorf("lock HR person: %w", err)
	}
	return nil
}

type hrDecision struct {
	eventID, kind string
	occurred      time.Time
	generation    int64
}

func latestHRDecision(ctx context.Context, tx pgx.Tx, person string) (hrDecision, error) {
	var d hrDecision
	err := tx.QueryRow(ctx, `SELECT event_id,type,occurred_at,generation FROM hr_events
	  WHERE person_id=$1 AND decision IN ('accepted','legacy')
	  ORDER BY generation DESC,occurred_at DESC,(type='leaver') DESC,event_id DESC LIMIT 1`, person).Scan(&d.eventID, &d.kind, &d.occurred, &d.generation)
	return d, err
}

func hrReceipt(ctx context.Context, tx pgx.Tx, id string) (muistamov1.HREventAccepted, error) {
	var r muistamov1.HREventAccepted
	err := tx.QueryRow(ctx, `SELECT event_id,workflow_id,decision,generation,dispatch_state FROM hr_events WHERE event_id=$1`, id).Scan(&r.EventId, &r.WorkflowId, &r.Decision, &r.Generation, &r.DispatchState)
	return r, err
}

// dispatchPending commits a monotonic attempt marker and signed intent before the handoff.
// Failed results remain pending. Retried Temporal handoffs inspect existing history and refuse
// a missing execution, including after history retention, rather than starting another one.
func (in *Intake) dispatchPending(ctx context.Context, tenant uuid.UUID, actor, requestID, id string) (muistamov1.HREventAccepted, error) {
	var receipt muistamov1.HREventAccepted
	var event muistamov1.HREvent
	var scope Scope
	handoff := false
	err := in.DB.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, tenant, false); err != nil {
			return err
		}
		var person string
		if err := tx.QueryRow(ctx, "SELECT person_id FROM hr_events WHERE event_id=$1", id).Scan(&person); err != nil {
			return err
		}
		if err := lockHRPerson(ctx, tx, tenant, person); err != nil {
			return err
		}
		var payload []byte
		var attempted *time.Time
		if err := tx.QueryRow(ctx, "SELECT payload,dispatch_attempted_at FROM hr_events WHERE event_id=$1 FOR UPDATE", id).Scan(&payload, &attempted); err != nil {
			return err
		}
		var err error
		receipt, err = hrReceipt(ctx, tx, id)
		if err != nil {
			return err
		}
		if receipt.DispatchState != muistamov1.HREventAcceptedDispatchStatePending {
			return nil
		}
		if err := json.Unmarshal(payload, &event); err != nil {
			return fmt.Errorf("decode pending HR event: %w", err)
		}
		latest, err := latestHRDecision(ctx, tx, person)
		if err != nil {
			return err
		}
		if event.Type == muistamov1.HREventTypeJoiner && latest.generation > receipt.Generation && attempted == nil {
			if _, err := tx.Exec(ctx, "UPDATE hr_events SET dispatch_state='cancelled' WHERE event_id=$1", id); err != nil {
				return err
			}
			receipt.DispatchState = muistamov1.HREventAcceptedDispatchStateCancelled
			_, err = evidence.Append(ctx, tx, in.Signer, evidence.Entry{Tenant: tenant, Actor: actor, RequestID: requestID, Action: "hr.event.dispatch-cancelled", SubjectKind: "HRPerson", SubjectName: person, After: map[string]any{"eventId": id, "generation": receipt.Generation, "reason": "superseded before any handoff attempt"}})
			return err
		}
		// An attempted handoff only reads its original Temporal result. New-work ordering
		// must not prevent reconciliation of a result that has already happened.
		if event.Type == muistamov1.HREventTypeJoiner && attempted == nil {
			var prior bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hr_events WHERE person_id=$1 AND type='leaver' AND dispatch_state='pending' AND generation<$2)", person, receipt.Generation).Scan(&prior); err != nil {
				return err
			}
			if prior {
				return ErrDispatch
			}
		}
		if in.Dispatcher == nil {
			return ErrDispatch
		}
		route, err := store.HRIdentityRoute(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		scope = Scope{Tenant: tenant, EventID: id, Generation: receipt.Generation, HandoffAttempted: attempted != nil, IdentityRoute: &route}
		dispatchID, err := DispatchWorkflowID(scope)
		if err != nil {
			return err
		}
		if event.Type == muistamov1.HREventTypeJoiner {
			rows, err := tx.Query(ctx, "SELECT DISTINCT workflow_id FROM hr_events WHERE person_id=$1 AND type='leaver' AND dispatch_state IN ('legacy','dispatched') AND workflow_id<>'' ORDER BY workflow_id", person)
			if err != nil {
				return err
			}
			for rows.Next() {
				var previous string
				if err := rows.Scan(&previous); err != nil {
					rows.Close()
					return err
				}
				scope.PriorLeaverWorkflows = append(scope.PriorLeaverWorkflows, previous)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
		}
		if attempted == nil {
			if _, err := tx.Exec(ctx, "UPDATE hr_events SET dispatch_attempted_at=now() WHERE event_id=$1", id); err != nil {
				return err
			}
			if _, err := evidence.Append(ctx, tx, in.Signer, evidence.Entry{Tenant: tenant, Actor: actor, RequestID: requestID, Action: "hr.event.dispatch-intent", SubjectKind: "HRPerson", SubjectName: person, After: map[string]any{"eventId": id, "generation": receipt.Generation, "dispatchWorkflowId": dispatchID}}); err != nil {
				return err
			}
		}
		handoff = true
		return nil
	})
	if err != nil {
		return muistamov1.HREventAccepted{}, err
	}
	if !handoff {
		return receipt, nil
	}

	// The attempt marker and signed intent have committed before ANY workflow mutation.
	workflowID, err := in.Dispatcher.Dispatch(ctx, scope, event)
	if err != nil {
		return muistamov1.HREventAccepted{}, fmt.Errorf("handoff HR event: %w: %w", ErrDispatch, err)
	}
	if workflowID == "" {
		return muistamov1.HREventAccepted{}, fmt.Errorf("handoff returned no workflow id: %w", ErrDispatch)
	}
	err = in.DB.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, tenant, false); err != nil {
			return err
		}
		if err := lockHRPerson(ctx, tx, tenant, event.Person.Id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM hr_events WHERE event_id=$1 FOR UPDATE", id); err != nil {
			return err
		}
		current, err := hrReceipt(ctx, tx, id)
		if err != nil {
			return err
		}
		if current.DispatchState == muistamov1.HREventAcceptedDispatchStateDispatched {
			if current.WorkflowId != workflowID {
				return ErrHandoffUncertain
			}
			receipt = current
			return nil
		}
		if current.DispatchState != muistamov1.HREventAcceptedDispatchStatePending {
			return ErrHandoffUncertain
		}
		if _, err := tx.Exec(ctx, "UPDATE hr_events SET workflow_id=$2,dispatch_state='dispatched',dispatched_at=now() WHERE event_id=$1", id, workflowID); err != nil {
			return err
		}
		dispatchID, err := DispatchWorkflowID(scope)
		if err != nil {
			return err
		}
		if _, err := evidence.Append(ctx, tx, in.Signer, evidence.Entry{Tenant: tenant, Actor: actor, RequestID: requestID, Action: "hr.event.dispatched", SubjectKind: "HRPerson", SubjectName: event.Person.Id, After: map[string]any{"eventId": id, "generation": current.Generation, "workflowId": workflowID, "dispatchWorkflowId": dispatchID}}); err != nil {
			return err
		}
		receipt = current
		receipt.WorkflowId = workflowID
		receipt.DispatchState = muistamov1.HREventAcceptedDispatchStateDispatched
		return nil
	})
	if err != nil {
		return muistamov1.HREventAccepted{}, err
	}
	return receipt, nil
}

// RetryPending drains a bounded tenant-scoped batch after a crash or workflow-engine outage.
// It attempts every selected event, preserving pending state on errors and never exposing payloads.
func (in *Intake) RetryPending(ctx context.Context, tenant uuid.UUID, actor, requestID string, limit int) ([]muistamov1.HREventAccepted, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("HR retry limit must be between 1 and 1000")
	}
	var ids []string
	if err := in.DB.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT event_id FROM hr_events WHERE dispatch_state='pending' ORDER BY generation,received_at,event_id LIMIT $1`, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	var out []muistamov1.HREventAccepted
	var failures []error
	for _, id := range ids {
		receipt, err := in.dispatchPending(ctx, tenant, actor, requestID, id)
		if err != nil {
			failures = append(failures, err)
		} else {
			out = append(out, receipt)
		}
	}
	return out, errors.Join(failures...)
}

// TemporalDispatcher starts or signals lifecycle workflows.
type TemporalDispatcher struct {
	Client client.Client
	// TaskQueue defaults to the package TaskQueue.
	TaskQueue string
}

// JoinerWorkflowID and LeaverWorkflowID are deterministic, so re-dispatching an event finds
// the same workflow.
func JoinerWorkflowID(tenant uuid.UUID, eventID string) string {
	return "joiner-" + tenant.String() + "-" + eventID
}

// LeaverWorkflowID names the one leaver workflow per person.
func LeaverWorkflowID(tenant uuid.UUID, personID string) string {
	return "leaver-" + tenant.String() + "-" + personID
}

// Dispatch starts a leaver workflow, signals a waiting one on rehire, or starts a joiner.
func (d TemporalDispatcher) Dispatch(ctx context.Context, scope Scope, event muistamov1.HREvent) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	id, err := DispatchWorkflowID(scope)
	if err != nil {
		return "", err
	}
	if scope.HandoffAttempted {
		execution, err := d.Client.DescribeWorkflowExecution(ctx, id, "")
		if err != nil {
			var absent *serviceerror.NotFound
			if errors.As(err, &absent) {
				return "", ErrHandoffUncertain
			}
			return "", fmt.Errorf("inspect prior HR handoff: %w", err)
		}
		if execution.WorkflowExecutionInfo == nil || execution.WorkflowExecutionInfo.Execution == nil {
			return "", ErrHandoffUncertain
		}
		var target string
		if err := d.Client.GetWorkflow(ctx, id, execution.WorkflowExecutionInfo.Execution.RunId).Get(ctx, &target); err != nil {
			return "", fmt.Errorf("reconcile prior HR handoff: %w", err)
		}
		return target, nil
	}
	var handler any = HRDispatch
	var input any = HRDispatchInput{Scope: scope, Event: event}
	queue := d.queue()
	if scope.IdentityRoute != nil && scope.IdentityRoute.ProviderMode == "entra" {
		handler = EntraHRDispatch
		input = muistamov1.EntraLifecycleRef{TenantId: scope.Tenant, ReceiptId: scope.IdentityRoute.ReceiptId}
		if d.TaskQueue == "" {
			queue = EntraTaskQueue
		}
	}
	run, err := d.Client.ExecuteWorkflow(ctx, client.StartWorkflowOptions{ID: id, TaskQueue: queue, WorkflowIDConflictPolicy: enums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING, WorkflowIDReusePolicy: enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE}, handler, input)
	if err != nil {
		var existing *serviceerror.WorkflowExecutionAlreadyStarted
		if !errors.As(err, &existing) {
			return "", fmt.Errorf("start HR handoff: %w", err)
		}
		run = d.Client.GetWorkflow(ctx, id, existing.RunId)
	}
	var target string
	if err := run.Get(ctx, &target); err != nil {
		return "", fmt.Errorf("wait for durable HR handoff: %w", err)
	}
	return target, nil
}

// DispatchWorkflowID depends only on the committed receipt's pinned route. Nil is reserved
// for legacy callers/histories; new intake always loads a route, including simulation backfill.
func DispatchWorkflowID(scope Scope) (string, error) {
	if scope.IdentityRoute == nil {
		return HRDispatchWorkflowID(scope.Tenant, scope.EventID), nil
	}
	route := scope.IdentityRoute
	if route.TenantId != scope.Tenant || route.ReceiptId == uuid.Nil {
		return "", ErrHandoffUncertain
	}
	switch route.ProviderMode {
	case "simulated":
		if route.BindingVersion != nil {
			return "", ErrHandoffUncertain
		}
		return HRDispatchWorkflowID(scope.Tenant, scope.EventID), nil
	case "entra":
		if route.BindingVersion == nil || *route.BindingVersion == uuid.Nil {
			return "", ErrHandoffUncertain
		}
		return EntraDispatchWorkflowID(muistamov1.EntraLifecycleRef{TenantId: scope.Tenant, ReceiptId: route.ReceiptId}), nil
	default:
		return "", ErrHandoffUncertain
	}
}

func (d TemporalDispatcher) queue() string {
	if d.TaskQueue != "" {
		return d.TaskQueue
	}
	return TaskQueue
}

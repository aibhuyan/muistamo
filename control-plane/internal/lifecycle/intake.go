package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

var (
	// ErrNoSecret means the tenant has no HR secret, so no HR event can be authenticated.
	ErrNoSecret = errors.New("tenant has no HR secret")
	// ErrDispatch means the workflow engine could not take the event; the HRIS should retry.
	ErrDispatch = errors.New("workflow engine unavailable")
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

// Accept records an event once and dispatches it. Re-delivering an event id returns the
// original workflow id with duplicate=true and dispatches nothing new.
//
// The dispatch happens inside the transaction, before commit: if the commit then fails, a
// re-delivery dispatches again, which is safe because dispatch is idempotent per event.
func (in *Intake) Accept(ctx context.Context, tenant uuid.UUID, actor, requestID string, event muistamov1.HREvent) (workflowID string, duplicate bool, err error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return "", false, fmt.Errorf("encode HR event: %w", err)
	}
	err = in.DB.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT workflow_id FROM hr_events WHERE event_id = $1`, event.Id).Scan(&workflowID)
		if err == nil {
			duplicate = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("look up HR event: %w", err)
		}
		workflowID, err = in.Dispatcher.Dispatch(ctx, Scope{Tenant: tenant, EventID: event.Id}, event)
		if err != nil {
			return fmt.Errorf("dispatch HR event %s: %w: %w", event.Id, ErrDispatch, err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO hr_events (tenant_id, event_id, type, person_id, workflow_id, payload)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			tenant, event.Id, string(event.Type), event.Person.Id, workflowID, payload); err != nil {
			return fmt.Errorf("record HR event: %w", err)
		}
		_, err = evidence.Append(ctx, tx, in.Signer, evidence.Entry{
			Tenant: tenant, Actor: actor, Action: "hr.event.received", RequestID: requestID,
			SubjectKind: "HRPerson", SubjectName: event.Person.Id,
			After: map[string]any{"eventId": event.Id, "type": event.Type, "jobCode": event.Person.JobCode, "workflowId": workflowID},
		})
		return err
	})
	return workflowID, duplicate, err
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
	person := Person{ID: event.Person.Id, Email: event.Person.Email, JobCode: event.Person.JobCode}
	if event.Person.ManagerEmail != nil {
		person.ManagerEmail = *event.Person.ManagerEmail
	}
	leaverID := LeaverWorkflowID(scope.Tenant, person.ID)

	switch event.Type {
	case muistamov1.HREventTypeLeaver:
		scope.WorkflowID = leaverID
		return d.start(ctx, leaverID, Leaver, LeaverInput{Scope: scope, Person: person})
	case muistamov1.HREventTypeJoiner:
		err := d.Client.SignalWorkflow(ctx, leaverID, "", RehiredSignal, Rehire{EventID: event.Id})
		if err == nil {
			return leaverID, nil
		}
		var notFound *serviceerror.NotFound
		if !errors.As(err, &notFound) {
			return "", fmt.Errorf("signal leaver workflow: %w", err)
		}
		id := JoinerWorkflowID(scope.Tenant, event.Id)
		scope.WorkflowID = id
		return d.start(ctx, id, Joiner, JoinerInput{Scope: scope, Person: person})
	default:
		return "", fmt.Errorf("unknown HR event type %q", event.Type)
	}
}

func (d TemporalDispatcher) queue() string {
	if d.TaskQueue != "" {
		return d.TaskQueue
	}
	return TaskQueue
}

func (d TemporalDispatcher) start(ctx context.Context, id string, workflow any, input any) (string, error) {
	run, err := d.Client.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:        id,
		TaskQueue: d.queue(),
		// A second start with the same id joins the running workflow instead of failing.
		WorkflowIDConflictPolicy: enums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
	}, workflow, input)
	if err != nil {
		return "", fmt.Errorf("start workflow %s: %w", id, err)
	}
	return run.GetID(), nil
}

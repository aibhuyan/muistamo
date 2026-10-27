package lifecycle

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// HRDispatchInput is a committed HR receipt's immutable workflow handoff. Old workflow and
// activity names keep their original implementation; no legacy history is reinterpreted.
type HRDispatchInput struct {
	Scope Scope
	Event muistamov1.HREvent
}

// HRDispatchWorkflowID is unique per retained HR event, including after execution closes.
func HRDispatchWorkflowID(tenant uuid.UUID, eventID string) string {
	return "hr-dispatch-" + tenant.String() + "-" + eventID
}

// HRDispatch records signal/start commands in workflow history. A lost handoff result reads this
// existing result; if history is missing, the ledger's attempt marker requires reconciliation.
// Each accepted leaver starts its own snapshot, rather than reusing an older person's workflow.
func HRDispatch(ctx workflow.Context, in HRDispatchInput) (string, error) {
	scope := in.Scope
	scope.PriorLeaverWorkflows = nil
	person := Person{ID: in.Event.Person.Id, Email: in.Event.Person.Email, JobCode: in.Event.Person.JobCode}
	if in.Event.Person.ManagerEmail != nil {
		person.ManagerEmail = *in.Event.Person.ManagerEmail
	}
	if in.Event.Type == muistamov1.HREventTypeJoiner {
		seen := map[string]bool{}
		var rehireTarget string
		// Include the old canonical name so an existing legacy waiting leaver is still signalled.
		targets := append([]string{LeaverWorkflowID(scope.Tenant, person.ID)}, in.Scope.PriorLeaverWorkflows...)
		for _, target := range targets {
			if seen[target] {
				continue
			}
			seen[target] = true
			err := workflow.SignalExternalWorkflow(ctx, target, "", RehiredSignal, Rehire{EventID: in.Event.Id}).Get(ctx, nil)
			if err == nil {
				if rehireTarget == "" {
					rehireTarget = target
				}
				continue
			}
			var absent *temporal.UnknownExternalWorkflowExecutionError
			if !errors.As(err, &absent) {
				return "", fmt.Errorf("signal rehire target: %w", err)
			}
		}
		if rehireTarget != "" {
			// Rehire only forwarded an event ID. Each prior leaver retains its own setup fence.
			scope.WorkflowID = HRDispatchWorkflowID(scope.Tenant, in.Event.Id)
			if err := settleHRSetup(ctx, scope); err != nil {
				return "", err
			}
			return rehireTarget, nil
		}
		scope.WorkflowID = JoinerWorkflowID(scope.Tenant, in.Event.Id)
		ctx = workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{WorkflowID: scope.WorkflowID, TaskQueue: workflow.GetInfo(ctx).TaskQueueName, ParentClosePolicy: enums.PARENT_CLOSE_POLICY_ABANDON, WorkflowIDReusePolicy: enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE})
		var execution workflow.Execution
		if err := workflow.ExecuteChildWorkflow(ctx, Joiner, JoinerInput{Scope: scope, Person: person}).GetChildWorkflowExecution().Get(ctx, &execution); err != nil {
			return "", err
		}
		return execution.ID, nil
	}
	if in.Event.Type != muistamov1.HREventTypeLeaver {
		return "", errors.New("invalid HR handoff type")
	}
	scope.WorkflowID = "leaver-event-" + scope.Tenant.String() + "-" + in.Event.Id
	ctx = workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{WorkflowID: scope.WorkflowID, TaskQueue: workflow.GetInfo(ctx).TaskQueueName, ParentClosePolicy: enums.PARENT_CLOSE_POLICY_ABANDON, WorkflowIDReusePolicy: enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE})
	var execution workflow.Execution
	if err := workflow.ExecuteChildWorkflow(ctx, Leaver, LeaverInput{Scope: scope, Person: person}).GetChildWorkflowExecution().Get(ctx, &execution); err != nil {
		return "", err
	}
	return execution.ID, nil
}

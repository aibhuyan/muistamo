package lifecycle

import (
	"errors"
	"fmt"
	"time"

	"go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

const EntraTaskQueue = "muistamo-entra-lifecycle"
const EntraRehiredSignal = "entra-rehired"

func EntraDispatchWorkflowID(ref muistamov1.EntraLifecycleRef) string {
	return "entra-dispatch-" + ref.TenantId.String() + "-" + ref.ReceiptId.String()
}
func EntraChildWorkflowID(ref muistamov1.EntraLifecycleRef, kind string) string {
	return "entra-" + kind + "-" + ref.TenantId.String() + "-" + ref.ReceiptId.String()
}

// These names never replace legacy workflow/activity registrations or reinterpret old input.
func EntraHRDispatch(ctx workflow.Context, ref muistamov1.EntraLifecycleRef) (string, error) {
	ctx = withActivityOptions(ctx)
	var a *EntraActivities
	var kind string
	if err := workflow.ExecuteActivity(ctx, a.EntraEventKind, ref).Get(ctx, &kind); err != nil {
		return "", err
	}
	if kind != "joiner" && kind != "leaver" {
		return "", errors.New("invalid live HR type")
	}
	if kind == "joiner" {
		var prior []string
		if err := workflow.ExecuteActivity(ctx, a.EntraPriorLeavers, ref).Get(ctx, &prior); err != nil {
			return "", err
		}
		for _, id := range prior {
			err := workflow.SignalExternalWorkflow(ctx, id, "", EntraRehiredSignal, ref).Get(ctx, nil)
			var absent *temporal.UnknownExternalWorkflowExecutionError
			if err != nil && !errors.As(err, &absent) {
				return "", err
			}
		}
	}
	id := EntraChildWorkflowID(ref, kind)
	ctx = workflow.WithChildOptions(ctx, workflow.ChildWorkflowOptions{WorkflowID: id, TaskQueue: workflow.GetInfo(ctx).TaskQueueName, ParentClosePolicy: enums.PARENT_CLOSE_POLICY_ABANDON, WorkflowIDReusePolicy: enums.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE})
	var execution workflow.Execution
	var child any = EntraJoiner
	if kind == "leaver" {
		child = EntraLeaver
	}
	if err := workflow.ExecuteChildWorkflow(ctx, child, ref).GetChildWorkflowExecution().Get(ctx, &execution); err != nil {
		return "", err
	}
	return execution.ID, nil
}

func EntraJoiner(ctx workflow.Context, ref muistamov1.EntraLifecycleRef) (names []string, resultErr error) {
	ctx = withActivityOptions(ctx)
	var a *EntraActivities
	defer func() {
		cleanup, _ := workflow.NewDisconnectedContext(ctx)
		cleanup = withActivityOptions(cleanup)
		if err := workflow.ExecuteActivity(cleanup, a.EntraSettleSetup, ref).Get(cleanup, nil); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("settle live joiner setup: %w", err))
		}
	}()
	var templates []registry.TemplateVersionRef
	if err := workflow.ExecuteActivity(ctx, a.EntraMatchTemplates, ref).Get(ctx, &templates); err != nil {
		return nil, err
	}
	// A rejoining person's earlier live reviews are fenced at this generation before the link
	// below can replace the Entra user they were opened under (docs/live-review-plan.md). The old
	// leaver run also stops at the rehire signal, so a fence that cannot be sent is evidenced and
	// the joiner continues: the person's agents do not wait on the knowledge service.
	if workflow.GetVersion(ctx, "entra-review-fence", workflow.DefaultVersion, 1) == 1 {
		if err := workflow.ExecuteActivity(ctx, a.EntraFenceReview, ref).Get(ctx, nil); err != nil {
			workflow.GetLogger(ctx).Warn("earlier personal-layer reviews not fenced; the old leaver run's rehire signal still stops them", "error", err)
			if err := workflow.ExecuteActivity(ctx, a.EntraRecordFenceFailure, ref).Get(ctx, nil); err != nil {
				return nil, fmt.Errorf("record the unsent review fence: %w", err)
			}
		}
	}
	// Which Entra user the person is, for on-behalf-of retrieval. It holds up the joiner by at
	// most a few minutes: an unlinked person gets their agents, and knowledge retrieval refuses
	// for them. A lookup that cannot finish replaces any earlier link, so a rehire never keeps a
	// link it could not confirm.
	if workflow.GetVersion(ctx, "entra-link-user", workflow.DefaultVersion, 1) == 1 {
		link := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
			StartToCloseTimeout: 30 * time.Second,
			RetryPolicy: &temporal.RetryPolicy{
				InitialInterval: time.Second, BackoffCoefficient: 2, MaximumInterval: 30 * time.Second, MaximumAttempts: 5,
			},
		})
		if err := workflow.ExecuteActivity(link, a.EntraLinkUser, ref).Get(link, nil); err != nil {
			workflow.GetLogger(ctx).Warn("Entra user not linked; knowledge retrieval refuses for this person until a joiner links them", "error", err)
			if err := workflow.ExecuteActivity(ctx, a.EntraUnlinkUser, ref).Get(ctx, nil); err != nil {
				return nil, fmt.Errorf("record the unlinked Entra user: %w", err)
			}
		}
	}
	for _, template := range templates {
		var name string
		if err := workflow.ExecuteActivity(ctx, a.EntraEnsureInstance, ref, template).Get(ctx, &name); err != nil {
			return names, err
		}
		for _, step := range []any{a.EntraCreate, a.EntraEnable, a.EntraActivate} {
			if err := workflow.ExecuteActivity(ctx, step, ref, name).Get(ctx, nil); err != nil {
				return names, err
			}
		}
		names = append(names, name)
	}
	return names, nil
}

func EntraLeaver(ctx workflow.Context, ref muistamov1.EntraLifecycleRef) (result LeaverResult, resultErr error) {
	ctx = withActivityOptions(ctx)
	var a *EntraActivities
	settled := false
	defer func() {
		if settled {
			return
		}
		cleanup, _ := workflow.NewDisconnectedContext(ctx)
		cleanup = withActivityOptions(cleanup)
		if err := workflow.ExecuteActivity(cleanup, a.EntraSettleSetup, ref).Get(cleanup, nil); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("settle live leaver setup: %w", err))
		}
	}()
	rehired := workflow.GetSignalChannel(ctx, EntraRehiredSignal)
	if err := workflow.ExecuteActivity(ctx, a.EntraPrepareLeaver, ref).Get(ctx, &result.Instances); err != nil {
		return result, err
	}
	// Disabling an identity is a remote call: a failed or uncertain one must not delay another
	// instance's first attempt, so it runs once. All disables go first; suspension has already
	// shut the gateway to these instances.
	options := workflow.GetActivityOptions(ctx)
	options.RetryPolicy = &temporal.RetryPolicy{MaximumAttempts: 1}
	once := workflow.WithActivityOptions(ctx, options)
	var failures []error
	for _, name := range result.Instances {
		if err := workflow.ExecuteActivity(once, a.EntraDisable, ref, name).Get(ctx, nil); err != nil {
			failures = append(failures, err)
		}
	}
	// Key revocation is a local, idempotent transaction: retry it, so a transient database error
	// does not leave a leaver's keys active. Reactivation also revokes any that survive.
	for _, name := range result.Instances {
		if err := workflow.ExecuteActivity(ctx, a.EntraRevoke, ref, name).Get(ctx, nil); err != nil {
			failures = append(failures, err)
		}
	}
	// The personal layer belongs to the person, not an instance: it is reviewed even with no
	// instances, and even when an instance needs reconciliation. It is then never purged until
	// that is done: the workflow ends below, frozen and visibly pending.
	var review ReviewOpened
	if workflow.GetVersion(ctx, "entra-live-review", workflow.DefaultVersion, 1) == workflow.DefaultVersion {
		if err := workflow.ExecuteActivity(ctx, a.EntraRecordReviewCoverage, ref).Get(ctx, nil); err != nil {
			return result, err
		}
	} else if err := workflow.ExecuteActivity(ctx, a.EntraOpenReview, ref).Get(ctx, &review); err != nil {
		return result, err
	}
	if review.Opened {
		result.Review = review.ID
	}
	if err := workflow.ExecuteActivity(ctx, a.EntraSettleSetup, ref).Get(ctx, nil); err != nil {
		return result, err
	}
	settled = true
	if len(failures) > 0 {
		return result, fmt.Errorf("live leaver requires reconciliation: %w", errors.Join(failures...))
	}
	if len(result.Instances) == 0 && !review.Opened {
		return result, nil
	}
	timerCtx, cancel := workflow.WithCancel(ctx)
	defer cancel()
	timer := workflow.NewTimer(timerCtx, GracePeriod)
	for {
		var signal *muistamov1.EntraLifecycleRef
		elapsed := false
		selector := workflow.NewSelector(ctx)
		selector.AddFuture(timer, func(workflow.Future) { elapsed = true })
		selector.AddReceive(rehired, func(c workflow.ReceiveChannel, _ bool) {
			var value muistamov1.EntraLifecycleRef
			c.Receive(ctx, &value)
			signal = &value
		})
		selector.Select(ctx)
		if signal != nil {
			// The rehire's joiner fences the review in the knowledge service; nothing to cancel here.
			if err := workflow.ExecuteActivity(ctx, a.EntraConfirmRehire, ref, *signal).Get(ctx, nil); err == nil {
				result.Rehired = true
				return result, nil
			}
		}
		if elapsed {
			break
		}
	}
	for _, name := range result.Instances {
		if err := workflow.ExecuteActivity(ctx, a.EntraRetire, ref, name).Get(ctx, nil); err != nil {
			failures = append(failures, err)
		}
	}
	// Purge an undecided layer; a kept one comes back with a later deadline to wait for. A rehire
	// after the grace period fences the review, and the next expiry then purges nothing.
	for review.Opened {
		var state ReviewState
		if err := workflow.ExecuteActivity(ctx, a.EntraExpireReview, ref, review.ID).Get(ctx, &state); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		if state.Closed {
			break
		}
		wait := state.Deadline.Sub(workflow.Now(ctx))
		if wait < liveReviewWait {
			wait = liveReviewWait
		}
		if err := workflow.Sleep(ctx, wait); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
	}
	return result, errors.Join(failures...)
}

// Package lifecycle runs HR-driven instance lifecycles as Temporal workflows (FR-401, FR-402).
//
// Joiner: the person's job code selects templates; each gets an instance, an identity, and is
// activated. Leaver: every instance is suspended and its credentials revoked at once, then the
// person's personal knowledge layer is frozen for review by their manager (E4.2); after the
// grace period the instances are retired, their identities disabled, and an undecided layer is
// purged. A rehire inside the grace period signals the waiting leaver workflow, which
// reactivates instead of retiring and cancels the review.
//
// Workflow code must stay deterministic: all side effects live in Activities.
package lifecycle

import (
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

const (
	// TaskQueue is where lifecycle workflows and activities run.
	TaskQueue = "muistamo-lifecycle"
	// GracePeriod is how long a leaver's instances stay suspended before retirement.
	GracePeriod = 30 * 24 * time.Hour
	// RehiredSignal reactivates a leaver's instances during the grace period.
	RehiredSignal = "rehired"
	// reviewChange versions the leaver workflow: histories recorded before personal-layer
	// reviews replay the old step (RecordPersonalLayerDecision).
	reviewChange = "personal-layer-review"
)

// JoinerInput starts a joiner workflow.
type JoinerInput struct {
	Scope  Scope
	Person Person
}

// LeaverInput starts a leaver workflow.
type LeaverInput struct {
	Scope  Scope
	Person Person
}

// LeaverResult reports how a leaver workflow ended.
type LeaverResult struct {
	Instances []string
	Rehired   bool
	// Review is the personal-layer review's id, if one was opened.
	Review string `json:",omitempty"`
}

// Rehire is the payload of RehiredSignal.
type Rehire struct {
	EventID string
}

func withActivityOptions(ctx workflow.Context) workflow.Context {
	return workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    5 * time.Minute,
			// Retry for well inside the one-hour joiner target, then fail visibly.
			MaximumAttempts: 20,
		},
	})
}

// Joiner creates, provisions and activates the person's instances. It returns their names.
func Joiner(ctx workflow.Context, in JoinerInput) ([]string, error) {
	ctx = withActivityOptions(ctx)
	var a *Activities

	var templates []registry.TemplateVersionRef
	if err := workflow.ExecuteActivity(ctx, a.MatchTemplates, in.Scope, in.Person.JobCode).Get(ctx, &templates); err != nil {
		return nil, err
	}
	instances := make([]string, 0, len(templates))
	for _, template := range templates {
		var name string
		if err := workflow.ExecuteActivity(ctx, a.EnsureInstance, in.Scope, template, in.Person).Get(ctx, &name); err != nil {
			return instances, err
		}
		if err := workflow.ExecuteActivity(ctx, a.ProvisionIdentity, in.Scope, name, in.Person).Get(ctx, nil); err != nil {
			return instances, err
		}
		if err := workflow.ExecuteActivity(ctx, a.SetState, in.Scope, name, muistamov1.InstanceStateActive).Get(ctx, nil); err != nil {
			return instances, err
		}
		instances = append(instances, name)
	}
	if err := settleHRSetup(ctx, in.Scope); err != nil {
		return instances, err
	}
	return instances, nil
}

// Leaver suspends and revokes the person's instances, then waits out the grace period.
func Leaver(ctx workflow.Context, in LeaverInput) (LeaverResult, error) {
	ctx = withActivityOptions(ctx)
	var a *Activities
	// Registered first so a rehire that arrives while suspending is not lost.
	rehired := workflow.GetSignalChannel(ctx, RehiredSignal)

	var instances []string
	if err := workflow.ExecuteActivity(ctx, a.PersonInstances, in.Scope, in.Person.ID).Get(ctx, &instances); err != nil {
		return LeaverResult{}, err
	}
	result := LeaverResult{Instances: instances}

	// Revocation first and for everyone: it is the safety-critical step. One instance's failure
	// must never leave the person's other instances active, so every instance is attempted and
	// the failures are reported together, as in the Entra leaver. Each step is retried first.
	var failures []error
	for _, name := range instances {
		if err := workflow.ExecuteActivity(ctx, a.SetState, in.Scope, name, muistamov1.InstanceStateSuspended).Get(ctx, nil); err != nil {
			// Revocation requires a suspended instance; the failure is reported below.
			failures = append(failures, fmt.Errorf("suspend %s: %w", name, err))
			continue
		}
		if err := workflow.ExecuteActivity(ctx, a.RevokeCredentials, in.Scope, name).Get(ctx, nil); err != nil {
			failures = append(failures, fmt.Errorf("revoke credentials of %s: %w", name, err))
		}
	}
	if len(failures) > 0 {
		return result, fmt.Errorf("leaver requires reconciliation: %w", errors.Join(failures...))
	}
	var review ReviewOpened
	if workflow.GetVersion(ctx, reviewChange, workflow.DefaultVersion, 1) == workflow.DefaultVersion {
		for _, name := range instances {
			if err := workflow.ExecuteActivity(ctx, a.RecordPersonalLayerDecision, in.Scope, name).Get(ctx, nil); err != nil {
				return result, err
			}
		}
	} else {
		// The layer belongs to the person, not an instance: review it even with no instances.
		if err := workflow.ExecuteActivity(ctx, a.OpenPersonalLayerReview, in.Scope, in.Person, instances).Get(ctx, &review); err != nil {
			return result, err
		}
		if review.Opened {
			result.Review = review.ID
		}
	}
	if err := settleHRSetup(ctx, in.Scope); err != nil {
		return result, err
	}
	if len(instances) == 0 && !review.Opened {
		return result, nil
	}

	timerCtx, cancelTimer := workflow.WithCancel(ctx)
	timer := workflow.NewTimer(timerCtx, GracePeriod)
	selector := workflow.NewSelector(ctx)
	selector.AddFuture(timer, func(workflow.Future) {})
	selector.AddReceive(rehired, func(c workflow.ReceiveChannel, _ bool) {
		var signal Rehire
		c.Receive(ctx, &signal)
		result.Rehired = true
	})
	selector.Select(ctx)

	if result.Rehired {
		cancelTimer()
		if review.Opened {
			if err := workflow.ExecuteActivity(ctx, a.CancelPersonalLayerReview, in.Scope, in.Person.ID, review.ID).Get(ctx, nil); err != nil {
				return result, err
			}
		}
		for _, name := range instances {
			if err := workflow.ExecuteActivity(ctx, a.SetIdentityEnabled, in.Scope, name, true).Get(ctx, nil); err != nil {
				return result, err
			}
			if err := workflow.ExecuteActivity(ctx, a.SetState, in.Scope, name, muistamov1.InstanceStateActive).Get(ctx, nil); err != nil {
				return result, err
			}
		}
		return result, nil
	}
	for _, name := range instances {
		if err := workflow.ExecuteActivity(ctx, a.SetState, in.Scope, name, muistamov1.InstanceStateRetired).Get(ctx, nil); err != nil {
			return result, err
		}
		if err := workflow.ExecuteActivity(ctx, a.SetIdentityEnabled, in.Scope, name, false).Get(ctx, nil); err != nil {
			return result, err
		}
	}
	// Purge an undecided layer; a kept one comes back with a later deadline to wait for.
	for review.Opened {
		var state ReviewState
		if err := workflow.ExecuteActivity(ctx, a.ExpirePersonalLayerReview, in.Scope, in.Person.ID, review.ID).Get(ctx, &state); err != nil {
			return result, err
		}
		if state.Closed {
			break
		}
		wait := state.Deadline.Sub(workflow.Now(ctx))
		if wait < time.Minute {
			wait = time.Minute
		}
		if err := workflow.Sleep(ctx, wait); err != nil {
			return result, err
		}
	}
	return result, nil
}

func settleHRSetup(ctx workflow.Context, scope Scope) error {
	// Generation zero belongs to legacy workflows; preserve their pending activity histories.
	if scope.Generation == 0 {
		return nil
	}
	if workflow.GetVersion(ctx, "hr-setup-completed", workflow.DefaultVersion, 1) == workflow.DefaultVersion {
		return nil
	}
	var a *Activities
	return workflow.ExecuteActivity(withActivityOptions(ctx), a.SettleHRSetup, scope).Get(ctx, nil)
}

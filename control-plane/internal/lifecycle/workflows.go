// Package lifecycle runs HR-driven instance lifecycles as Temporal workflows (FR-401, FR-402).
//
// Joiner: the person's job code selects templates; each gets an instance, an identity, and is
// activated. Leaver: every instance is suspended and its credentials revoked at once; after the
// grace period it is retired and its identity disabled. A rehire inside the grace period
// signals the waiting leaver workflow, which reactivates instead of retiring.
//
// Workflow code must stay deterministic: all side effects live in Activities.
package lifecycle

import (
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

	// Revocation first and for everyone: it is the safety-critical step.
	for _, name := range instances {
		if err := workflow.ExecuteActivity(ctx, a.SetState, in.Scope, name, muistamov1.InstanceStateSuspended).Get(ctx, nil); err != nil {
			return result, err
		}
		if err := workflow.ExecuteActivity(ctx, a.RevokeCredentials, in.Scope, name).Get(ctx, nil); err != nil {
			return result, err
		}
	}
	for _, name := range instances {
		if err := workflow.ExecuteActivity(ctx, a.RecordPersonalLayerDecision, in.Scope, name).Get(ctx, nil); err != nil {
			return result, err
		}
	}
	if len(instances) == 0 {
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
	return result, nil
}

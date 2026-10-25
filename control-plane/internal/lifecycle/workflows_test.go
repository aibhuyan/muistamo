package lifecycle

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

var (
	a      *Activities
	scope  = Scope{Tenant: uuid.MustParse("00000000-0000-0000-0000-000000000001"), WorkflowID: "wf", EventID: "ev"}
	person = Person{ID: "e-1", Email: "person-a@example.invalid", JobCode: "ANALYST_INTERN"}
)

func newEnv(t *testing.T) *testsuite.TestWorkflowEnvironment {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivity(&Activities{})
	return env
}

// steps records activity calls in order.
type steps []string

func (s *steps) add(step string) func(mock.Arguments) {
	return func(mock.Arguments) { *s = append(*s, step) }
}

func TestJoinerProvisionsBeforeActivating(t *testing.T) {
	env := newEnv(t)
	var got steps
	templates := []registry.TemplateVersionRef{{Name: "analyst-intern", Version: 3}}
	env.OnActivity(a.MatchTemplates, mock.Anything, scope, "ANALYST_INTERN").Return(templates, nil)
	env.OnActivity(a.EnsureInstance, mock.Anything, scope, templates[0], person).Return("analyst-intern-e-1", nil).Run(got.add("ensure"))
	env.OnActivity(a.ProvisionIdentity, mock.Anything, scope, "analyst-intern-e-1", person).Return(nil).Run(got.add("provision"))
	env.OnActivity(a.SetState, mock.Anything, scope, "analyst-intern-e-1", muistamov1.InstanceStateActive).Return(nil).Run(got.add("activate"))

	env.ExecuteWorkflow(Joiner, JoinerInput{Scope: scope, Person: person})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow error: %v", env.GetWorkflowError())
	}
	var instances []string
	if err := env.GetWorkflowResult(&instances); err != nil || len(instances) != 1 {
		t.Fatalf("instances = %v, %v", instances, err)
	}
	if want := []string{"ensure", "provision", "activate"}; !equal(got, want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}
}

func TestJoinerRetriesAStepWhoseEvidenceFailed(t *testing.T) {
	env := newEnv(t)
	templates := []registry.TemplateVersionRef{{Name: "analyst-intern", Version: 1}}
	env.OnActivity(a.MatchTemplates, mock.Anything, scope, "ANALYST_INTERN").Return(templates, nil)
	env.OnActivity(a.EnsureInstance, mock.Anything, scope, templates[0], person).Return("i", nil)
	env.OnActivity(a.ProvisionIdentity, mock.Anything, scope, "i", person).Return(errors.New("evidence could not be recorded")).Once()
	env.OnActivity(a.ProvisionIdentity, mock.Anything, scope, "i", person).Return(nil).Once()
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateActive).Return(nil)

	env.ExecuteWorkflow(Joiner, JoinerInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatalf("workflow should succeed after the retry: %v", env.GetWorkflowError())
	}
	env.AssertExpectations(t)
}

const reviewID = "wf:run"

// expectLeaverStart mocks suspension, revocation and an opened personal-layer review.
func expectLeaverStart(env *testsuite.TestWorkflowEnvironment, got *steps, instance string) {
	env.OnActivity(a.PersonInstances, mock.Anything, scope, person.ID).Return([]string{instance}, nil)
	env.OnActivity(a.SetState, mock.Anything, scope, instance, muistamov1.InstanceStateSuspended).Return(nil).Run(got.add("suspend"))
	env.OnActivity(a.RevokeCredentials, mock.Anything, scope, instance).Return(nil).Run(got.add("revoke"))
	env.OnActivity(a.OpenPersonalLayerReview, mock.Anything, scope, person, []string{instance}).
		Return(ReviewOpened{ID: reviewID, Opened: true}, nil).Run(got.add("personal-layer"))
}

func TestLeaverRetiresAfterTheGracePeriod(t *testing.T) {
	env := newEnv(t)
	var got steps
	expectLeaverStart(env, &got, "i")
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateRetired).Return(nil).Run(got.add("retire"))
	env.OnActivity(a.SetIdentityEnabled, mock.Anything, scope, "i", false).Return(nil).Run(got.add("disable"))
	env.OnActivity(a.ExpirePersonalLayerReview, mock.Anything, scope, person.ID, reviewID).Return(ReviewState{Closed: true}, nil).Run(got.add("purge-undecided"))

	// Fails the test if anything retires before the grace period ends.
	env.RegisterDelayedCallback(func() {
		if len(got) != 3 {
			t.Errorf("at day 29: steps = %v, want only suspend, revoke, personal-layer", got)
		}
	}, GracePeriod-24*time.Hour)

	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatal(env.GetWorkflowError())
	}
	if want := []string{"suspend", "revoke", "personal-layer", "retire", "disable", "purge-undecided"}; !equal(got, want) {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	var result LeaverResult
	if err := env.GetWorkflowResult(&result); err != nil || result.Rehired {
		t.Fatalf("result = %+v, %v; want not rehired", result, err)
	}
}

func TestRehireDuringGracePeriodReactivates(t *testing.T) {
	env := newEnv(t)
	var got steps
	expectLeaverStart(env, &got, "i")
	env.OnActivity(a.SetIdentityEnabled, mock.Anything, scope, "i", true).Return(nil).Run(got.add("enable"))
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateActive).Return(nil).Run(got.add("activate"))
	env.OnActivity(a.CancelPersonalLayerReview, mock.Anything, scope, person.ID, reviewID).Return(nil).Run(got.add("cancel-review"))

	env.RegisterDelayedCallback(func() { env.SignalWorkflow(RehiredSignal, Rehire{EventID: "rehire-1"}) }, 10*24*time.Hour)
	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatal(env.GetWorkflowError())
	}
	if want := []string{"suspend", "revoke", "personal-layer", "cancel-review", "enable", "activate"}; !equal(got, want) {
		t.Fatalf("steps = %v, want %v (and never retire)", got, want)
	}
	var result LeaverResult
	if err := env.GetWorkflowResult(&result); err != nil || !result.Rehired {
		t.Fatalf("result = %+v, %v; want rehired", result, err)
	}
}

func TestRehireBeforeSuspensionFinishesIsNotLost(t *testing.T) {
	env := newEnv(t)
	var got steps
	expectLeaverStart(env, &got, "i")
	env.OnActivity(a.SetIdentityEnabled, mock.Anything, scope, "i", true).Return(nil)
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateActive).Return(nil).Run(got.add("activate"))
	env.OnActivity(a.CancelPersonalLayerReview, mock.Anything, scope, person.ID, reviewID).Return(nil)

	env.RegisterDelayedCallback(func() { env.SignalWorkflow(RehiredSignal, Rehire{EventID: "early"}) }, 0)
	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatal(env.GetWorkflowError())
	}
	if got[0] != "suspend" || got[len(got)-1] != "activate" {
		t.Fatalf("steps = %v: an early rehire must still suspend and revoke first, then reactivate", got)
	}
}

func TestLeaverWithNoInstancesOrLayerEnds(t *testing.T) {
	env := newEnv(t)
	env.OnActivity(a.PersonInstances, mock.Anything, scope, person.ID).Return([]string(nil), nil)
	env.OnActivity(a.OpenPersonalLayerReview, mock.Anything, scope, person, []string(nil)).Return(ReviewOpened{}, nil)

	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if !env.IsWorkflowCompleted() || env.GetWorkflowError() != nil {
		t.Fatalf("workflow error: %v", env.GetWorkflowError())
	}
	env.AssertExpectations(t)
}

// A person can have a personal layer without any instance (through their own assistant): it is
// still reviewed, and purged after the grace period.
func TestLeaverWithOnlyAPersonalLayerIsStillReviewed(t *testing.T) {
	env := newEnv(t)
	var got steps
	env.OnActivity(a.PersonInstances, mock.Anything, scope, person.ID).Return([]string(nil), nil)
	env.OnActivity(a.OpenPersonalLayerReview, mock.Anything, scope, person, []string(nil)).
		Return(ReviewOpened{ID: reviewID, Opened: true}, nil).Run(got.add("open"))
	env.OnActivity(a.ExpirePersonalLayerReview, mock.Anything, scope, person.ID, reviewID).
		Return(ReviewState{Closed: true}, nil).Run(got.add("expire"))

	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatal(env.GetWorkflowError())
	}
	if !equal(got, []string{"open", "expire"}) {
		t.Fatalf("steps = %v", got)
	}
}

// A review the decider kept comes back open with a later deadline; the workflow waits for it and
// asks again, rather than purging early or giving up.
func TestKeptReviewIsExpiredAtItsLaterDeadline(t *testing.T) {
	env := newEnv(t)
	var got steps
	expectLeaverStart(env, &got, "i")
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateRetired).Return(nil)
	env.OnActivity(a.SetIdentityEnabled, mock.Anything, scope, "i", false).Return(nil)
	var calls []time.Time
	kept := env.Now().Add(GracePeriod + 30*24*time.Hour)
	env.OnActivity(a.ExpirePersonalLayerReview, mock.Anything, scope, person.ID, reviewID).
		Return(ReviewState{Deadline: kept}, nil).Once().Run(func(mock.Arguments) { calls = append(calls, env.Now()) })
	env.OnActivity(a.ExpirePersonalLayerReview, mock.Anything, scope, person.ID, reviewID).
		Return(ReviewState{Closed: true}, nil).Once().Run(func(mock.Arguments) { calls = append(calls, env.Now()) })

	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatal(env.GetWorkflowError())
	}
	if len(calls) != 2 || calls[1].Before(kept) {
		t.Fatalf("expiry calls at %v; want two, the second at or after %v", calls, kept)
	}
	var result LeaverResult
	if err := env.GetWorkflowResult(&result); err != nil || result.Review != reviewID {
		t.Fatalf("result = %+v, %v", result, err)
	}
}

// A leaver workflow recorded before reviews existed replays its old step, so in-flight leavers
// finish instead of failing on a non-deterministic history.
func TestLeaverStartedBeforeReviewsKeepsTheOldStep(t *testing.T) {
	env := newEnv(t)
	var got steps
	env.OnGetVersion(reviewChange, workflow.DefaultVersion, 1).Return(workflow.DefaultVersion)
	env.OnActivity(a.PersonInstances, mock.Anything, scope, person.ID).Return([]string{"i"}, nil)
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateSuspended).Return(nil)
	env.OnActivity(a.RevokeCredentials, mock.Anything, scope, "i").Return(nil)
	env.OnActivity(a.RecordPersonalLayerDecision, mock.Anything, scope, "i").Return(nil).Run(got.add("old-step"))
	env.OnActivity(a.SetState, mock.Anything, scope, "i", muistamov1.InstanceStateRetired).Return(nil)
	env.OnActivity(a.SetIdentityEnabled, mock.Anything, scope, "i", false).Return(nil)

	env.ExecuteWorkflow(Leaver, LeaverInput{Scope: scope, Person: person})

	if env.GetWorkflowError() != nil {
		t.Fatal(env.GetWorkflowError())
	}
	if !equal(got, []string{"old-step"}) {
		t.Fatalf("steps = %v, want the old personal-layer step only", got)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

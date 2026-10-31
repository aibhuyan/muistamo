package lifecycle

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

var liveRef = muistamov1.EntraLifecycleRef{TenantId: uuid.MustParse("11111111-1111-4111-8111-111111111111"), ReceiptId: uuid.MustParse("22222222-2222-4222-8222-222222222222")}
var liveActs *EntraActivities

func liveEnv() *testsuite.TestWorkflowEnvironment {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivity(&EntraActivities{})
	return env
}

func TestEntraJoinerEnablesBeforeActivation(t *testing.T) {
	env := liveEnv()
	var got steps
	refs := []registry.TemplateVersionRef{{Name: "analyst", Version: 1}}
	env.OnActivity(liveActs.EntraMatchTemplates, mock.Anything, liveRef).Return(refs, nil)
	env.OnActivity(liveActs.EntraLinkUser, mock.Anything, liveRef).Return(nil).Run(got.add("link"))
	env.OnActivity(liveActs.EntraEnsureInstance, mock.Anything, liveRef, refs[0]).Return("instance", nil).Run(got.add("ensure"))
	env.OnActivity(liveActs.EntraCreate, mock.Anything, liveRef, "instance").Return(nil).Run(got.add("create"))
	env.OnActivity(liveActs.EntraEnable, mock.Anything, liveRef, "instance").Return(nil).Run(got.add("enable"))
	env.OnActivity(liveActs.EntraActivate, mock.Anything, liveRef, "instance").Return(nil).Run(got.add("activate"))
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil).Run(got.add("settle"))
	env.ExecuteWorkflow(EntraJoiner, liveRef)
	if env.GetWorkflowError() != nil || !equal(got, []string{"link", "ensure", "create", "enable", "activate", "settle"}) {
		t.Fatalf("live joiner order: %v %v", got, env.GetWorkflowError())
	}
}

// An unlinked person still gets their agents; only knowledge retrieval refuses for them.
func TestEntraJoinerContinuesWhenTheUserCannotBeLinked(t *testing.T) {
	env := liveEnv()
	var got steps
	refs := []registry.TemplateVersionRef{{Name: "analyst", Version: 1}}
	env.OnActivity(liveActs.EntraMatchTemplates, mock.Anything, liveRef).Return(refs, nil)
	env.OnActivity(liveActs.EntraLinkUser, mock.Anything, liveRef).Return(temporal.NewNonRetryableApplicationError("Entra user lookup refused", "lookup-refused", nil)).Run(got.add("link"))
	env.OnActivity(liveActs.EntraUnlinkUser, mock.Anything, liveRef).Return(nil).Run(got.add("unlink"))
	env.OnActivity(liveActs.EntraEnsureInstance, mock.Anything, liveRef, refs[0]).Return("instance", nil).Run(got.add("ensure"))
	env.OnActivity(liveActs.EntraCreate, mock.Anything, liveRef, "instance").Return(nil)
	env.OnActivity(liveActs.EntraEnable, mock.Anything, liveRef, "instance").Return(nil)
	env.OnActivity(liveActs.EntraActivate, mock.Anything, liveRef, "instance").Return(nil).Run(got.add("activate"))
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil)
	env.ExecuteWorkflow(EntraJoiner, liveRef)
	if env.GetWorkflowError() != nil || !equal(got, []string{"link", "unlink", "ensure", "activate"}) {
		t.Fatalf("joiner with an unlinked user: %v %v", got, env.GetWorkflowError())
	}
}

// A lookup that keeps failing gives up within minutes, records the person unlinked, and the
// joiner continues; if even that cannot be recorded, the joiner fails rather than keep a link.
func TestEntraJoinerBoundsAFailingLookup(t *testing.T) {
	for name, unlink := range map[string]error{"recorded": nil, "unrecorded": errors.New("database unavailable")} {
		t.Run(name, func(t *testing.T) {
			env := liveEnv()
			attempts := 0
			refs := []registry.TemplateVersionRef{{Name: "analyst", Version: 1}}
			env.OnActivity(liveActs.EntraMatchTemplates, mock.Anything, liveRef).Return(refs, nil)
			env.OnActivity(liveActs.EntraLinkUser, mock.Anything, liveRef).Return(errors.New("graph unavailable")).Run(func(mock.Arguments) { attempts++ })
			env.OnActivity(liveActs.EntraUnlinkUser, mock.Anything, liveRef).Return(unlink)
			env.OnActivity(liveActs.EntraEnsureInstance, mock.Anything, liveRef, refs[0]).Return("instance", nil)
			env.OnActivity(liveActs.EntraCreate, mock.Anything, liveRef, "instance").Return(nil)
			env.OnActivity(liveActs.EntraEnable, mock.Anything, liveRef, "instance").Return(nil)
			env.OnActivity(liveActs.EntraActivate, mock.Anything, liveRef, "instance").Return(nil)
			env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil)
			env.ExecuteWorkflow(EntraJoiner, liveRef)
			if attempts != 5 {
				t.Fatalf("lookup attempts = %d, want 5", attempts)
			}
			if failed := env.GetWorkflowError() != nil; failed != (unlink != nil) {
				t.Fatalf("joiner error = %v with unlink error %v", env.GetWorkflowError(), unlink)
			}
		})
	}
}

// A joiner recorded before user linking (no version marker) replays without a lookup.
func TestEntraJoinerBeforeUserLinkingNeverLooksUp(t *testing.T) {
	env := liveEnv()
	env.OnGetVersion("entra-link-user", workflow.DefaultVersion, workflow.Version(1)).Return(workflow.DefaultVersion)
	env.OnActivity(liveActs.EntraMatchTemplates, mock.Anything, liveRef).Return([]registry.TemplateVersionRef{}, nil)
	var got steps
	// A forbidden call would only fail the link step, which the joiner tolerates: record it instead.
	env.OnActivity(liveActs.EntraLinkUser, mock.Anything, liveRef).Return(nil).Maybe().Run(got.add("link"))
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil)
	env.ExecuteWorkflow(EntraJoiner, liveRef)
	if env.GetWorkflowError() != nil || len(got) != 0 {
		t.Fatalf("pre-linking joiner: steps %v, error %v", got, env.GetWorkflowError())
	}
}

func TestEntraLeaverAttemptsEveryDisableAfterLocalSuspension(t *testing.T) {
	env := liveEnv()
	var got steps
	env.OnActivity(liveActs.EntraPrepareLeaver, mock.Anything, liveRef).Return([]string{"one", "two"}, nil).Run(got.add("suspend-all"))
	for _, name := range []string{"one", "two"} {
		env.OnActivity(liveActs.EntraRevoke, mock.Anything, liveRef, name).Return(nil).Run(got.add("revoke-" + name))
		var err error
		if name == "one" {
			err = errors.New("uncertain provider result")
		}
		env.OnActivity(liveActs.EntraDisable, mock.Anything, liveRef, name).Return(err).Once().Run(got.add("disable-" + name))
	}
	env.OnActivity(liveActs.EntraRecordReviewCoverage, mock.Anything, liveRef).Return(nil).Run(got.add("coverage"))
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil).Run(got.add("settle"))
	env.ExecuteWorkflow(EntraLeaver, liveRef)
	if env.GetWorkflowError() == nil || !equal(got, []string{"suspend-all", "disable-one", "disable-two", "revoke-one", "revoke-two", "coverage", "settle"}) {
		t.Fatalf("leaver skipped remaining instances: %v %v", got, env.GetWorkflowError())
	}
	env.AssertExpectations(t)
}

func TestEntraLeaverRehireOnlyCancelsGrace(t *testing.T) {
	env := liveEnv()
	newRef := liveRef
	newRef.ReceiptId = uuid.New()
	env.OnActivity(liveActs.EntraPrepareLeaver, mock.Anything, liveRef).Return([]string{"one"}, nil)
	env.OnActivity(liveActs.EntraRevoke, mock.Anything, liveRef, "one").Return(nil)
	env.OnActivity(liveActs.EntraDisable, mock.Anything, liveRef, "one").Return(nil)
	env.OnActivity(liveActs.EntraRecordReviewCoverage, mock.Anything, liveRef).Return(nil)
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil)
	env.OnActivity(liveActs.EntraConfirmRehire, mock.Anything, liveRef, newRef).Return(nil)
	env.RegisterDelayedCallback(func() { env.SignalWorkflow(EntraRehiredSignal, newRef) }, time.Hour)
	env.ExecuteWorkflow(EntraLeaver, liveRef)
	var result LeaverResult
	if err := env.GetWorkflowResult(&result); err != nil || !result.Rehired {
		t.Fatalf("rehire grace cancellation: %+v %v", result, err)
	}
	env.AssertNotCalled(t, "EntraEnable", mock.Anything, mock.Anything, mock.Anything)
	env.AssertNotCalled(t, "EntraRetire", mock.Anything, mock.Anything, mock.Anything)
}

func TestEntraSupersededJoinerSettlesItsPersonalSetup(t *testing.T) {
	env := liveEnv()
	env.OnActivity(liveActs.EntraMatchTemplates, mock.Anything, liveRef).Return(nil, temporal.NewNonRetryableApplicationError("superseded", "scope-refused", nil)).Once()
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil).Once()
	env.ExecuteWorkflow(EntraJoiner, liveRef)
	if env.GetWorkflowError() == nil {
		t.Fatal("superseded joiner reported success")
	}
	env.AssertExpectations(t)
}

func TestEntraFailedLeaverPreparationSettlesItsPersonalSetup(t *testing.T) {
	env := liveEnv()
	env.OnActivity(liveActs.EntraPrepareLeaver, mock.Anything, liveRef).Return(nil, temporal.NewNonRetryableApplicationError("superseded", "scope-refused", nil)).Once()
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil).Once()
	env.ExecuteWorkflow(EntraLeaver, liveRef)
	if env.GetWorkflowError() == nil {
		t.Fatal("superseded leaver reported success")
	}
	env.AssertExpectations(t)
}

// Revocation is local and idempotent, so the leaver retries it: one transient database error must
// not leave the instance's virtual keys active for a later rehire to reactivate.
func TestEntraLeaverRetriesKeyRevocation(t *testing.T) {
	env := liveEnv()
	env.OnActivity(liveActs.EntraPrepareLeaver, mock.Anything, liveRef).Return([]string{"one"}, nil)
	env.OnActivity(liveActs.EntraRevoke, mock.Anything, liveRef, "one").Return(errors.New("transient database error")).Once()
	env.OnActivity(liveActs.EntraRevoke, mock.Anything, liveRef, "one").Return(nil).Once()
	env.OnActivity(liveActs.EntraDisable, mock.Anything, liveRef, "one").Return(nil).Once()
	env.OnActivity(liveActs.EntraRecordReviewCoverage, mock.Anything, liveRef).Return(nil)
	env.OnActivity(liveActs.EntraSettleSetup, mock.Anything, liveRef).Return(nil)
	env.OnActivity(liveActs.EntraRetire, mock.Anything, liveRef, "one").Return(nil).Once()
	env.ExecuteWorkflow(EntraLeaver, liveRef)
	var result LeaverResult
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatalf("a retried revocation still needs reconciliation: %v", err)
	}
	env.AssertExpectations(t)
}

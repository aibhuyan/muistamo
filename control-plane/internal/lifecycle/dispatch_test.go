package lifecycle_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/mocks"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
)

func TestTemporalMissingHandoffHistoryRequiresReconciliation(t *testing.T) {
	c := &mocks.Client{}
	tenant := uuid.New()
	event := intakeEvent("expired", muistamov1.HREventTypeJoiner, 0)
	c.On("DescribeWorkflowExecution", mock.Anything, lifecycle.HRDispatchWorkflowID(tenant, event.Id), "").Return(nil, serviceerror.NewNotFound("fake expired history"))
	d := lifecycle.TemporalDispatcher{Client: c}
	_, err := d.Dispatch(context.Background(), lifecycle.Scope{Tenant: tenant, EventID: event.Id, Generation: 1, HandoffAttempted: true}, event)
	if !errors.Is(err, lifecycle.ErrHandoffUncertain) {
		t.Fatalf("missing history was treated as a new dispatch: %v", err)
	}
	c.AssertExpectations(t)
}

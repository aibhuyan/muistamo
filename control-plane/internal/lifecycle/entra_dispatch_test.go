package lifecycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/mocks"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

func TestEntraDispatchRetryUsesOpaquePinnedHistory(t *testing.T) {
	c := &mocks.Client{}
	tenant := uuid.New()
	receipt := uuid.New()
	version := uuid.New()
	event := intakeEvent("private-hr-event", muistamov1.HREventTypeJoiner, 0)
	route := &muistamov1.HRIdentityRoute{TenantId: tenant, ReceiptId: receipt, ProviderMode: "entra", BindingVersion: &version}
	scope := lifecycle.Scope{Tenant: tenant, EventID: event.Id, Generation: 1, HandoffAttempted: true, IdentityRoute: route}
	ref := muistamov1.EntraLifecycleRef{TenantId: tenant, ReceiptId: receipt}
	c.On("DescribeWorkflowExecution", mock.Anything, lifecycle.EntraDispatchWorkflowID(ref), "").Return(nil, serviceerror.NewNotFound("expired history"))
	_, err := (lifecycle.TemporalDispatcher{Client: c}).Dispatch(context.Background(), scope, event)
	if !errors.Is(err, lifecycle.ErrHandoffUncertain) {
		t.Fatalf("missing live history permitted a fresh start: %v", err)
	}
	c.AssertExpectations(t)
	c.AssertNotCalled(t, "ExecuteWorkflow", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestEntraDispatchRejectsUnprovedRouteBeforeTemporal(t *testing.T) {
	tenant, receipt, version := uuid.New(), uuid.New(), uuid.New()
	for _, route := range []muistamov1.HRIdentityRoute{
		{TenantId: uuid.New(), ReceiptId: receipt, ProviderMode: "entra", BindingVersion: &version},
		{TenantId: tenant, ReceiptId: receipt, ProviderMode: "entra"},
		{TenantId: tenant, ReceiptId: receipt, ProviderMode: "unknown"},
		{TenantId: tenant, ReceiptId: receipt, ProviderMode: "simulated", BindingVersion: &version},
		{TenantId: tenant, ProviderMode: "entra", BindingVersion: &version},
	} {
		c := &mocks.Client{}
		c.On("DescribeWorkflowExecution", mock.Anything, mock.Anything, mock.Anything).Return(nil, serviceerror.NewNotFound("expired history"))
		scope := lifecycle.Scope{Tenant: tenant, EventID: "event", HandoffAttempted: true, IdentityRoute: &route}
		if _, err := (lifecycle.TemporalDispatcher{Client: c}).Dispatch(context.Background(), scope, intakeEvent("event", "joiner", 0)); !errors.Is(err, lifecycle.ErrHandoffUncertain) {
			t.Fatalf("unproved route accepted: %+v %v", route, err)
		}
		if len(c.Calls) != 0 {
			t.Fatalf("unproved route consulted Temporal: %+v", route)
		}
	}
}

func TestEntraIntakePinsRouteAndSignsActualDispatchID(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "operator:test", RequestID: "enroll"}
	b := muistamov1.EntraIdentityBinding{TenantId: f.scope.Tenant.String(), BindingVersion: uuid.NewString(), EntraTenantId: uuid.NewString(), BlueprintAppId: uuid.NewString(), BlueprintObjectId: uuid.NewString(), BlueprintPrincipalId: uuid.NewString(), SponsorUserIds: []string{uuid.NewString()}, CredentialRef: "fake-vault", CredentialVersion: "fake-version"}
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, actor, b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnrollIdentityTenant(ctx, actor, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	d := &intakeRecorder{}
	in := newIntake(t, f, d)
	event := intakeEvent("private-event-id", "joiner", 0)
	if _, err := in.Accept(ctx, actor.Tenant, "hris:test", event.Id, event); err != nil {
		t.Fatal(err)
	}
	if len(d.scopes) != 1 || d.scopes[0].IdentityRoute == nil {
		t.Fatal("dispatch did not load committed identity route")
	}
	route := d.scopes[0].IdentityRoute
	if route.ProviderMode != "entra" || route.BindingVersion == nil || route.BindingVersion.String() != b.BindingVersion {
		t.Fatalf("dispatch route changed: %+v", route)
	}
	want := lifecycle.EntraDispatchWorkflowID(muistamov1.EntraLifecycleRef{TenantId: actor.Tenant, ReceiptId: route.ReceiptId})
	events, err := f.svc.ListEvents(ctx, actor, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	proofs := 0
	for _, entry := range events {
		if entry.Action == "hr.event.dispatch-intent" || entry.Action == "hr.event.dispatched" {
			var after map[string]any
			if err := json.Unmarshal(entry.After, &after); err != nil {
				t.Fatal(err)
			}
			if after["dispatchWorkflowId"] != want {
				t.Fatalf("signed dispatch id does not match pinned live route: %v", after)
			}
			proofs++
		}
	}
	if proofs != 2 {
		t.Fatalf("live handoff evidence missing: %d", proofs)
	}
}

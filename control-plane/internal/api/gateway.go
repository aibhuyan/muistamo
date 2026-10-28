package api

import (
	"context"
	"net/http"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// The gateway's virtual-key and usage endpoints are declared in the contract (step 2 of
// docs/agentgateway-plan.md) ahead of their implementation: key issuance and revocation arrive with
// the authorisation service (step 3) and usage with metering (step 5). Until then they answer 501
// and say so, rather than pretending to issue or meter anything (invariant 8).

func notYet(step string) muistamov1.Problem {
	detail := "the gateway's " + step + " is not implemented yet; see docs/agentgateway-plan.md"
	return muistamov1.Problem{Title: "Not implemented", Status: http.StatusNotImplemented, Detail: &detail}
}

func (s *server) ListVirtualKeys(context.Context, muistamov1.ListVirtualKeysRequestObject) (muistamov1.ListVirtualKeysResponseObject, error) {
	return muistamov1.ListVirtualKeysdefaultApplicationProblemPlusJSONResponse{Body: notYet("virtual key service (step 3)"), StatusCode: http.StatusNotImplemented}, nil
}

func (s *server) IssueVirtualKey(context.Context, muistamov1.IssueVirtualKeyRequestObject) (muistamov1.IssueVirtualKeyResponseObject, error) {
	return muistamov1.IssueVirtualKeydefaultApplicationProblemPlusJSONResponse{Body: notYet("virtual key service (step 3)"), StatusCode: http.StatusNotImplemented}, nil
}

func (s *server) GetVirtualKey(context.Context, muistamov1.GetVirtualKeyRequestObject) (muistamov1.GetVirtualKeyResponseObject, error) {
	return muistamov1.GetVirtualKeydefaultApplicationProblemPlusJSONResponse{Body: notYet("virtual key service (step 3)"), StatusCode: http.StatusNotImplemented}, nil
}

func (s *server) RevokeVirtualKey(context.Context, muistamov1.RevokeVirtualKeyRequestObject) (muistamov1.RevokeVirtualKeyResponseObject, error) {
	return muistamov1.RevokeVirtualKeydefaultApplicationProblemPlusJSONResponse{Body: notYet("virtual key service (step 3)"), StatusCode: http.StatusNotImplemented}, nil
}

func (s *server) ListUsage(context.Context, muistamov1.ListUsageRequestObject) (muistamov1.ListUsageResponseObject, error) {
	return muistamov1.ListUsagedefaultApplicationProblemPlusJSONResponse{Body: notYet("usage metering (step 5)"), StatusCode: http.StatusNotImplemented}, nil
}

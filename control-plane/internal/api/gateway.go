package api

import (
	"context"
	"net/http"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// Virtual keys (docs/agentgateway-plan.md, step 3a). Usage arrives with metering (step 5); until
// then it answers 501 and says so, rather than pretending to meter anything (invariant 8).

func (s *server) ListVirtualKeys(ctx context.Context, req muistamov1.ListVirtualKeysRequestObject) (muistamov1.ListVirtualKeysResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListVirtualKeysdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	instance := ""
	if req.Params.Instance != nil {
		instance = *req.Params.Instance
	}
	keys, err := s.svc.ListKeys(ctx, actor, instance)
	if err != nil {
		return muistamov1.ListVirtualKeysdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListVirtualKeys200JSONResponse{Items: keys}, nil
}

func (s *server) IssueVirtualKey(ctx context.Context, req muistamov1.IssueVirtualKeyRequestObject) (muistamov1.IssueVirtualKeyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.IssueVirtualKeydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	issued, err := s.svc.IssueKey(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.IssueVirtualKeydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.IssueVirtualKey201JSONResponse{
		Body:    issued,
		Headers: muistamov1.IssueVirtualKey201ResponseHeaders{CacheControl: "no-store"},
	}, nil
}

func (s *server) GetVirtualKey(ctx context.Context, req muistamov1.GetVirtualKeyRequestObject) (muistamov1.GetVirtualKeyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetVirtualKeydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	key, err := s.svc.GetKey(ctx, actor, req.Id)
	if err != nil {
		return muistamov1.GetVirtualKeydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetVirtualKey200JSONResponse(key), nil
}

func (s *server) RevokeVirtualKey(ctx context.Context, req muistamov1.RevokeVirtualKeyRequestObject) (muistamov1.RevokeVirtualKeyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.RevokeVirtualKeydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	key, err := s.svc.RevokeKey(ctx, actor, req.Id, string(req.Body.Reason))
	if err != nil {
		return muistamov1.RevokeVirtualKeydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.RevokeVirtualKey200JSONResponse(key), nil
}

func (s *server) ListUsage(context.Context, muistamov1.ListUsageRequestObject) (muistamov1.ListUsageResponseObject, error) {
	detail := "the gateway's usage metering (step 5) is not implemented yet; see docs/agentgateway-plan.md"
	return muistamov1.ListUsagedefaultApplicationProblemPlusJSONResponse{
		Body:       muistamov1.Problem{Title: "Not implemented", Status: http.StatusNotImplemented, Detail: &detail},
		StatusCode: http.StatusNotImplemented,
	}, nil
}

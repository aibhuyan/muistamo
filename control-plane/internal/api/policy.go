package api

import (
	"context"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

func (s *server) ApplyLink(ctx context.Context, req muistamov1.ApplyLinkRequestObject) (muistamov1.ApplyLinkResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyLink(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ApplyLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	etag := registry.ETag(rec.Revision)
	if created {
		return muistamov1.ApplyLink201JSONResponse{Body: rec, Headers: muistamov1.ApplyLink201ResponseHeaders{ETag: &etag}}, nil
	}
	return muistamov1.ApplyLink200JSONResponse{LinkRecordJSONResponse: linkResponse(rec)}, nil
}

func (s *server) GetLink(ctx context.Context, req muistamov1.GetLinkRequestObject) (muistamov1.GetLinkResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetLink(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetLink200JSONResponse{LinkRecordJSONResponse: linkResponse(rec)}, nil
}

func (s *server) ListLinks(ctx context.Context, _ muistamov1.ListLinksRequestObject) (muistamov1.ListLinksResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListLinksdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListLinks(ctx, actor)
	if err != nil {
		return muistamov1.ListLinksdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListLinks200JSONResponse{Items: items}, nil
}

func (s *server) DeleteLink(ctx context.Context, req muistamov1.DeleteLinkRequestObject) (muistamov1.DeleteLinkResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = s.svc.DeleteLink(ctx, actor, req.Name)
	}
	if err != nil {
		return muistamov1.DeleteLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.DeleteLink204Response{}, nil
}

func (s *server) ApplyActionPolicy(ctx context.Context, req muistamov1.ApplyActionPolicyRequestObject) (muistamov1.ApplyActionPolicyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyActionPolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyActionPolicy(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ApplyActionPolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	etag := registry.ETag(rec.Revision)
	if created {
		return muistamov1.ApplyActionPolicy201JSONResponse{Body: rec, Headers: muistamov1.ApplyActionPolicy201ResponseHeaders{ETag: &etag}}, nil
	}
	return muistamov1.ApplyActionPolicy200JSONResponse{ActionPolicyRecordJSONResponse: actionPolicyResponse(rec)}, nil
}

func (s *server) GetActionPolicy(ctx context.Context, req muistamov1.GetActionPolicyRequestObject) (muistamov1.GetActionPolicyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetActionPolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetActionPolicy(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetActionPolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetActionPolicy200JSONResponse{ActionPolicyRecordJSONResponse: actionPolicyResponse(rec)}, nil
}

func (s *server) ListActionPolicies(ctx context.Context, _ muistamov1.ListActionPoliciesRequestObject) (muistamov1.ListActionPoliciesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListActionPoliciesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListActionPolicies(ctx, actor)
	if err != nil {
		return muistamov1.ListActionPoliciesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListActionPolicies200JSONResponse{Items: items}, nil
}

func (s *server) DeleteActionPolicy(ctx context.Context, req muistamov1.DeleteActionPolicyRequestObject) (muistamov1.DeleteActionPolicyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = s.svc.DeleteActionPolicy(ctx, actor, req.Name)
	}
	if err != nil {
		return muistamov1.DeleteActionPolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.DeleteActionPolicy204Response{}, nil
}

func (s *server) DecidePolicy(ctx context.Context, req muistamov1.DecidePolicyRequestObject) (muistamov1.DecidePolicyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.DecidePolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	d, err := s.svc.Decide(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.DecidePolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.DecidePolicy200JSONResponse(d), nil
}

func (s *server) SimulatePolicy(ctx context.Context, req muistamov1.SimulatePolicyRequestObject) (muistamov1.SimulatePolicyResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.SimulatePolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	sim, err := s.svc.Simulate(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.SimulatePolicydefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.SimulatePolicy200JSONResponse(sim), nil
}

func (s *server) GetCompiledPolicies(ctx context.Context, _ muistamov1.GetCompiledPoliciesRequestObject) (muistamov1.GetCompiledPoliciesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetCompiledPoliciesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	out, err := s.svc.CompiledPolicies(ctx, actor)
	if err != nil {
		return muistamov1.GetCompiledPoliciesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetCompiledPolicies200JSONResponse(out), nil
}

func linkResponse(rec muistamov1.AgentLinkRecord) muistamov1.LinkRecordJSONResponse {
	etag := registry.ETag(rec.Revision)
	return muistamov1.LinkRecordJSONResponse{Body: rec, Headers: muistamov1.LinkRecordResponseHeaders{ETag: &etag}}
}

func actionPolicyResponse(rec muistamov1.ActionPolicyRecord) muistamov1.ActionPolicyRecordJSONResponse {
	etag := registry.ETag(rec.Revision)
	return muistamov1.ActionPolicyRecordJSONResponse{Body: rec, Headers: muistamov1.ActionPolicyRecordResponseHeaders{ETag: &etag}}
}

package api

import (
	"context"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func (s *server) ListModels(ctx context.Context, _ muistamov1.ListModelsRequestObject) (muistamov1.ListModelsResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListModelsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListModels(ctx, actor)
	if err != nil {
		return muistamov1.ListModelsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListModels200JSONResponse{Items: items}, nil
}

func (s *server) GetModel(ctx context.Context, req muistamov1.GetModelRequestObject) (muistamov1.GetModelResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetModeldefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetModel(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetModeldefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetModel200JSONResponse(rec), nil
}

func (s *server) DecideModel(ctx context.Context, req muistamov1.DecideModelRequestObject) (muistamov1.DecideModelResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.DecideModeldefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.DecideModel(ctx, actor, req.Name, req.Body.Decision, req.Body.Reason)
	if err != nil {
		return muistamov1.DecideModeldefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.DecideModel200JSONResponse(rec), nil
}

func (s *server) ListModelAliases(ctx context.Context, _ muistamov1.ListModelAliasesRequestObject) (muistamov1.ListModelAliasesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListModelAliasesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListModelAliases(ctx, actor)
	if err != nil {
		return muistamov1.ListModelAliasesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListModelAliases200JSONResponse{Items: items}, nil
}

func (s *server) GetModelAlias(ctx context.Context, req muistamov1.GetModelAliasRequestObject) (muistamov1.GetModelAliasResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetModelAliasdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetModelAlias(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetModelAliasdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetModelAlias200JSONResponse(rec), nil
}

func (s *server) StartRollout(ctx context.Context, req muistamov1.StartRolloutRequestObject) (muistamov1.StartRolloutResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.StartRolloutdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	out, err := s.svc.StartRollout(ctx, actor, req.Name, *req.Body)
	if err != nil {
		return muistamov1.StartRolloutdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.StartRollout201JSONResponse(out), nil
}

func (s *server) ListRollouts(ctx context.Context, _ muistamov1.ListRolloutsRequestObject) (muistamov1.ListRolloutsResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListRolloutsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListRollouts(ctx, actor)
	if err != nil {
		return muistamov1.ListRolloutsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListRollouts200JSONResponse{Items: items}, nil
}

func (s *server) GetRollout(ctx context.Context, req muistamov1.GetRolloutRequestObject) (muistamov1.GetRolloutResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetRolloutdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	out, err := s.svc.GetRollout(ctx, actor, req.Id)
	if err != nil {
		return muistamov1.GetRolloutdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetRollout200JSONResponse(out), nil
}

func (s *server) RollbackRollout(ctx context.Context, req muistamov1.RollbackRolloutRequestObject) (muistamov1.RollbackRolloutResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.RollbackRolloutdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	out, err := s.svc.RollbackRollout(ctx, actor, req.Id, req.Body.Reason)
	if err != nil {
		return muistamov1.RollbackRolloutdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.RollbackRollout200JSONResponse(out), nil
}

func (s *server) ApplyModel(ctx context.Context, req muistamov1.ApplyModelRequestObject) (muistamov1.ApplyModelResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyModeldefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyModel(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ApplyModeldefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if created {
		return muistamov1.ApplyModel201JSONResponse(rec), nil
	}
	return muistamov1.ApplyModel200JSONResponse(rec), nil
}

func (s *server) ApplyModelAlias(ctx context.Context, req muistamov1.ApplyModelAliasRequestObject) (muistamov1.ApplyModelAliasResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyModelAliasdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyModelAlias(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ApplyModelAliasdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if created {
		return muistamov1.ApplyModelAlias201JSONResponse(rec), nil
	}
	return muistamov1.ApplyModelAlias200JSONResponse(rec), nil
}

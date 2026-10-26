package api

import (
	"context"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

func (s *server) ApplyClone(ctx context.Context, req muistamov1.ApplyCloneRequestObject) (muistamov1.ApplyCloneResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyClonedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyClone(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ApplyClonedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	etag := registry.ETag(rec.Revision)
	if created {
		return muistamov1.ApplyClone201JSONResponse{Body: rec, Headers: muistamov1.ApplyClone201ResponseHeaders{ETag: &etag}}, nil
	}
	return muistamov1.ApplyClone200JSONResponse{CloneRecordJSONResponse: cloneResponse(rec)}, nil
}

func (s *server) GetClone(ctx context.Context, req muistamov1.GetCloneRequestObject) (muistamov1.GetCloneResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetClonedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetClone(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetClonedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetClone200JSONResponse{CloneRecordJSONResponse: cloneResponse(rec)}, nil
}

func (s *server) ListClones(ctx context.Context, _ muistamov1.ListClonesRequestObject) (muistamov1.ListClonesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListClonesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListClones(ctx, actor, "")
	if err != nil {
		return muistamov1.ListClonesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListClones200JSONResponse{Items: items}, nil
}

func (s *server) ListTemplateClones(ctx context.Context, req muistamov1.ListTemplateClonesRequestObject) (muistamov1.ListTemplateClonesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListTemplateClonesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if _, err := s.svc.GetTemplate(ctx, actor, req.Name); err != nil {
		return muistamov1.ListTemplateClonesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListClones(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.ListTemplateClonesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListTemplateClones200JSONResponse{Items: items}, nil
}

func (s *server) SyncClone(ctx context.Context, req muistamov1.SyncCloneRequestObject) (muistamov1.SyncCloneResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.SyncClonedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.SyncClone(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.SyncClonedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.SyncClone200JSONResponse{CloneRecordJSONResponse: cloneResponse(rec)}, nil
}

func (s *server) GetEffectiveSpec(ctx context.Context, req muistamov1.GetEffectiveSpecRequestObject) (muistamov1.GetEffectiveSpecResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetEffectiveSpecdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	out, err := s.svc.EffectiveSpec(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetEffectiveSpecdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetEffectiveSpec200JSONResponse(out), nil
}

func cloneResponse(rec muistamov1.AgentCloneRecord) muistamov1.CloneRecordJSONResponse {
	etag := registry.ETag(rec.Revision)
	return muistamov1.CloneRecordJSONResponse{Body: rec, Headers: muistamov1.CloneRecordResponseHeaders{ETag: &etag}}
}

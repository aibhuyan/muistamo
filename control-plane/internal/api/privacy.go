package api

import (
	"context"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func (s *server) ErasePersonalData(ctx context.Context, req muistamov1.ErasePersonalDataRequestObject) (muistamov1.ErasePersonalDataResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ErasePersonalDatadefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	proof, created, err := s.svc.Erase(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ErasePersonalDatadefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if created {
		return muistamov1.ErasePersonalData201JSONResponse(proof), nil
	}
	return muistamov1.ErasePersonalData200JSONResponse(proof), nil
}

func (s *server) GetErasure(ctx context.Context, req muistamov1.GetErasureRequestObject) (muistamov1.GetErasureResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetErasuredefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	proof, err := s.svc.GetErasure(ctx, actor, req.Id)
	if err != nil {
		return muistamov1.GetErasuredefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetErasure200JSONResponse(proof), nil
}

func (s *server) ExportPersonalData(ctx context.Context, req muistamov1.ExportPersonalDataRequestObject) (muistamov1.ExportPersonalDataResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ExportPersonalDatadefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	out, err := s.svc.ExportPersonalData(ctx, actor, req.Body.Subject)
	if err != nil {
		return muistamov1.ExportPersonalDatadefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ExportPersonalData200JSONResponse(out), nil
}

func (s *server) GetEntraUserLink(ctx context.Context, req muistamov1.GetEntraUserLinkRequestObject) (muistamov1.GetEntraUserLinkResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetEntraUserLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	link, err := s.svc.GetEntraUserLink(ctx, actor, req.PersonId)
	if err != nil {
		return muistamov1.GetEntraUserLinkdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetEntraUserLink200JSONResponse(link), nil
}

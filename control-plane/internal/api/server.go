// Package api serves the control-plane HTTP API generated from contracts/.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

const (
	service      = "control-plane"
	defaultLimit = 50
	maxLimit     = 200
)

// Handler returns the full HTTP handler: authentication, contract validation, then the API.
// hr may be nil, in which case every HR event is refused.
func Handler(svc *registry.Service, resolver TenantResolver, hr HRIntake, log *slog.Logger) http.Handler {
	s := &server{svc: svc, hr: hr, log: log}
	strict := muistamov1.NewStrictHandlerWithOptions(s, nil, muistamov1.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeProblem(w, http.StatusBadRequest, "Bad request", err.Error())
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("response failed", "path", r.URL.Path, "err", err)
			writeProblem(w, http.StatusInternalServerError, "Internal error", "")
		},
	})
	mux := http.NewServeMux()
	routes := muistamov1.HandlerWithOptions(strict, muistamov1.StdHTTPServerOptions{BaseRouter: mux})
	return authenticate(resolver, hr, log, validateDocuments(routes))
}

type server struct {
	svc *registry.Service
	hr  HRIntake
	log *slog.Logger
}

var _ muistamov1.StrictServerInterface = (*server)(nil)

func (s *server) GetHealth(context.Context, muistamov1.GetHealthRequestObject) (muistamov1.GetHealthResponseObject, error) {
	return muistamov1.GetHealth200JSONResponse{Status: muistamov1.HealthStatusStatusOk, Service: service}, nil
}

func (s *server) ApplyTemplate(ctx context.Context, req muistamov1.ApplyTemplateRequestObject) (muistamov1.ApplyTemplateResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyTemplatedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyTemplate(ctx, actor, *req.Body)
	if err != nil {
		return muistamov1.ApplyTemplatedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	etag := registry.ETag(rec.Version)
	if created {
		return muistamov1.ApplyTemplate201JSONResponse{Body: rec, Headers: muistamov1.ApplyTemplate201ResponseHeaders{ETag: &etag}}, nil
	}
	return muistamov1.ApplyTemplate200JSONResponse{TemplateRecordJSONResponse: templateResponse(rec)}, nil
}

func (s *server) GetTemplate(ctx context.Context, req muistamov1.GetTemplateRequestObject) (muistamov1.GetTemplateResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetTemplatedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetTemplate(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetTemplatedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetTemplate200JSONResponse{TemplateRecordJSONResponse: templateResponse(rec)}, nil
}

func (s *server) GetTemplateVersion(ctx context.Context, req muistamov1.GetTemplateVersionRequestObject) (muistamov1.GetTemplateVersionResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetTemplateVersiondefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetTemplateVersion(ctx, actor, req.Name, req.Version)
	if err != nil {
		return muistamov1.GetTemplateVersiondefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetTemplateVersion200JSONResponse{TemplateRecordJSONResponse: templateResponse(rec)}, nil
}

func (s *server) ListTemplates(ctx context.Context, req muistamov1.ListTemplatesRequestObject) (muistamov1.ListTemplatesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListTemplatesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	page, err := s.svc.ListTemplates(ctx, actor, deref(req.Params.Cursor), limit(req.Params.Limit))
	if err != nil {
		return muistamov1.ListTemplatesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListTemplates200JSONResponse(page), nil
}

func (s *server) ApplyInstance(ctx context.Context, req muistamov1.ApplyInstanceRequestObject) (muistamov1.ApplyInstanceResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = sameName(req.Name, req.Body.Metadata.Name)
	}
	if err != nil {
		return muistamov1.ApplyInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, created, err := s.svc.ApplyInstance(ctx, actor, *req.Body, deref(req.Params.IfMatch))
	if err != nil {
		return muistamov1.ApplyInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	etag := registry.ETag(rec.Revision)
	if created {
		return muistamov1.ApplyInstance201JSONResponse{Body: rec, Headers: muistamov1.ApplyInstance201ResponseHeaders{ETag: &etag}}, nil
	}
	return muistamov1.ApplyInstance200JSONResponse{InstanceRecordJSONResponse: instanceResponse(rec)}, nil
}

func (s *server) GetInstance(ctx context.Context, req muistamov1.GetInstanceRequestObject) (muistamov1.GetInstanceResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.GetInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.GetInstance(ctx, actor, req.Name)
	if err != nil {
		return muistamov1.GetInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.GetInstance200JSONResponse{InstanceRecordJSONResponse: instanceResponse(rec)}, nil
}

func (s *server) ListInstances(ctx context.Context, req muistamov1.ListInstancesRequestObject) (muistamov1.ListInstancesResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListInstancesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	page, err := s.svc.ListInstances(ctx, actor, deref(req.Params.Cursor), limit(req.Params.Limit))
	if err != nil {
		return muistamov1.ListInstancesdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListInstances200JSONResponse(page), nil
}

func (s *server) TransitionInstance(ctx context.Context, req muistamov1.TransitionInstanceRequestObject) (muistamov1.TransitionInstanceResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.TransitionInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if !req.Body.To.Valid() {
		err = fmt.Errorf("unknown state %q: %w", req.Body.To, registry.ErrInvalid)
		return muistamov1.TransitionInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.Transition(ctx, actor, req.Name, req.Body.To, deref(req.Params.IfMatch))
	if err != nil {
		return muistamov1.TransitionInstancedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.TransitionInstance200JSONResponse{InstanceRecordJSONResponse: instanceResponse(rec)}, nil
}

func (s *server) ListEvents(ctx context.Context, req muistamov1.ListEventsRequestObject) (muistamov1.ListEventsResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListEventsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	after := int64(0)
	if req.Params.AfterSeq != nil {
		after = int64(*req.Params.AfterSeq)
	}
	n := limit(req.Params.Limit)
	events, err := s.svc.ListEvents(ctx, actor, after, n+1)
	if err != nil {
		return muistamov1.ListEventsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	page := muistamov1.EvidenceEventPage{Items: []muistamov1.EvidenceEvent{}}
	if len(events) > n {
		events = events[:n]
		next := int(events[n-1].Seq)
		page.NextAfterSeq = &next
	}
	for _, e := range events {
		tenant, err := uuid.Parse(e.Tenant)
		if err != nil {
			return muistamov1.ListEventsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, fmt.Errorf("stored tenant id: %w", err))), nil
		}
		item := muistamov1.EvidenceEvent{
			Tenant: tenant, Seq: int(e.Seq), OccurredAt: e.OccurredAt, Actor: e.Actor, Action: e.Action,
			Before: e.Before, After: e.After, RequestId: e.RequestID,
			PrevHash: e.PrevHash, Hash: e.Hash, KeyId: e.KeyID, Signature: e.Signature,
		}
		item.Subject.Kind, item.Subject.Name = e.Subject.Kind, e.Subject.Name
		page.Items = append(page.Items, item)
	}
	return muistamov1.ListEvents200JSONResponse(page), nil
}

func (s *server) ReceiveHrEvent(ctx context.Context, req muistamov1.ReceiveHrEventRequestObject) (muistamov1.ReceiveHrEventResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil && s.hr == nil {
		err = errUnauthenticated
	}
	if err != nil {
		return muistamov1.ReceiveHrEventdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	accepted, err := s.hr.Accept(ctx, actor.Tenant, actor.Name, actor.RequestID, *req.Body)
	if err != nil {
		return muistamov1.ReceiveHrEventdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if accepted.Duplicate {
		return muistamov1.ReceiveHrEvent200JSONResponse(accepted), nil
	}
	return muistamov1.ReceiveHrEvent202JSONResponse(accepted), nil
}

func (s *server) RequestPublication(ctx context.Context, req muistamov1.RequestPublicationRequestObject) (muistamov1.RequestPublicationResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.RequestPublicationdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.RequestPublication(ctx, actor, req.Name, req.Version)
	if err != nil {
		return muistamov1.RequestPublicationdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.RequestPublication201JSONResponse{CatalogueRequestJSONResponse: muistamov1.CatalogueRequestJSONResponse(rec)}, nil
}

func (s *server) DecideCatalogueRequest(ctx context.Context, req muistamov1.DecideCatalogueRequestRequestObject) (muistamov1.DecideCatalogueRequestResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.DecideCatalogueRequestdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	rec, err := s.svc.DecideCatalogueRequest(ctx, actor, req.Id, string(req.Body.Decision), req.Body.Reason)
	if err != nil {
		return muistamov1.DecideCatalogueRequestdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.DecideCatalogueRequest200JSONResponse{CatalogueRequestJSONResponse: muistamov1.CatalogueRequestJSONResponse(rec)}, nil
}

func (s *server) WithdrawFromCatalogue(ctx context.Context, req muistamov1.WithdrawFromCatalogueRequestObject) (muistamov1.WithdrawFromCatalogueResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil {
		err = s.svc.Withdraw(ctx, actor, req.Name)
	}
	if err != nil {
		return muistamov1.WithdrawFromCataloguedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.WithdrawFromCatalogue204Response{}, nil
}

func (s *server) ListCatalogue(ctx context.Context, _ muistamov1.ListCatalogueRequestObject) (muistamov1.ListCatalogueResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListCataloguedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	items, err := s.svc.ListCatalogue(ctx, actor)
	if err != nil {
		return muistamov1.ListCataloguedefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListCatalogue200JSONResponse{Items: items}, nil
}

func (s *server) ListCatalogueRequests(ctx context.Context, req muistamov1.ListCatalogueRequestsRequestObject) (muistamov1.ListCatalogueRequestsResponseObject, error) {
	actor, err := s.actor(ctx)
	if err != nil {
		return muistamov1.ListCatalogueRequestsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	state := ""
	if req.Params.State != nil {
		state = string(*req.Params.State)
	}
	items, err := s.svc.ListCatalogueRequests(ctx, actor, state)
	if err != nil {
		return muistamov1.ListCatalogueRequestsdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	return muistamov1.ListCatalogueRequests200JSONResponse{Items: items}, nil
}

func (s *server) actor(ctx context.Context) (registry.Actor, error) {
	actor, ok := actorFrom(ctx)
	if !ok {
		return registry.Actor{}, errUnauthenticated
	}
	return actor, nil
}

// problemResponse has the shape of every generated default (error) response.
type problemResponse struct {
	Body       muistamov1.Problem
	StatusCode int
}

// problem maps an error to a response. Unknown errors are logged and returned as a bare 500
// so internal detail never reaches the caller.
func (s *server) problem(ctx context.Context, err error) problemResponse {
	status, title := http.StatusInternalServerError, "Internal error"
	switch {
	case errors.Is(err, errUnauthenticated), errors.Is(err, store.ErrUnknownTenant):
		status, title = http.StatusUnauthorized, "Unauthorized"
	case errors.Is(err, registry.ErrNotFound):
		status, title = http.StatusNotFound, "Not found"
	case errors.Is(err, registry.ErrInvalid):
		status, title = http.StatusUnprocessableEntity, "Invalid request"
	case errors.Is(err, registry.ErrForbidden):
		status, title = http.StatusForbidden, "Forbidden"
	case errors.Is(err, registry.ErrConflict):
		status, title = http.StatusConflict, "Conflict"
	case errors.Is(err, registry.ErrPrecondition):
		status, title = http.StatusPreconditionFailed, "Precondition failed"
	case errors.Is(err, registry.ErrPreconditionRequired):
		status, title = http.StatusPreconditionRequired, "Precondition required"
	case errors.Is(err, lifecycle.ErrDispatch):
		status, title = http.StatusServiceUnavailable, "Workflow engine unavailable; retry later"
	case errors.Is(err, registry.ErrEvidence):
		status, title = http.StatusServiceUnavailable, "Evidence could not be recorded; nothing was changed"
	}
	actor, _ := actorFrom(ctx)
	if status >= http.StatusInternalServerError {
		s.log.Error("request failed", "request_id", actor.RequestID, "tenant", actor.Tenant, "actor", actor.Name, "err", err)
	}
	p := muistamov1.Problem{Title: title, Status: status}
	if status < http.StatusInternalServerError && status != http.StatusUnauthorized {
		detail := err.Error()
		p.Detail = &detail
	}
	return problemResponse{Body: p, StatusCode: status}
}

func sameName(path, document string) error {
	if path != document {
		return fmt.Errorf("path name %q does not match metadata.name %q: %w", path, document, registry.ErrInvalid)
	}
	return nil
}

func templateResponse(rec muistamov1.AgentTemplateRecord) muistamov1.TemplateRecordJSONResponse {
	etag := registry.ETag(rec.Version)
	return muistamov1.TemplateRecordJSONResponse{Body: rec, Headers: muistamov1.TemplateRecordResponseHeaders{ETag: &etag}}
}

func instanceResponse(rec muistamov1.AgentInstanceRecord) muistamov1.InstanceRecordJSONResponse {
	etag := registry.ETag(rec.Revision)
	return muistamov1.InstanceRecordJSONResponse{Body: rec, Headers: muistamov1.InstanceRecordResponseHeaders{ETag: &etag}}
}

// limit clamps the page size to the contract's 1..200.
func limit(requested *int) int {
	switch {
	case requested == nil:
		return defaultLimit
	case *requested < 1:
		return 1
	case *requested > maxLimit:
		return maxLimit
	}
	return *requested
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

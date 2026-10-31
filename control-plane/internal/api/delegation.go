package api

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling and service-call signatures. The knowledge
// service asks for a delegation with a signed request; the response carries a bearer token.

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/signature"
)

const delegationsPath = "/v1/internal/knowledge/delegations"

// Delegator validates a user token and decides a delegation. entra.Delegator implements it.
// A refusal is a *registry.DelegationRefused, already evidenced.
type Delegator interface {
	Delegate(ctx context.Context, actor registry.Actor, req muistamov1.KnowledgeDelegationRequest) (muistamov1.KnowledgeDelegation, error)
}

// knowledgeSecret loads a tenant's knowledge-service secret; nil means none is set.
type knowledgeSecret func(ctx context.Context, tenant uuid.UUID) ([]byte, error)

// verifyKnowledge authenticates a knowledge-service call and returns its tenant. The signature
// is the HR scheme under the key derived for the knowledge→control-plane direction, so a request
// the control plane signed for the knowledge service can never be replayed here. The nonce in
// the body is checked by the handler, after the signature.
func verifyKnowledge(r *http.Request, secrets knowledgeSecret, now time.Time) (uuid.UUID, error) {
	tenant, err := uuid.Parse(r.Header.Get("X-Muistamo-Tenant"))
	if err != nil {
		return uuid.Nil, errors.New("missing or malformed X-Muistamo-Tenant")
	}
	ts, sig, body, err := readSigned(r, now)
	if err != nil {
		return uuid.Nil, err
	}
	secret, err := secrets(r.Context(), tenant)
	if err != nil {
		return uuid.Nil, fmt.Errorf("load knowledge secret: %w", err)
	}
	if len(secret) == 0 {
		return uuid.Nil, errors.New("no knowledge-service secret is set for the tenant")
	}
	if !hmac.Equal(sig, signature.MAC(signature.DirectionKey(secret, signature.KnowledgeToControlPlane, tenant.String()), ts, body)) {
		return uuid.Nil, errors.New("signature does not match")
	}
	return tenant, nil
}

var notConfigured = muistamov1.IssueKnowledgeDelegationdefaultApplicationProblemPlusJSONResponse{
	StatusCode: http.StatusNotImplemented,
	Body:       muistamov1.Problem{Title: "Delegation is not configured", Status: http.StatusNotImplemented},
}

func (s *server) IssueKnowledgeDelegation(ctx context.Context, req muistamov1.IssueKnowledgeDelegationRequestObject) (muistamov1.IssueKnowledgeDelegationResponseObject, error) {
	actor, err := s.actor(ctx)
	if err == nil && actor.Name != "knowledge:"+actor.Tenant.String() {
		// Only the knowledge service's signature reaches this route (auth.go); never act on any
		// other credential if routing ever changed.
		err = errUnauthenticated
	}
	if err != nil {
		return muistamov1.IssueKnowledgeDelegationdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	if s.delegator == nil {
		return notConfigured, nil
	}
	if err := s.svc.UseDelegationNonce(ctx, actor.Tenant, req.Body.Nonce); err != nil {
		if errors.Is(err, registry.ErrConflict) {
			s.log.Warn("delegation nonce replayed", "request_id", actor.RequestID, "tenant", actor.Tenant, "actor", actor.Name)
			err = errUnauthenticated
		}
		return muistamov1.IssueKnowledgeDelegationdefaultApplicationProblemPlusJSONResponse(s.problem(ctx, err)), nil
	}
	issued, err := s.delegator.Delegate(ctx, actor, *req.Body)
	var refused *registry.DelegationRefused
	switch {
	case err == nil:
		s.log.Info("delegation issued", "request_id", actor.RequestID, "tenant", actor.Tenant, "actor", actor.Name, "person", issued.Person, "agent", issued.Instance)
		return muistamov1.IssueKnowledgeDelegation200JSONResponse{
			Body:    issued,
			Headers: muistamov1.IssueKnowledgeDelegation200ResponseHeaders{CacheControl: "no-store"},
		}, nil
	case errors.As(err, &refused):
		s.log.Info("delegation refused", "request_id", actor.RequestID, "tenant", actor.Tenant, "actor", actor.Name, "reason", refused.Reason)
		return muistamov1.IssueKnowledgeDelegation403JSONResponse{Reason: refused.Reason}, nil
	case errors.Is(err, registry.ErrDelegationNotConfigured):
		return notConfigured, nil
	case errors.Is(err, registry.ErrEvidence):
		s.log.Error("delegation not recorded; nothing issued", "request_id", actor.RequestID, "tenant", actor.Tenant, "actor", actor.Name, "err", err)
		return muistamov1.IssueKnowledgeDelegation503JSONResponse{Reason: muistamov1.KnowledgeDelegationRefusalReasonEvidenceUnavailable}, nil
	default:
		// Nothing about the failure leaves the server; it is logged with the request.
		s.log.Error("delegation failed; nothing issued", "request_id", actor.RequestID, "tenant", actor.Tenant, "actor", actor.Name, "err", err)
		return muistamov1.IssueKnowledgeDelegationdefaultApplicationProblemPlusJSONResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       muistamov1.Problem{Title: "Internal error", Status: http.StatusInternalServerError},
		}, nil
	}
}

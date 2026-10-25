package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// TenantResolver establishes which tenant and actor a request acts for. It must fail closed:
// any doubt returns an error and the request is refused.
type TenantResolver interface {
	Resolve(r *http.Request) (tenant uuid.UUID, actor string, err error)
}

var errUnauthenticated = errors.New("unauthenticated")

// DenyAll refuses every request. It is the resolver whenever no real one is configured.
type DenyAll struct{}

// Resolve always fails.
func (DenyAll) Resolve(*http.Request) (uuid.UUID, string, error) {
	return uuid.Nil, "", errUnauthenticated
}

// InsecureDevHeaders trusts X-Muistamo-Tenant and X-Muistamo-Actor as given. Development only:
// anyone who can reach the server can claim any tenant. Real authentication replaces it.
type InsecureDevHeaders struct{}

// Resolve reads the development headers.
func (InsecureDevHeaders) Resolve(r *http.Request) (uuid.UUID, string, error) {
	tenant, err := uuid.Parse(r.Header.Get("X-Muistamo-Tenant"))
	if err != nil {
		return uuid.Nil, "", errUnauthenticated
	}
	actor := r.Header.Get("X-Muistamo-Actor")
	if actor == "" {
		return uuid.Nil, "", errUnauthenticated
	}
	return tenant, "dev:" + actor, nil
}

type actorKey struct{}

func actorFrom(ctx context.Context) (registry.Actor, bool) {
	actor, ok := ctx.Value(actorKey{}).(registry.Actor)
	return actor, ok
}

// authenticate resolves the actor for every request except the health check. HR events carry
// their own HMAC credential and never use the user resolver.
func authenticate(resolver TenantResolver, hr HRIntake, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		requestID := uuid.NewString()
		w.Header().Set("X-Request-Id", requestID)

		var tenant uuid.UUID
		var name string
		var err error
		if r.URL.Path == hrEventsPath {
			tenant, err = verifyHR(r, hr, time.Now())
			name = "hris:" + tenant.String()
		} else {
			tenant, name, err = resolver.Resolve(r)
		}
		if err != nil {
			log.Warn("request refused", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "err", err)
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "")
			return
		}
		actor := registry.Actor{Tenant: tenant, Name: name, RequestID: requestID}
		log.Info("request", "request_id", requestID, "tenant", tenant, "actor", name, "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}

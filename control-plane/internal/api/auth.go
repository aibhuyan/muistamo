package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
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

// ConsoleRoutes is the explicit list of routes a person signed in through the console may call
// (docs/control-plane-console-plan.md). Every other route refuses a console caller before any
// handler runs. It grows with the console, one reviewed entry at a time.
func ConsoleRoute(r *http.Request) bool {
	if r.URL.RawPath != "" {
		return false // an escaped path never matches: no route by decoding
	}
	parts := strings.Split(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/catalogue/requests":
		return true
	case r.Method == http.MethodPost && len(parts) == 6 && parts[1] == "v1" && parts[2] == "catalogue" &&
		parts[3] == "requests" && parts[5] == "decision":
		id, err := uuid.Parse(parts[4])
		return err == nil && id.String() == parts[4]
	}
	return false
}

// ConsoleResolver authenticates a console caller, also naming the console app.
type ConsoleResolver interface {
	ResolveConsole(r *http.Request) (tenant uuid.UUID, actor string, clientApp uuid.UUID, err error)
}

// clientResolver is a resolver that may name the client app the caller came through.
type clientResolver interface {
	ResolveClient(r *http.Request) (tenant uuid.UUID, actor string, clientApp uuid.UUID, err error)
}

// WithConsole resolves a request with a bearer token through console (only on ConsoleRoute, and
// never together with development headers) and any other request through fallback.
type WithConsole struct {
	Console  ConsoleResolver
	Fallback TenantResolver
}

// Resolve implements TenantResolver.
func (w WithConsole) Resolve(r *http.Request) (uuid.UUID, string, error) {
	tenant, actor, _, err := w.ResolveClient(r)
	return tenant, actor, err
}

// ResolveClient is Resolve, also naming the console app of a console caller.
func (w WithConsole) ResolveClient(r *http.Request) (uuid.UUID, string, uuid.UUID, error) {
	if r.Header.Get("Authorization") == "" {
		tenant, actor, err := w.Fallback.Resolve(r)
		return tenant, actor, uuid.Nil, err
	}
	if r.Header.Get("X-Muistamo-Tenant") != "" || r.Header.Get("X-Muistamo-Actor") != "" {
		return uuid.Nil, "", uuid.Nil, errUnauthenticated // one identity per request, never two
	}
	if !ConsoleRoute(r) {
		return uuid.Nil, "", uuid.Nil, errUnauthenticated
	}
	return w.Console.ResolveConsole(r)
}

type actorKey struct{}

func actorFrom(ctx context.Context) (registry.Actor, bool) {
	actor, ok := ctx.Value(actorKey{}).(registry.Actor)
	return actor, ok
}

// authenticate resolves the actor for every request except the health check. HR events and the
// knowledge service's delegation requests carry their own HMAC credentials and never use the user
// resolver; no other route accepts either.
func authenticate(resolver TenantResolver, hr HRIntake, knowledge knowledgeSecret, log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		requestID := uuid.NewString()
		w.Header().Set("X-Request-Id", requestID)

		var tenant, clientApp uuid.UUID
		var name string
		var err error
		switch r.URL.Path {
		case hrEventsPath:
			tenant, err = verifyHR(r, hr, time.Now())
			name = "hris:" + tenant.String()
		case delegationsPath, peopleCurrentPath:
			tenant, err = verifyKnowledge(r, knowledge, time.Now())
			name = "knowledge:" + tenant.String()
		default:
			// The resolver logs with the server's request id, never one the client sent.
			r = r.WithContext(registry.WithRequestID(r.Context(), requestID))
			if cr, ok := resolver.(clientResolver); ok {
				tenant, name, clientApp, err = cr.ResolveClient(r)
			} else {
				tenant, name, err = resolver.Resolve(r)
			}
		}
		if err != nil {
			log.Warn("request refused", "request_id", requestID, "method", r.Method, "path", r.URL.Path, "err", err)
			if errors.Is(err, registry.ErrUnavailable) {
				writeProblem(w, http.StatusServiceUnavailable, "Service unavailable", "a required check could not be made; try again")
				return
			}
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "")
			return
		}
		actor := registry.Actor{Tenant: tenant, Name: name, RequestID: requestID, ClientApp: clientApp}
		log.Info("request", "request_id", requestID, "tenant", tenant, "actor", name, "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}

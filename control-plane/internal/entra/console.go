package entra

// HUMAN REVIEW REQUIRED (AGENTS.md): authentication and authorisation of people at the control
// plane (docs/control-plane-console-plan.md). A person signed in to the console is accepted only
// with a token their own directory issued to the tenant's console app for the tenant's
// control-plane API app, and only while they are a current employee, decided at this moment by
// the delegation's own rule. The tenant comes from the token's directory alone.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
)

var errConsole = errors.New("not an accepted console caller")

// ConsoleResolver authenticates console callers for the tenants the control plane holds an Entra
// binding for (the same clients that serve delegations).
type ConsoleResolver struct {
	registry *registry.Service
	clients  map[uuid.UUID]*Client // by Muistamo tenant
	log      *slog.Logger
}

// NewConsoleResolver serves the delegator's tenants. Each directory must belong to one tenant.
func NewConsoleResolver(d *Delegator) (*ConsoleResolver, error) {
	seen := map[string]bool{}
	for _, c := range d.clients {
		if seen[c.Directory()] {
			return nil, ErrConfiguration
		}
		seen[c.Directory()] = true
	}
	return &ConsoleResolver{registry: d.registry, clients: d.clients, log: d.log}, nil
}

// Resolve implements api.TenantResolver for a request that carries a bearer token.
func (c *ConsoleResolver) Resolve(r *http.Request) (uuid.UUID, string, error) {
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || raw == "" || strings.Contains(raw, " ") {
		return uuid.Nil, "", errConsole
	}
	// The directory, read without verifying, only to choose the tenant's binding; the token is
	// then verified against exactly that binding.
	directory, ok := unverifiedTenant(raw)
	if !ok {
		return uuid.Nil, "", errConsole
	}
	var tenant uuid.UUID
	var client *Client
	for t, cl := range c.clients {
		if cl.Directory() == directory {
			tenant, client = t, cl
		}
	}
	if client == nil {
		return uuid.Nil, "", errConsole
	}
	ctx := r.Context()
	console, found, err := c.registry.ConsoleClientOf(ctx, tenant)
	if err != nil {
		return uuid.Nil, "", err
	}
	if !found {
		return uuid.Nil, "", errConsole
	}
	user, err := client.ValidateConsoleToken(ctx, raw, time.Now(), console.APIApp, console.ClientApp)
	if err != nil {
		return uuid.Nil, "", errConsole
	}
	actor := registry.Actor{Tenant: tenant, Name: "console-check:" + tenant.String(), RequestID: r.Header.Get("X-Request-Id")}
	reason, err := c.registry.PersonCurrent(ctx, actor, registry.DelegationRequest{
		BindingVersion: uuid.MustParse(client.binding.BindingVersion),
		EntraTenant:    uuid.MustParse(client.binding.EntraTenantId),
		User:           user.ObjectID,
	})
	if err != nil {
		return uuid.Nil, "", err
	}
	if reason != "" {
		c.log.Info("console caller refused: not a current employee", "tenant", tenant, "reason", reason)
		return uuid.Nil, "", errConsole
	}
	return tenant, "entra:" + user.ObjectID.String(), nil
}

// unverifiedTenant reads the tid claim of a JWT without verifying it.
func unverifiedTenant(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		TenantID string `json:"tid"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return "", false
	}
	id, ok := canonicalID(claims.TenantID)
	if !ok {
		return "", false
	}
	return id.String(), true
}

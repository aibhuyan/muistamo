package entra

// HUMAN REVIEW REQUIRED (AGENTS.md): authentication and authorisation of people at the control
// plane (docs/control-plane-console-plan.md). A person signed in to the console is accepted only
// with a token their own directory issued to the tenant's console app for the tenant's
// control-plane API app, and only while they are a current employee, decided at this moment by
// the delegation's own rule. The tenant comes from the token's directory alone. The signature is
// verified before anything is read for the tenant; a check that cannot be made is "try again".

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	clients  map[string]consoleTenant // by directory
	log      *slog.Logger
}

type consoleTenant struct {
	tenant uuid.UUID
	client *Client
}

// NewConsoleResolver serves the delegator's tenants. A directory bound to more than one tenant is
// ambiguous: its console callers are refused (and logged), and everything else keeps working.
func NewConsoleResolver(d *Delegator) *ConsoleResolver {
	byDirectory := map[string]consoleTenant{}
	ambiguous := map[string]bool{}
	for tenant, c := range d.clients {
		if _, seen := byDirectory[c.Directory()]; seen {
			ambiguous[c.Directory()] = true
		}
		byDirectory[c.Directory()] = consoleTenant{tenant: tenant, client: c}
	}
	for directory := range ambiguous {
		delete(byDirectory, directory)
		d.log.Warn("console callers refused for a directory bound to more than one tenant", "directory", directory)
	}
	return &ConsoleResolver{registry: d.registry, clients: byDirectory, log: d.log}
}

// Resolve implements api.TenantResolver.
func (c *ConsoleResolver) Resolve(r *http.Request) (uuid.UUID, string, error) {
	tenant, actor, _, err := c.ResolveConsole(r)
	return tenant, actor, err
}

// ResolveConsole is Resolve, also naming the console app the token was obtained by.
func (c *ConsoleResolver) ResolveConsole(r *http.Request) (uuid.UUID, string, uuid.UUID, error) {
	requestID := registry.RequestIDFrom(r.Context())
	scheme, raw, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") || raw == "" || strings.Contains(raw, " ") {
		return uuid.Nil, "", uuid.Nil, errConsole
	}
	// The directory, read without verifying, only to choose the tenant's binding; the token is
	// then verified against exactly that binding, before anything is read for the tenant.
	directory, ok := unverifiedTenant(raw)
	if !ok {
		return uuid.Nil, "", uuid.Nil, errConsole
	}
	found, ok := c.clients[directory]
	if !ok {
		return uuid.Nil, "", uuid.Nil, errConsole
	}
	ctx := r.Context()
	token, err := found.client.VerifyConsoleToken(ctx, raw, time.Now())
	if err != nil {
		if !errors.Is(err, ErrUserToken) {
			c.log.Warn("console token could not be checked", "request_id", requestID, "tenant", found.tenant, "err", err)
			return uuid.Nil, "", uuid.Nil, fmt.Errorf("check console token: %w", registry.ErrUnavailable)
		}
		return uuid.Nil, "", uuid.Nil, errConsole
	}
	console, has, err := c.registry.ConsoleClientOf(ctx, found.tenant)
	if err != nil {
		c.log.Error("console client could not be read", "request_id", requestID, "tenant", found.tenant, "err", err)
		return uuid.Nil, "", uuid.Nil, fmt.Errorf("read console client: %w", registry.ErrUnavailable)
	}
	if !has || token.Audience != console.APIApp.String() || token.ClientApp != console.ClientApp {
		c.log.Info("console caller refused: not this tenant's console", "request_id", requestID, "tenant", found.tenant,
			"client_app", token.ClientApp, "person", personDigest(found.tenant, directory, token.User.ObjectID))
		return uuid.Nil, "", uuid.Nil, errConsole
	}
	actor := registry.Actor{Tenant: found.tenant, Name: "console-check:" + found.tenant.String(), RequestID: requestID}
	reason, err := c.registry.PersonCurrent(ctx, actor, registry.DelegationRequest{
		BindingVersion: uuid.MustParse(found.client.binding.BindingVersion),
		EntraTenant:    uuid.MustParse(found.client.binding.EntraTenantId),
		User:           token.User.ObjectID,
	})
	if err != nil {
		c.log.Error("console caller could not be checked", "request_id", requestID, "tenant", found.tenant, "err", err)
		return uuid.Nil, "", uuid.Nil, fmt.Errorf("check console caller: %w", registry.ErrUnavailable)
	}
	if reason != "" {
		c.log.Info("console caller refused: not a current employee", "request_id", requestID, "tenant", found.tenant,
			"client_app", token.ClientApp, "person", personDigest(found.tenant, directory, token.User.ObjectID), "reason", reason)
		return uuid.Nil, "", uuid.Nil, errConsole
	}
	return found.tenant, "entra:" + token.User.ObjectID.String(), token.ClientApp, nil
}

// personDigest names the person in logs without their object id.
func personDigest(tenant uuid.UUID, directory string, user uuid.UUID) string {
	sum := sha256.Sum256([]byte("muistamo/v1 entra-user\n" + tenant.String() + "\n" + directory + "\n" + user.String()))
	return hex.EncodeToString(sum[:])[:16]
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

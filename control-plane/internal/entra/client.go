// Package entra contains the development Entra Agent ID provider client (FR-201).
//
// HUMAN REVIEW REQUIRED (AGENTS.md): credentials, identity ownership and deletion.
// This is a provider primitive, NOT an idempotent lifecycle activity. Before using a mutation,
// the caller must durably reserve the operation and signed intent, enforce the current HR
// generation, and persist the observed result/evidence before activation or reporting success.
// An uncertain create/enable must be reconciled; it must never be blindly retried. The legacy
// simulated Provisioner deliberately does not use this client.
package entra

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

const (
	graphBase          = "https://graph.microsoft.com/v1.0/"
	identityCollection = "servicePrincipals/microsoft.graph.agentIdentity"
	identitySelect     = "id,agentIdentityBlueprintId,servicePrincipalType,tags,accountEnabled"
	readAttempts       = 6
	maxResponse        = 1 << 20
	graphScope         = "https://graph.microsoft.com/.default"
	exchangeScope      = "api://AzureADTokenExchange/.default"
	jwtBearerGrant     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	assertionType      = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

var (
	ErrConfiguration = errors.New("invalid Entra identity binding")
	ErrScope         = errors.New("entra tenant or operation scope refused")
	ErrOwnership     = errors.New("entra identity ownership unverified")
	ErrNotFound      = errors.New("entra identity not found; ownership is unproved")
	ErrState         = errors.New("entra identity state unverified")
	ErrProvider      = errors.New("entra provider request failed")
	ErrUncertain     = errors.New("entra operation requires reconciliation")
)

// Error contains only bounded, sanitized provider metadata. It never wraps a resolver,
// transport or raw provider error, all of which may contain credentials or response content.
type Error struct {
	Operation       string
	Status          int
	Code            string
	RequestID       uuid.UUID
	ServerRequestID uuid.UUID
	Uncertain       bool
	kind            error
}

func (e *Error) Error() string {
	return fmt.Sprintf("Entra %s: status=%d code=%s request=%s uncertain=%t", e.Operation, e.Status, e.Code, e.RequestID, e.Uncertain)
}

func (e *Error) Is(target error) bool {
	return target == e.kind || (target == ErrUncertain && e.Uncertain)
}

// SecretResolver resolves an exact operator reference/version in memory. The first client-secret
// implementation is for local development acceptance; production certificate/FIC setup is separate.
// Resolver errors are intentionally sanitized rather than propagated to logs or workflow history.
type SecretResolver func(context.Context, string, string) (string, error)

// Reference is the recorded provider ID and opaque ORIGINAL CREATE operation. It must come from
// durable tenant/instance ownership state, not an editable instance identityRef or caller input.
type Reference struct {
	ID         uuid.UUID
	CreationID uuid.UUID
}

// Identity is an observed provider state, not an authorization or evidence receipt. On a create
// error, Ref.ID may be an UNVERIFIED candidate for reconciliation. Never bind it on that error.
type Identity struct {
	Ref     Reference
	Enabled bool
}

// Client pins one immutable tenant, blueprint, binding version and credential version. Its token
// cache is private to that binding; a new configuration/credential version needs a new client.
type Client struct {
	binding muistamov1.EntraIdentityBinding
	resolve SecretResolver
	http    *http.Client
	pause   func(context.Context) error
	mu      sync.Mutex
	token   string
	expiry  time.Time
	// The directory's signing keys, for user tokens (usertoken.go).
	keysMu      sync.Mutex
	keys        map[string]*rsa.PublicKey
	keysFetched time.Time
	keysTried   time.Time
	// Exchange caches (delegation.go): T1 per agent identity, delegated tokens per agent and user
	// token digest.
	cacheMu    sync.Mutex
	assertions map[uuid.UUID]cachedToken
	delegated  map[delegatedKey]cachedToken
}

// String and GoString keep tokens out of ordinary diagnostic formatting.
func (*Client) String() string   { return "EntraClient(redacted)" }
func (*Client) GoString() string { return "EntraClient(redacted)" }

// ParseBinding validates operator JSON before decoding the generated contract. There is no public
// administration endpoint and no inline secret, endpoint override or credential-file lookup.
func ParseBinding(raw []byte) (muistamov1.EntraIdentityBinding, error) {
	var binding muistamov1.EntraIdentityBinding
	if len(raw) > 65536 || contracts.ValidateAgainst("entraidentitybinding.json", raw) != nil {
		return binding, ErrConfiguration
	}
	if err := json.Unmarshal(raw, &binding); err != nil {
		return binding, ErrConfiguration
	}
	if err := validateBinding(binding); err != nil {
		return muistamov1.EntraIdentityBinding{}, err
	}
	return binding, nil
}

func validateBinding(b muistamov1.EntraIdentityBinding) error {
	ids := []string{b.TenantId, b.BindingVersion, b.EntraTenantId, b.BlueprintAppId, b.BlueprintObjectId, b.BlueprintPrincipalId}
	ids = append(ids, b.SponsorUserIds...)
	for _, id := range ids {
		if _, ok := canonicalID(id); !ok {
			return ErrConfiguration
		}
	}
	return nil
}

// New constructs a client without making HTTP requests or resolving a credential. Authority and
// Graph hosts are fixed to the approved global-cloud development setup; redirects are refused.
func New(binding muistamov1.EntraIdentityBinding, resolve SecretResolver) (*Client, error) {
	raw, err := json.Marshal(binding)
	if err != nil || resolve == nil {
		return nil, ErrConfiguration
	}
	checked, err := ParseBinding(raw)
	if err != nil {
		return nil, err
	}
	return &Client{
		binding: checked, resolve: resolve,
		http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		pause: func(ctx context.Context) error {
			timer := time.NewTimer(time.Second)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		},
	}, nil
}

func canonicalID(s string) (uuid.UUID, bool) {
	id, err := uuid.Parse(s)
	return id, err == nil && id != uuid.Nil && id.String() == s
}

func (c *Client) scope(ctx context.Context, tenant uuid.UUID, ids ...uuid.UUID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tenant.String() != c.binding.TenantId {
		return ErrScope
	}
	for _, id := range ids {
		if id == uuid.Nil {
			return ErrScope
		}
	}
	return nil
}

func marker(tenant, creation uuid.UUID) string {
	return "muistamo:" + tenant.String() + ":" + creation.String()
}
func identityPath(ref Reference) string {
	return "servicePrincipals/" + ref.ID.String() + "/microsoft.graph.agentIdentity"
}

type graphIdentity struct {
	ID        string   `json:"id"`
	Blueprint string   `json:"agentIdentityBlueprintId"`
	Type      string   `json:"servicePrincipalType"`
	Tags      []string `json:"tags"`
	Enabled   *bool    `json:"accountEnabled"`
}

func (c *Client) owned(data graphIdentity, ref Reference) (Identity, error) {
	if data.ID != ref.ID.String() || data.Blueprint != c.binding.BlueprintAppId || data.Type != "ServiceIdentity" || !slices.Contains(data.Tags, marker(uuid.MustParse(c.binding.TenantId), ref.CreationID)) {
		return Identity{}, ErrOwnership
	}
	if data.Enabled == nil {
		return Identity{}, ErrState
	}
	return Identity{Ref: ref, Enabled: *data.Enabled}, nil
}

// CreateDisabled performs ONE POST, then bounded read-only ownership/state verification. A known
// 201 followed by read failure still returns its candidate ID with ErrUncertain. No cleanup mutation
// occurs here: cleanup also needs its own durable intent and HR/operation authorization.
func (c *Client) CreateDisabled(ctx context.Context, tenant, creation uuid.UUID) (Identity, error) {
	if err := c.scope(ctx, tenant, creation); err != nil {
		return Identity{}, err
	}
	sponsors := make([]string, len(c.binding.SponsorUserIds))
	for i, sponsor := range c.binding.SponsorUserIds {
		sponsors[i] = graphBase + "users/" + sponsor
	}
	body, err := json.Marshal(map[string]any{
		"@odata.type": "#microsoft.graph.agentIdentity", "displayName": "muistamo-" + creation.String(),
		"agentIdentityBlueprintId": c.binding.BlueprintAppId, "accountEnabled": false,
		"tags": []string{marker(tenant, creation)}, "sponsors@odata.bind": sponsors,
	})
	if err != nil {
		return Identity{}, &Error{Operation: "create", Code: "invalid_request", kind: ErrProvider}
	}
	reply, err := c.graph(ctx, "create", http.MethodPost, identityCollection, body, creation)
	if err != nil {
		return Identity{}, err
	}
	if reply.status != http.StatusCreated {
		return Identity{}, reply.failure("create", true, creation)
	}
	// Extract a valid ID independently, so a different malformed field cannot discard the
	// candidate needed for reconciliation. It remains unverified whenever an error is returned.
	var envelope struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(reply.body, &envelope); err != nil {
		return Identity{}, &Error{Operation: "create", Code: "invalid_response", Status: reply.status, RequestID: creation, Uncertain: true, kind: ErrProvider}
	}
	id, valid := canonicalID(envelope.ID)
	if !valid {
		return Identity{}, &Error{Operation: "create", Code: "invalid_identity_id", Status: reply.status, RequestID: creation, Uncertain: true, kind: ErrOwnership}
	}
	candidate := Identity{Ref: Reference{ID: id, CreationID: creation}}
	var data graphIdentity
	if err := json.Unmarshal(reply.body, &data); err != nil {
		return candidate, &Error{Operation: "create", Code: "invalid_response", Status: reply.status, RequestID: creation, ServerRequestID: reply.serverID, Uncertain: true, kind: ErrProvider}
	}
	if data.Blueprint != c.binding.BlueprintAppId || data.Type != "ServiceIdentity" {
		return candidate, &Error{Operation: "create", Code: "creation_ownership_unverified", Status: reply.status, RequestID: creation, Uncertain: true, kind: ErrOwnership}
	}
	verified, err := c.pollState(ctx, tenant, candidate.Ref, false, true)
	if err != nil {
		return candidate, uncertain("create", creation, err)
	}
	return verified, nil
}

// Inspect refuses missing/mismatched ownership or missing boolean accountEnabled. A 404 never
// proves ownership or a prior delete. It is not automatically converted into success.
func (c *Client) Inspect(ctx context.Context, tenant uuid.UUID, ref Reference) (Identity, error) {
	if err := c.scope(ctx, tenant, ref.ID, ref.CreationID); err != nil {
		return Identity{}, err
	}
	id := uuid.New()
	reply, err := c.graph(ctx, "inspect", http.MethodGet, identityPath(ref)+"?"+url.Values{"$select": {identitySelect}}.Encode(), nil, id)
	if err != nil {
		return Identity{}, err
	}
	if reply.status != http.StatusOK {
		return Identity{}, reply.failure("inspect", false, id)
	}
	var data graphIdentity
	if err := json.Unmarshal(reply.body, &data); err != nil {
		return Identity{}, &Error{Operation: "inspect", Code: "invalid_response", Status: reply.status, RequestID: id, kind: ErrProvider}
	}
	return c.owned(data, ref)
}

func (c *Client) pollState(ctx context.Context, tenant uuid.UUID, ref Reference, enabled, allowMissing bool) (Identity, error) {
	for attempt := 0; attempt < readAttempts; attempt++ {
		observed, err := c.Inspect(ctx, tenant, ref)
		if err == nil && observed.Enabled == enabled {
			return observed, nil
		}
		if err != nil && (!allowMissing || !errors.Is(err, ErrNotFound)) {
			return Identity{}, err
		}
		if attempt+1 == readAttempts {
			if err != nil {
				return Identity{}, err
			}
			return Identity{}, ErrState
		}
		if err := c.pause(ctx); err != nil {
			return Identity{}, err
		}
	}
	return Identity{}, ErrState
}

// SetEnabled verifies current ownership, performs at most one PATCH, then verifies the boolean
// state. A failed/ambiguous PATCH is never retried or followed by another mutation. Account
// disablement does not prove immediate invalidation of previously issued tokens.
func (c *Client) SetEnabled(ctx context.Context, tenant uuid.UUID, ref Reference, enabled bool, requestID uuid.UUID) (Identity, error) {
	if err := c.scope(ctx, tenant, ref.ID, ref.CreationID, requestID); err != nil {
		return Identity{}, err
	}
	if _, err := c.Inspect(ctx, tenant, ref); err != nil {
		return Identity{}, err
	}
	body, err := json.Marshal(map[string]bool{"accountEnabled": enabled})
	if err != nil {
		return Identity{}, &Error{Operation: "set_enabled", Code: "invalid_request", kind: ErrProvider}
	}
	reply, err := c.graph(ctx, "set_enabled", http.MethodPatch, identityPath(ref), body, requestID)
	if err != nil {
		return Identity{}, err
	}
	if reply.status != http.StatusNoContent {
		return Identity{}, reply.failure("set_enabled", true, requestID)
	}
	observed, err := c.pollState(ctx, tenant, ref, enabled, false)
	if err != nil {
		return Identity{}, uncertain("set_enabled", requestID, err)
	}
	return observed, nil
}

// Delete requires a currently owned disabled identity, one DELETE 204 acknowledgement and a
// subsequent 404. Provider deletion is recoverable (soft deletion), not permanent erasure.
func (c *Client) Delete(ctx context.Context, tenant uuid.UUID, ref Reference, requestID uuid.UUID) error {
	if err := c.scope(ctx, tenant, ref.ID, ref.CreationID, requestID); err != nil {
		return err
	}
	observed, err := c.Inspect(ctx, tenant, ref)
	if err != nil {
		return err
	}
	if observed.Enabled {
		return ErrState
	}
	reply, err := c.graph(ctx, "delete", http.MethodDelete, identityPath(ref), nil, requestID)
	if err != nil {
		return err
	}
	if reply.status != http.StatusNoContent {
		return reply.failure("delete", true, requestID)
	}
	for attempt := 0; attempt < readAttempts; attempt++ {
		_, err := c.Inspect(ctx, tenant, ref)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return uncertain("delete", requestID, err)
		}
		if attempt+1 < readAttempts {
			if err := c.pause(ctx); err != nil {
				return uncertain("delete", requestID, err)
			}
		}
	}
	return uncertain("delete", requestID, ErrState)
}

// FindCreated can reconcile a KNOWN original create intent when one complete, scoped result is
// found and direct ownership is verified. No/partial/multiple matches are inconclusive, never
// permission to create again. Provider discovery may be unavailable under the current grant.
// Arbitrary nextLink URLs are never followed, even if one matching row was already returned.
func (c *Client) FindCreated(ctx context.Context, tenant, creation uuid.UUID) (Identity, error) {
	if err := c.scope(ctx, tenant, creation); err != nil {
		return Identity{}, err
	}
	query := url.Values{"$filter": {"agentIdentityBlueprintId eq '" + c.binding.BlueprintAppId + "' and tags/any(t:t eq '" + marker(tenant, creation) + "')"}, "$select": {identitySelect}, "$count": {"true"}, "$top": {"2"}}
	id := uuid.New()
	reply, err := c.graph(ctx, "discovery", http.MethodGet, identityCollection+"?"+query.Encode(), nil, id)
	if err != nil {
		return Identity{}, err
	}
	if reply.status != http.StatusOK {
		return Identity{}, reply.failure("discovery", false, id)
	}
	var page struct {
		Value []graphIdentity `json:"value"`
		Next  json.RawMessage `json:"@odata.nextLink"`
		Count json.RawMessage `json:"@odata.count"`
	}
	if err := json.Unmarshal(reply.body, &page); err != nil || len(page.Value) != 1 || len(page.Next) != 0 {
		return Identity{}, &Error{Operation: "discovery", Code: "discovery_inconclusive", RequestID: id, Uncertain: true, kind: ErrOwnership}
	}
	var count int
	if len(page.Count) != 0 && (json.Unmarshal(page.Count, &count) != nil || count != 1) {
		return Identity{}, &Error{Operation: "discovery", Code: "discovery_inconclusive", RequestID: id, Uncertain: true, kind: ErrOwnership}
	}
	providerID, valid := canonicalID(page.Value[0].ID)
	if !valid {
		return Identity{}, ErrOwnership
	}
	ref := Reference{ID: providerID, CreationID: creation}
	if _, err := c.owned(page.Value[0], ref); err != nil {
		return Identity{}, err
	}
	return c.Inspect(ctx, tenant, ref)
}

func uncertain(operation string, requestID uuid.UUID, err error) error {
	var provider *Error
	if errors.As(err, &provider) {
		copy := *provider
		copy.Uncertain = true
		copy.Operation = operation
		// Keep the failed verification request paired with its own provider request ID.
		// The original mutation ID is already known to the caller's durable operation.
		return &copy
	}
	return &Error{Operation: operation, Code: "state_unverified", RequestID: requestID, Uncertain: true, kind: err}
}

type providerReply struct {
	status   int
	body     []byte
	serverID uuid.UUID
}

func (r providerReply) failure(operation string, mutation bool, requestID uuid.UUID) error {
	code := "request_failed"
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(r.body, &payload) == nil {
		switch payload.Error.Code {
		case "Authorization_RequestDenied", "InvalidAuthenticationToken", "Request_ResourceNotFound", "TooManyRequests", "ServiceUnavailable", "BadRequest":
			code = payload.Error.Code
		}
	}
	kind := ErrProvider
	if r.status == 404 {
		kind = ErrNotFound
	}
	definite := r.status == 400 || r.status == 401 || r.status == 403 || r.status == 404 || r.status == 405 || r.status == 409 || r.status == 412 || r.status == 415 || r.status == 422 || r.status == 429
	return &Error{Operation: operation, Status: r.status, Code: code, RequestID: requestID, ServerRequestID: r.serverID, Uncertain: mutation && !definite, kind: kind}
}

func (c *Client) graph(ctx context.Context, operation, method, path string, body []byte, requestID uuid.UUID) (providerReply, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return providerReply{}, err
	}
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Content-Type", "application/json")
	headers.Set("OData-Version", "4.0")
	headers.Set("client-request-id", requestID.String())
	headers.Set("return-client-request-id", "true")
	if operation == "discovery" || operation == "user-lookup" {
		headers.Set("ConsistencyLevel", "eventual")
	}
	return c.send(ctx, operation, method, graphBase+path, headers, body, requestID, method != http.MethodGet)
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Add(time.Minute).Before(c.expiry) {
		return c.token, nil
	}
	c.token = ""
	c.expiry = time.Time{}
	secret, err := c.resolve(ctx, c.binding.CredentialRef, c.binding.CredentialVersion)
	if err != nil || secret == "" {
		return "", &Error{Operation: "authenticate", Code: "credential_unavailable", kind: ErrProvider}
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.binding.BlueprintAppId}, "scope": {graphScope}, "client_secret": {secret}}
	token, expiry, err := c.requestToken(ctx, "authenticate", form)
	if err != nil {
		return "", err
	}
	c.token, c.expiry = token, expiry
	return c.token, nil
}

// requestToken posts one allowed form to the tenant's token endpoint and returns a well-formed
// bearer token and when it expires. Only the provider's OAuth error code, from a fixed list,
// leaves this function; the response body never does.
func (c *Client) requestToken(ctx context.Context, operation string, form url.Values) (string, time.Time, error) {
	id := uuid.New()
	if !c.allowedTokenForm(form) {
		return "", time.Time{}, &Error{Operation: operation, Code: "destination_refused", RequestID: id, kind: ErrProvider}
	}
	started := time.Now()
	reply, err := c.send(ctx, operation, http.MethodPost, "https://login.microsoftonline.com/"+c.binding.EntraTenantId+"/oauth2/v2.0/token", http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, []byte(form.Encode()), id, false)
	if err != nil {
		return "", time.Time{}, err
	}
	var payload struct {
		Token   string `json:"access_token"`
		Type    string `json:"token_type"`
		Seconds int    `json:"expires_in"`
		Error   string `json:"error"`
	}
	if reply.status != 200 || json.Unmarshal(reply.body, &payload) != nil || payload.Token == "" || len(payload.Token) > 16384 || strings.IndexFunc(payload.Token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 || !strings.EqualFold(payload.Type, "Bearer") || payload.Seconds <= 60 || payload.Seconds > 86400 {
		code := "authentication_failed"
		if slices.Contains(oauthErrors, payload.Error) {
			code = payload.Error
		}
		return "", time.Time{}, &Error{Operation: operation, Status: reply.status, Code: code, RequestID: id, ServerRequestID: reply.serverID, kind: ErrProvider}
	}
	return payload.Token, started.Add(time.Duration(payload.Seconds) * time.Second), nil
}

// oauthErrors are the token endpoint's error codes worth recording (RFC 6749 section 5.2 and
// Entra's consent and interaction errors).
var oauthErrors = []string{"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "consent_required", "interaction_required", "temporarily_unavailable"}

// allowedTokenForm admits exactly three requests to the token endpoint: the blueprint's own Graph
// token, the blueprint's exchange assertion for one agent identity (T1), and that agent identity's
// on-behalf-of exchange of a user token. Every parameter is named and has one value.
func (c *Client) allowedTokenForm(form url.Values) bool {
	for _, values := range form {
		if len(values) != 1 || values[0] == "" {
			return false
		}
	}
	switch form.Get("grant_type") {
	case "client_credentials":
		if form.Get("client_id") != c.binding.BlueprintAppId || form.Get("client_secret") == "" {
			return false
		}
		switch form.Get("scope") {
		case graphScope:
			return len(form) == 4
		case exchangeScope:
			_, agent := canonicalID(form.Get("fmi_path"))
			return agent && len(form) == 5
		}
	case jwtBearerGrant:
		_, agent := canonicalID(form.Get("client_id"))
		return agent && len(form) == 7 && form.Get("scope") == graphScope && form.Get("requested_token_use") == "on_behalf_of" &&
			form.Get("client_assertion_type") == assertionType && form.Get("client_assertion") != "" && form.Get("assertion") != ""
	}
	return false
}

func (c *Client) send(ctx context.Context, operation, method, target string, headers http.Header, body []byte, requestID uuid.UUID, mutation bool) (providerReply, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return providerReply{}, &Error{Operation: operation, Code: "invalid_request", kind: ErrProvider}
	}
	if !c.allowedDestination(req) {
		return providerReply{}, &Error{Operation: operation, Code: "destination_refused", RequestID: requestID, kind: ErrProvider}
	}
	// No body replay for identity writes. In particular, no idempotency-key header is sent.
	req.GetBody = nil
	req.Header = headers
	res, err := c.http.Do(req)
	if err != nil {
		kind := ErrProvider
		if ctx.Err() != nil {
			kind = ctx.Err()
		}
		return providerReply{}, &Error{Operation: operation, Code: "transport_failed", RequestID: requestID, Uncertain: mutation, kind: kind}
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return providerReply{}, &Error{Operation: operation, Status: res.StatusCode, Code: "invalid_response", RequestID: requestID, Uncertain: mutation, kind: ErrProvider}
	}
	serverID, _ := canonicalID(res.Header.Get("request-id"))
	return providerReply{status: res.StatusCode, body: raw, serverID: serverID}, nil
}

func (c *Client) allowedDestination(req *http.Request) bool {
	u := req.URL
	if u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.EscapedPath() != u.Path {
		return false
	}
	if u.Host == "login.microsoftonline.com" {
		if u.RawQuery != "" || u.ForceQuery {
			return false
		}
		return (req.Method == http.MethodPost && u.Path == "/"+c.binding.EntraTenantId+"/oauth2/v2.0/token") ||
			(req.Method == http.MethodGet && u.Path == "/"+c.binding.EntraTenantId+"/discovery/v2.0/keys")
	}
	if u.Host != "graph.microsoft.com" || !strings.HasPrefix(u.Path, "/v1.0/") {
		return false
	}
	path := strings.TrimPrefix(u.Path, "/v1.0/")
	if req.Method != http.MethodGet && (u.RawQuery != "" || u.ForceQuery) {
		return false
	}
	if path == identityCollection {
		return req.Method == http.MethodGet || req.Method == http.MethodPost
	}
	if path == usersCollection {
		// Only the employeeId lookup: a read with exactly its parameters.
		q := u.Query()
		for _, key := range []string{"$filter", "$select", "$count", "$top"} {
			if len(q[key]) != 1 {
				return false
			}
		}
		filter, prefixed := strings.CutPrefix(q.Get("$filter"), "employeeId eq '")
		id, quoted := strings.CutSuffix(filter, "'")
		return req.Method == http.MethodGet && len(q) == 4 && q.Get("$select") == "id,employeeId" &&
			q.Get("$count") == "true" && q.Get("$top") == "2" && prefixed && quoted && employeeIDPattern.MatchString(id)
	}
	if !strings.HasPrefix(path, "servicePrincipals/") {
		return false
	}
	id, typed := strings.CutSuffix(strings.TrimPrefix(path, "servicePrincipals/"), "/microsoft.graph.agentIdentity")
	if _, valid := canonicalID(id); !typed || !valid {
		return false
	}
	return req.Method == http.MethodGet || req.Method == http.MethodPatch || req.Method == http.MethodDelete
}

package entra

// HUMAN REVIEW REQUIRED (AGENTS.md): token validation. A user token is accepted only when the
// directory signed it for Muistamo's blueprint, for a person (never an app), with the
// Knowledge.Read scope, and it is current. Its user is then only a candidate: the registry
// decides whether that user is a linked person with an active agent.

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

const (
	// KnowledgeScope is the delegated scope a person's token must carry.
	KnowledgeScope = "Knowledge.Read"
	tokenLeeway    = 60 * time.Second
	// The directory's keys are fetched again after keysMaxAge, or for an unknown key id, but
	// never more often than keysMinRefresh, so unknown key ids cannot drive a fetch per request.
	keysMaxAge     = 24 * time.Hour
	keysMinRefresh = 30 * time.Second
	keysFetchLimit = 5 * time.Second
	maxUserToken   = 16384
)

// ErrUserToken is every user-token validation failure. The reason is not exposed.
var ErrUserToken = errors.New("user token is not valid for Muistamo")

// UserClaims is what a valid user token establishes.
type UserClaims struct {
	ObjectID uuid.UUID
	Expiry   time.Time
}

type userTokenClaims struct {
	TenantID  string `json:"tid"`
	ObjectID  string `json:"oid"`
	Version   string `json:"ver"`
	Scope     string `json:"scp"`
	TokenType string `json:"idtyp"`
}

// ValidateUserToken checks a person's Entra access token for Muistamo at now: RS256 under one of
// the binding directory's current signing keys; issuer, tenant and audience of this binding;
// version 2.0; current within a minute's skew; the Knowledge.Read scope; a user object id; and
// not an app-only token.
func (c *Client) ValidateUserToken(ctx context.Context, raw string, now time.Time) (UserClaims, error) {
	t, err := c.personToken(ctx, raw, now)
	if err != nil {
		return UserClaims{}, err
	}
	// Delegated scopes are space separated; an app-only token has none.
	if t.audience != c.binding.BlueprintAppId || !containsWord(t.scope, KnowledgeScope) {
		return UserClaims{}, ErrUserToken
	}
	return t.user, nil
}

// personToken holds what every person's token for Muistamo establishes, before the checks that
// depend on who it is for (the blueprint, or the control plane's own API app).
type personToken struct {
	user     UserClaims
	audience string // exactly one
	scope    string
	azp      string
}

// personToken checks what every person's token must be: RS256 under one of the binding
// directory's current signing keys; that directory's issuer and tenant; version 2.0; current
// within a minute's skew, with expiry and not-before present; exactly one audience; a user object
// id; not an app-only token. A failure to fetch the keys is returned as is (not ErrUserToken).
func (c *Client) personToken(ctx context.Context, raw string, now time.Time) (personToken, error) {
	if len(raw) == 0 || len(raw) > maxUserToken {
		return personToken{}, ErrUserToken
	}
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(token.Headers) != 1 || token.Headers[0].KeyID == "" {
		return personToken{}, ErrUserToken
	}
	key, err := c.signingKey(ctx, token.Headers[0].KeyID, now)
	if err != nil {
		return personToken{}, err
	}
	var std jwt.Claims
	var claims consoleTokenClaims
	if err := token.Claims(key, &std, &claims); err != nil {
		return personToken{}, ErrUserToken
	}
	if std.Expiry == nil || std.NotBefore == nil || len(std.Audience) != 1 {
		return personToken{}, ErrUserToken
	}
	expected := jwt.Expected{Issuer: "https://login.microsoftonline.com/" + c.binding.EntraTenantId + "/v2.0", Time: now}
	if std.ValidateWithLeeway(expected, tokenLeeway) != nil {
		return personToken{}, ErrUserToken
	}
	user, valid := canonicalID(claims.ObjectID)
	if !valid || claims.TenantID != c.binding.EntraTenantId || claims.Version != "2.0" || claims.TokenType == "app" {
		return personToken{}, ErrUserToken
	}
	return personToken{
		user:     UserClaims{ObjectID: user, Expiry: std.Expiry.Time()},
		audience: std.Audience[0],
		scope:    claims.Scope,
		azp:      claims.AuthorizedParty,
	}, nil
}

// ConsoleScope is the delegated scope a console token for the control plane must carry.
const ConsoleScope = "Registry.Console"

type consoleTokenClaims struct {
	userTokenClaims
	AuthorizedParty string `json:"azp"`
}

// ConsoleToken is a person's token from the console, verified (signature, directory, current),
// with the audience and client app still to be matched against the tenant's console client.
type ConsoleToken struct {
	User      UserClaims
	Audience  string
	ClientApp uuid.UUID
}

// VerifyConsoleToken verifies a console token for the control plane at now, before anything is
// read for the tenant: the person-token rules, the Registry.Console scope, and a client app (azp).
// The caller then requires Audience = the tenant's control-plane API app (never the blueprint)
// and ClientApp = the tenant's console app.
func (c *Client) VerifyConsoleToken(ctx context.Context, raw string, now time.Time) (ConsoleToken, error) {
	t, err := c.personToken(ctx, raw, now)
	if err != nil {
		return ConsoleToken{}, err
	}
	azp, ok := canonicalID(t.azp)
	if !ok || !containsWord(t.scope, ConsoleScope) || t.audience == c.binding.BlueprintAppId {
		return ConsoleToken{}, ErrUserToken
	}
	return ConsoleToken{User: t.user, Audience: t.audience, ClientApp: azp}, nil
}

// ValidateConsoleToken is VerifyConsoleToken plus the tenant's own apps.
func (c *Client) ValidateConsoleToken(ctx context.Context, raw string, now time.Time, apiApp, clientApp uuid.UUID) (UserClaims, error) {
	t, err := c.VerifyConsoleToken(ctx, raw, now)
	if err != nil {
		return UserClaims{}, err
	}
	if t.Audience != apiApp.String() || t.ClientApp != clientApp {
		return UserClaims{}, ErrUserToken
	}
	return t.User, nil
}

// Directory is the Entra directory this client's binding is for.
func (c *Client) Directory() string { return c.binding.EntraTenantId }

func containsWord(list, word string) bool {
	for _, item := range strings.Fields(list) {
		if item == word {
			return true
		}
	}
	return false
}

// signingKey returns the directory's RSA signing key with id kid, fetching the key set when the
// cache is old or lacks kid, at most once per keysMinRefresh.
func (c *Client) signingKey(ctx context.Context, kid string, now time.Time) (*rsa.PublicKey, error) {
	c.keysMu.Lock()
	defer c.keysMu.Unlock()
	key, known := c.keys[kid]
	fresh := now.Sub(c.keysFetched) < keysMaxAge
	if known && fresh {
		return key, nil
	}
	if now.Sub(c.keysTried) < keysMinRefresh {
		if known {
			return key, nil
		}
		return nil, ErrUserToken
	}
	c.keysTried = now
	// Validations wait for this fetch, so it is bounded more tightly than other provider calls.
	fetch, cancel := context.WithTimeout(ctx, keysFetchLimit)
	defer cancel()
	keys, err := c.fetchSigningKeys(fetch)
	if err != nil {
		// A stale set is kept for keys it has; an outage never admits an unknown key.
		if known {
			return key, nil
		}
		return nil, err
	}
	c.keys, c.keysFetched = keys, now
	if key, known = keys[kid]; !known {
		return nil, ErrUserToken
	}
	return key, nil
}

// fetchSigningKeys reads the directory's published keys. Only RSA keys of at least 2048 bits
// meant for signatures are kept; anything else in the set is ignored rather than trusted.
func (c *Client) fetchSigningKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	id := uuid.New()
	reply, err := c.send(ctx, "signing-keys", http.MethodGet, "https://login.microsoftonline.com/"+c.binding.EntraTenantId+"/discovery/v2.0/keys", http.Header{}, nil, id, false)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if reply.status != http.StatusOK || json.Unmarshal(reply.body, &set) != nil {
		return nil, &Error{Operation: "signing-keys", Status: reply.status, Code: "invalid_response", RequestID: id, ServerRequestID: reply.serverID, kind: ErrProvider}
	}
	keys := map[string]*rsa.PublicKey{}
	for _, raw := range set.Keys {
		var jwk jose.JSONWebKey
		if json.Unmarshal(raw, &jwk) != nil || jwk.KeyID == "" || !jwk.Valid() || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Algorithm != "" && jwk.Algorithm != string(jose.RS256)) {
			continue
		}
		key, ok := jwk.Key.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 {
			continue
		}
		if _, dup := keys[jwk.KeyID]; dup {
			// Two keys under one id: trust neither.
			keys[jwk.KeyID] = nil
			continue
		}
		keys[jwk.KeyID] = key
	}
	for kid, key := range keys {
		if key == nil {
			delete(keys, kid)
		}
	}
	return keys, nil
}

package entra

// HUMAN REVIEW REQUIRED (AGENTS.md): token handling. The agent identity exchanges the person's
// token for a Graph token naming both (Entra Agent ID on-behalf-of, docs/obo-retrieval-plan.md):
// the blueprint first obtains an exchange assertion for that one agent identity (T1), then the
// agent identity presents T1 and the person's token. The registry decides, under its locks and
// for every request, whether the exchange may happen at all; the caches here only avoid asking
// Entra again for a token it already issued.

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// graphAppID is Microsoft Graph's application id, the audience of its v1.0 access tokens.
const graphAppID = "00000003-0000-0000-c000-000000000000"

// maxCachedTokens bounds each exchange cache; a full cache drops its expired entries, then all.
const maxCachedTokens = 4096

type cachedToken struct {
	token  string
	expiry time.Time
}

type delegatedKey struct {
	agent uuid.UUID
	user  [sha256.Size]byte
}

func usable(t cachedToken, now time.Time) bool {
	return t.token != "" && now.Add(time.Minute).Before(t.expiry)
}

func remember[K comparable](cache map[K]cachedToken, key K, value cachedToken, now time.Time) map[K]cachedToken {
	if cache == nil {
		cache = map[K]cachedToken{}
	}
	if len(cache) >= maxCachedTokens {
		for k, v := range cache {
			if !usable(v, now) {
				delete(cache, k)
			}
		}
		if len(cache) >= maxCachedTokens {
			cache = map[K]cachedToken{}
		}
	}
	cache[key] = value
	return cache
}

// OnBehalfOf returns a Graph token for agent acting for the person whose validated token is
// userToken. The answer must name the same user and this agent identity, in this directory, or
// it is refused. It expires no later than the person's own token.
func (c *Client) OnBehalfOf(ctx context.Context, tenant, agent uuid.UUID, userToken string, user UserClaims) (string, time.Time, error) {
	if err := c.scope(ctx, tenant, agent, user.ObjectID); err != nil {
		return "", time.Time{}, err
	}
	key := delegatedKey{agent: agent, user: sha256.Sum256([]byte(userToken))}
	c.cacheMu.Lock()
	cached, hit := c.delegated[key]
	c.cacheMu.Unlock()
	if hit && usable(cached, time.Now()) {
		return cached.token, cached.expiry, nil
	}
	assertion, err := c.agentAssertion(ctx, agent)
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{
		"grant_type": {jwtBearerGrant}, "client_id": {agent.String()},
		"client_assertion_type": {assertionType}, "client_assertion": {assertion},
		"assertion": {userToken}, "requested_token_use": {"on_behalf_of"}, "scope": {graphScope},
	}
	token, expiry, err := c.requestToken(ctx, "on-behalf-of", form)
	if err != nil {
		return "", time.Time{}, err
	}
	if !c.namesAgentAndUser(token, agent, user.ObjectID) {
		return "", time.Time{}, &Error{Operation: "on-behalf-of", Code: "token_mismatch", kind: ErrProvider}
	}
	if user.Expiry.Before(expiry) {
		expiry = user.Expiry
	}
	now := time.Now()
	if !now.Before(expiry) {
		return "", time.Time{}, &Error{Operation: "on-behalf-of", Code: "token_expired", kind: ErrProvider}
	}
	c.cacheMu.Lock()
	c.delegated = remember(c.delegated, key, cachedToken{token: token, expiry: expiry}, now)
	c.cacheMu.Unlock()
	return token, expiry, nil
}

// namesAgentAndUser reads the delegated token's claims. Muistamo is not its audience and cannot
// verify its signature; it reads the claims only to refuse an answer for another user, agent or
// directory, which would mean the exchange did not do what was asked.
func (c *Client) namesAgentAndUser(token string, agent, user uuid.UUID) bool {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return false
	}
	var claims struct {
		Audience jwt.Audience `json:"aud"`
		ObjectID string       `json:"oid"`
		TenantID string       `json:"tid"`
		Azp      string       `json:"azp"`
		AppID    string       `json:"appid"`
	}
	if parsed.UnsafeClaimsWithoutVerification(&claims) != nil {
		return false
	}
	// A token for Microsoft Graph, by its URI or its application id.
	if len(claims.Audience) != 1 || (claims.Audience[0] != registry.GraphResource && claims.Audience[0] != graphAppID) {
		return false
	}
	// v2.0 tokens name the client in azp, v1.0 tokens (Graph's) in appid. Each one present must be
	// the agent identity, and at least one must be.
	if claims.Azp == "" && claims.AppID == "" {
		return false
	}
	for _, client := range []string{claims.Azp, claims.AppID} {
		if client != "" && client != agent.String() {
			return false
		}
	}
	return claims.ObjectID == user.String() && claims.TenantID == c.binding.EntraTenantId
}

// agentAssertion returns the blueprint's exchange assertion (T1) for one agent identity.
func (c *Client) agentAssertion(ctx context.Context, agent uuid.UUID) (string, error) {
	c.cacheMu.Lock()
	cached, hit := c.assertions[agent]
	c.cacheMu.Unlock()
	if hit && usable(cached, time.Now()) {
		return cached.token, nil
	}
	secret, err := c.resolve(ctx, c.binding.CredentialRef, c.binding.CredentialVersion)
	if err != nil || secret == "" {
		return "", &Error{Operation: "agent-assertion", Code: "credential_unavailable", kind: ErrProvider}
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.binding.BlueprintAppId}, "scope": {exchangeScope}, "fmi_path": {agent.String()}, "client_secret": {secret}}
	token, expiry, err := c.requestToken(ctx, "agent-assertion", form)
	if err != nil {
		return "", err
	}
	c.cacheMu.Lock()
	c.assertions = remember(c.assertions, agent, cachedToken{token: token, expiry: expiry}, time.Now())
	c.cacheMu.Unlock()
	return token, nil
}

// Delegator answers the knowledge service's delegation requests for the tenants it has a binding
// for: it validates the person's token with that tenant's binding, then lets the registry decide
// and, under the registry's locks, performs the exchange.
type Delegator struct {
	registry *registry.Service
	clients  map[uuid.UUID]*Client
	log      *slog.Logger
}

// NewDelegator serves one binding per tenant: the tenant's enrolled one (checked by the caller).
func NewDelegator(svc *registry.Service, log *slog.Logger, clients ...*Client) (*Delegator, error) {
	d := &Delegator{registry: svc, clients: map[uuid.UUID]*Client{}, log: log}
	for _, client := range clients {
		tenant, err := uuid.Parse(client.binding.TenantId)
		if err != nil || d.clients[tenant] != nil {
			return nil, ErrConfiguration
		}
		d.clients[tenant] = client
	}
	return d, nil
}

// Delegate implements api.Delegator.
func (d *Delegator) Delegate(ctx context.Context, actor registry.Actor, req muistamov1.KnowledgeDelegationRequest) (muistamov1.KnowledgeDelegation, error) {
	client := d.clients[actor.Tenant]
	if client == nil {
		return muistamov1.KnowledgeDelegation{}, registry.ErrDelegationNotConfigured
	}
	user, err := client.ValidateUserToken(ctx, req.UserToken, time.Now())
	if err != nil {
		if !errors.Is(err, ErrUserToken) {
			d.log.Warn("user token could not be validated", "request_id", actor.RequestID, "tenant", actor.Tenant, "err", err)
		}
		return muistamov1.KnowledgeDelegation{}, d.registry.RefuseDelegation(ctx, actor, muistamov1.KnowledgeDelegationRefusalReasonTokenInvalid)
	}
	entraTenant := uuid.MustParse(client.binding.EntraTenantId)
	version := uuid.MustParse(client.binding.BindingVersion)
	return d.registry.Delegate(ctx, actor, registry.DelegationRequest{BindingVersion: version, EntraTenant: entraTenant, User: user.ObjectID, Instance: req.Instance},
		func(ctx context.Context, agent uuid.UUID) (string, time.Time, error) {
			token, expiry, err := client.OnBehalfOf(ctx, actor.Tenant, agent, req.UserToken, user)
			if err != nil {
				d.log.Warn("on-behalf-of exchange failed", "request_id", actor.RequestID, "tenant", actor.Tenant, "agent_identity", agent, "err", err)
			}
			return token, expiry, err
		})
}

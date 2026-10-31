package entra

// HUMAN REVIEW REQUIRED: on-behalf-of delegation, with the real registry and database and a fake
// Entra directory (signing keys, the agent assertion and the exchange) that checks every request.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// directory is a fake Entra tenant: it publishes signing keys, signs user tokens, and answers
// the blueprint's agent assertion and the agent identity's on-behalf-of exchange.
type directory struct {
	t          *testing.T
	key        *rsa.PrivateKey
	kid        string
	mu         sync.Mutex
	keyFetches int
	assertions int
	exchanges  int
	refuse     bool      // the exchange answers invalid_grant
	answerFor  uuid.UUID // when set, the exchange names this user instead
	answerApp  string    // when set, the exchange names this client instead ("-": none)
	answerTid  string    // when set, the exchange names this directory instead
	answerAud  string    // when set, the exchange's token is for this audience instead
	graphLife  time.Duration
}

func newDirectory(t *testing.T) *directory {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &directory{t: t, key: key, kid: "test-signing-key", graphLife: time.Hour}
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// userClaims are a valid person's token claims for Muistamo's blueprint.
func userClaims(oid uuid.UUID) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": "https://login.microsoftonline.com/" + binding().EntraTenantId + "/v2.0", "aud": binding().BlueprintAppId,
		"tid": binding().EntraTenantId, "oid": oid.String(), "sub": "obviously-fake-subject", "ver": "2.0", "scp": "openid Knowledge.Read",
		"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(30 * time.Minute).Unix(),
	}
}

func (d *directory) token(claims map[string]any) string { return sign(d.t, d.key, d.kid, claims) }

func (d *directory) transport(next roundTripFunc) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "login.microsoftonline.com" {
			return next(r)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		tenant := "/" + binding().EntraTenantId
		if r.Method == http.MethodGet && r.URL.Path == tenant+"/discovery/v2.0/keys" && r.URL.RawQuery == "" {
			d.keyFetches++
			public := jose.JSONWebKey{Key: &d.key.PublicKey, KeyID: d.kid, Use: "sig", Algorithm: "RS256"}
			return response(r, 200, map[string]any{"keys": []any{public}}), nil
		}
		if r.Method != http.MethodPost || r.URL.Path != tenant+"/oauth2/v2.0/token" {
			d.t.Errorf("unexpected directory call %s %s", r.Method, r.URL.Path)
			return response(r, 404, nil), nil
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			d.t.Fatal(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			d.t.Fatal(err)
		}
		bearer := func(token string) *http.Response {
			return response(r, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(d.graphLife.Seconds())})
		}
		switch {
		case form.Get("grant_type") == "client_credentials" && form.Get("scope") == graphScope:
			return bearer(fakeToken), nil
		case form.Get("grant_type") == "client_credentials" && form.Get("scope") == exchangeScope:
			if form.Get("client_id") != binding().BlueprintAppId || form.Get("client_secret") != fakeSecret || len(form) != 5 {
				d.t.Error("agent assertion without the blueprint's credential")
			}
			d.assertions++
			return bearer("obviously-fake-t1-for-" + form.Get("fmi_path")), nil
		case form.Get("grant_type") == jwtBearerGrant:
			agent := form.Get("client_id")
			if form.Get("client_assertion") != "obviously-fake-t1-for-"+agent || form.Get("requested_token_use") != "on_behalf_of" ||
				form.Get("scope") != graphScope || form.Get("client_assertion_type") != assertionType || form.Has("client_secret") {
				d.t.Error("exchange without the agent's own assertion")
			}
			d.exchanges++
			if d.refuse {
				return response(r, 400, map[string]any{"error": "invalid_grant", "error_description": "obviously fake refusal"}), nil
			}
			assertion, err := jwt.ParseSigned(form.Get("assertion"), []jose.SignatureAlgorithm{jose.RS256})
			if err != nil {
				d.t.Fatal(err)
			}
			var person struct {
				Oid string `json:"oid"`
			}
			if err := assertion.Claims(&d.key.PublicKey, &person); err != nil {
				d.t.Fatal(err)
			}
			oid, app := person.Oid, agent
			if d.answerFor != uuid.Nil {
				oid = d.answerFor.String()
			}
			if d.answerApp != "" {
				app = d.answerApp
			}
			tid := binding().EntraTenantId
			if d.answerTid != "" {
				tid = d.answerTid
			}
			aud := registry.GraphResource
			if d.answerAud != "" {
				aud = d.answerAud
			}
			claims := map[string]any{"aud": aud, "tid": tid, "oid": oid, "appid": app, "exp": time.Now().Add(d.graphLife).Unix(), "uti": uuid.NewString()}
			if app == "-" {
				delete(claims, "appid")
			}
			graph := sign(d.t, d.key, "graph-key", claims)
			return bearer(graph), nil
		}
		d.t.Errorf("unexpected token request %v", form.Get("grant_type"))
		return response(r, 400, nil), nil
	}
}

type delegationFixture struct {
	adapterFixture
	dir       *directory
	delegator *Delegator
	actor     registry.Actor
}

// setupDelegation makes HR-PERSON a linked person (userA) with one active live agent.
func setupDelegation(t *testing.T) delegationFixture {
	t.Helper()
	ctx := context.Background()
	f, acts, _ := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON"), user(userB, "HR-OTHER")}
	join := adapterLifecycleRef(t, f, "join")
	if err := acts.EntraLinkUser(ctx, join); err != nil {
		t.Fatal(err)
	}
	for _, step := range []func(context.Context, muistamov1.EntraLifecycleRef, string) error{acts.EntraCreate, acts.EntraEnable, acts.EntraActivate} {
		if err := step(ctx, join, f.name); err != nil {
			t.Fatal(err)
		}
	}
	dir := newDirectory(t)
	f.client.http = &http.Client{Transport: dir.transport(f.graph.transport(t))}
	d, err := NewDelegator(f.svc, quiet, f.client)
	if err != nil {
		t.Fatal(err)
	}
	return delegationFixture{adapterFixture: f, dir: dir, delegator: d, actor: registry.Actor{Tenant: testTenant, Name: "knowledge:" + testTenant.String(), RequestID: uuid.NewString()}}
}

func (f delegationFixture) delegate(t *testing.T, token string, instance *string) (muistamov1.KnowledgeDelegation, error) {
	t.Helper()
	f.actor.RequestID = uuid.NewString()
	return f.delegator.Delegate(context.Background(), f.actor, muistamov1.KnowledgeDelegationRequest{UserToken: token, Instance: instance, Nonce: "00000000000000000000000000000000"})
}

func refusedWith(t *testing.T, err error, reason muistamov1.KnowledgeDelegationRefusalReason) {
	t.Helper()
	var refused *registry.DelegationRefused
	if !errors.As(err, &refused) || refused.Reason != reason {
		t.Fatalf("delegation = %v, want refused %s", err, reason)
	}
}

func TestDelegationActsForTheLinkedPersonThroughTheirActiveAgent(t *testing.T) {
	f := setupDelegation(t)
	token := f.dir.token(userClaims(userA))
	issued, err := f.delegate(t, token, nil)
	if err != nil {
		t.Fatal(err)
	}
	if issued.Instance != f.name || issued.AgentIdentity != testIdentity || issued.Person != "HR-PERSON" || issued.Packs == nil || issued.GraphToken == "" {
		t.Fatalf("delegation = %+v", issued)
	}
	// The delegation never outlives the person's own token.
	if limit := time.Unix(userClaims(userA)["exp"].(int64), 0).Add(time.Second); issued.ExpiresAt.After(limit) {
		t.Fatalf("delegation expires %s, after the person's token", issued.ExpiresAt)
	}
	// Each request is decided and evidenced again; Entra is asked only once for the same token.
	if _, err := f.delegate(t, token, &f.name); err != nil {
		t.Fatal(err)
	}
	if f.dir.exchanges != 1 || f.dir.assertions != 1 {
		t.Fatalf("exchanges = %d, assertions = %d", f.dir.exchanges, f.dir.assertions)
	}
	if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.issued"); n != "2" {
		t.Fatalf("issued evidence events = %s", n)
	}
	// Evidence names the agent, the person and a hash prefix, never a token or the user's id.
	after := testdb.Scalar(t, f.db.OwnerURL, `SELECT string_agg(after::text, ' ') FROM evidence_events WHERE action='knowledge.delegation.issued'`)
	for _, secret := range []string{token, issued.GraphToken, userA.String(), "obviously-fake-t1"} {
		if strings.Contains(after, secret) {
			t.Fatalf("evidence carries %q: %s", secret, after)
		}
	}
	for _, want := range []string{`"tokenHash"`, `"HR-PERSON"`, testIdentity.String(), `"user"`, registry.GraphResource} {
		if !strings.Contains(after, want) {
			t.Fatalf("evidence lacks %s: %s", want, after)
		}
	}
}

func TestDelegationRefusesTokensThatAreNotAPersonsTokenForMuistamo(t *testing.T) {
	f := setupDelegation(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	with := func(change func(map[string]any)) string {
		claims := userClaims(userA)
		change(claims)
		return f.dir.token(claims)
	}
	hs, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("obviously-fake-hmac-key-0123456789")}, (&jose.SignerOptions{}).WithHeader("kid", f.dir.kid))
	if err != nil {
		t.Fatal(err)
	}
	symmetric, err := jwt.Signed(hs).Claims(userClaims(userA)).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	valid := f.dir.token(userClaims(userA))
	parts := strings.Split(valid, ".")
	for name, token := range map[string]string{
		"another key, same id":  sign(t, other, f.dir.kid, userClaims(userA)),
		"unknown key id":        sign(t, f.dir.key, "unknown-key", userClaims(userA)),
		"symmetric algorithm":   symmetric,
		"unsigned":              parts[0] + "." + parts[1] + ".",
		"expired":               with(func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Minute).Unix() }),
		"not yet valid":         with(func(c map[string]any) { c["nbf"] = time.Now().Add(5 * time.Minute).Unix() }),
		"no expiry":             with(func(c map[string]any) { delete(c, "exp") }),
		"no not-before":         with(func(c map[string]any) { delete(c, "nbf") }),
		"another audience":      with(func(c map[string]any) { c["aud"] = "https://graph.microsoft.com" }),
		"two audiences":         with(func(c map[string]any) { c["aud"] = []string{binding().BlueprintAppId, "other"} }),
		"another issuer":        with(func(c map[string]any) { c["iss"] = "https://login.microsoftonline.com/" + uuid.NewString() + "/v2.0" }),
		"another directory":     with(func(c map[string]any) { c["tid"] = uuid.NewString() }),
		"version 1.0":           with(func(c map[string]any) { c["ver"] = "1.0" }),
		"no scope (app-only)":   with(func(c map[string]any) { delete(c, "scp"); c["roles"] = []string{"Knowledge.Read"} }),
		"another scope":         with(func(c map[string]any) { c["scp"] = "Knowledge.ReadWrite User.Read" }),
		"app token type":        with(func(c map[string]any) { c["idtyp"] = "app" }),
		"user id not a uuid":    with(func(c map[string]any) { c["oid"] = "not-a-uuid" }),
		"user id not canonical": with(func(c map[string]any) { c["oid"] = strings.ToUpper(userA.String()) }),
		"oversized":             valid + strings.Repeat("A", maxUserToken),
		"tampered claims":       parts[0] + "." + strings.TrimRight(parts[1], "Q") + "Q." + parts[2],
		"not a token":           "obviously-fake-not-a-jwt",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.delegate(t, token, nil)
			refusedWith(t, err, "token-invalid")
		})
	}
	if f.dir.exchanges != 0 || f.dir.assertions != 0 {
		t.Fatalf("an invalid token reached the exchange: %d", f.dir.exchanges)
	}
	if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.refused"); n == "0" {
		t.Fatal("refusals were not evidenced")
	}
	// A token whose only fault is a scope list with the scope as a substring is still refused.
	if containsWord("Knowledge.ReadAll", KnowledgeScope) || !containsWord("a Knowledge.Read b", KnowledgeScope) {
		t.Fatal("scope match is not by word")
	}
}

func TestDelegationRefusesUsersThatAreNotLinkedByTheCurrentJoiner(t *testing.T) {
	f := setupDelegation(t)
	_, err := f.delegate(t, f.dir.token(userClaims(userB)), nil)
	refusedWith(t, err, "user-unlinked")

	// After a leaver the link's joiner is no longer the person's latest HR event.
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	_, err = f.delegate(t, f.dir.token(userClaims(userA)), nil)
	refusedWith(t, err, "user-unlinked")

	// A rehire whose joiner has not (yet) linked the user is not linked either.
	seedAdapterHR(t, f.conn, f.key, f.actor, "rehire", "joiner", 3)
	_, err = f.delegate(t, f.dir.token(userClaims(userA)), nil)
	refusedWith(t, err, "user-unlinked")
	if f.dir.exchanges != 0 {
		t.Fatalf("an unlinked user reached the exchange")
	}
	// Each refusal is signed with its reason, naming the user only by digest.
	if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.refused"); n != "3" {
		t.Fatalf("refused evidence events = %s", n)
	}
	after := testdb.Scalar(t, f.db.OwnerURL, `SELECT string_agg(after::text, ' ') FROM evidence_events WHERE action='knowledge.delegation.refused'`)
	if !strings.Contains(after, `"user-unlinked"`) || !strings.Contains(after, `"user"`) || strings.Contains(after, userA.String()) {
		t.Fatalf("refusal evidence = %s", after)
	}
}

// otherDirectory registers a second binding, for another Entra directory, and returns its version.
func otherDirectory(t *testing.T, f delegationFixture) string {
	t.Helper()
	version := uuid.NewString()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO entra_bindings (tenant_id, binding_version, config_digest, entra_tenant_id, blueprint_app_id)
		VALUES ($1, $2, repeat('0', 64), gen_random_uuid(), $3)`, testTenant, version, binding().BlueprintAppId)
	return version
}

func TestDelegationRefusesAnErasedOrUnmatchedLink(t *testing.T) {
	for name, change := range map[string]string{
		"erased":          `DELETE FROM person_entra_links`,
		"conflict":        `UPDATE person_entra_links SET status='conflict', entra_user_object_id=NULL`,
		"other directory": `UPDATE person_entra_links SET (binding_version, entra_tenant_id) = (SELECT binding_version, entra_tenant_id FROM entra_bindings WHERE binding_version=$1)`,
	} {
		t.Run(name, func(t *testing.T) {
			f := setupDelegation(t)
			var args []any
			if name == "other directory" {
				args = append(args, otherDirectory(t, f))
			}
			testdb.Exec(t, f.db.OwnerURL, change, args...)
			_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
			refusedWith(t, err, "user-unlinked")
		})
	}
}

func TestDelegationNeedsTheTenantsEnrolledDirectory(t *testing.T) {
	for name, want := range map[string]struct {
		change string
		reason muistamov1.KnowledgeDelegationRefusalReason
	}{
		// The token's binding is no longer the enrolled one.
		"enrolled with another directory": {`UPDATE identity_enrollments SET binding_version=$1`, "identity-not-ready"},
		"not enrolled":                    {`DELETE FROM identity_enrollments WHERE binding_version<>$1`, "user-unlinked"},
	} {
		t.Run(name, func(t *testing.T) {
			f := setupDelegation(t)
			// Only an operator migration changes an enrollment; the test does it directly.
			testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE hr_events DROP CONSTRAINT hr_identity_enrollment`)
			testdb.Exec(t, f.db.OwnerURL, want.change, otherDirectory(t, f))
			_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
			refusedWith(t, err, want.reason)
		})
	}
	// A tenant the control plane holds no binding for is not configured: nothing is decided.
	f := setupDelegation(t)
	other := f.actor
	other.Tenant = uuid.New()
	if _, err := f.delegator.Delegate(context.Background(), other, muistamov1.KnowledgeDelegationRequest{UserToken: f.dir.token(userClaims(userA))}); !errors.Is(err, registry.ErrDelegationNotConfigured) {
		t.Fatalf("another tenant = %v", err)
	}
}

func TestDelegationRefusesWhenTheAgentIsNotActive(t *testing.T) {
	f := setupDelegation(t)
	if _, err := f.svc.TransitionTo(context.Background(), f.actor, f.name, muistamov1.InstanceStateSuspended); err != nil {
		t.Fatal(err)
	}
	_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
	refusedWith(t, err, "no-active-agent")
	other := "someone-elses-agent"
	_, err = f.delegate(t, f.dir.token(userClaims(userA)), &other)
	refusedWith(t, err, "no-active-agent")
	if f.dir.exchanges != 0 {
		t.Fatal("an inactive agent reached the exchange")
	}
}

func TestDelegationRefusesAnIdentityNotEnabledForTheCurrentGeneration(t *testing.T) {
	f := setupDelegation(t)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE instance_identities SET observed_state='disabled'`)
	_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
	refusedWith(t, err, "identity-not-ready")
	if f.dir.exchanges != 0 {
		t.Fatal("an identity that is not ready reached the exchange")
	}
}

// secondAgent adds another active live agent for HR-PERSON whose identity is not provisioned.
func secondAgent(t *testing.T, f delegationFixture) string {
	t.Helper()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO agent_instances (tenant_id, name, template_name, template_version, state, revision, document)
		SELECT tenant_id, 'analyst-second', template_name, template_version, state, revision, jsonb_set(document, '{metadata,name}', '"analyst-second"')
		FROM agent_instances WHERE name=$1`, f.name)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO instance_identities (tenant_id, instance_name, provider_mode, binding_version, entra_tenant_id, assignment_receipt_id, observed_state)
		SELECT tenant_id, 'analyst-second', 'entra', binding_version, entra_tenant_id, assignment_receipt_id, 'unprovisioned' FROM instance_identities WHERE instance_name=$1`, f.name)
	return "analyst-second"
}

func TestDelegationNeedsTheAgentNamedWhenThePersonHasSeveral(t *testing.T) {
	f := setupDelegation(t)
	second := secondAgent(t, f)
	_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
	refusedWith(t, err, "agent-ambiguous")
	_, err = f.delegate(t, f.dir.token(userClaims(userA)), &second)
	refusedWith(t, err, "identity-not-ready")
	if _, err := f.delegate(t, f.dir.token(userClaims(userA)), &f.name); err != nil {
		t.Fatalf("named agent = %v", err)
	}
	// An agent that is not active does not make the choice ambiguous.
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET state='suspended', document=jsonb_set(document,'{spec,state}','"suspended"') WHERE name=$1`, second)
	if issued, err := f.delegate(t, f.dir.token(userClaims(userA)), nil); err != nil || issued.Instance != f.name {
		t.Fatalf("one active agent = %+v, %v", issued, err)
	}
}

// A change that holds the instance's lock commits before the decision reads the agent's state.
func TestADelegationReadsTheAgentUnderItsLock(t *testing.T) {
	f := setupDelegation(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The row lock alone, as UPDATE takes it; the committed row still reads active until commit.
	if _, err := tx.Exec(ctx, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,state}','"suspended"') WHERE name=$1`, f.name); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
		done <- err
	}()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM pg_stat_activity WHERE wait_event_type='Lock' AND wait_event IN ('transactionid','tuple')`) != "0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the delegation never waited on the instance lock")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	refusedWith(t, <-done, "no-active-agent")
}

func TestDelegationRefusesAnExchangeEntraRefusedOrAnsweredForAnotherPrincipal(t *testing.T) {
	for name, change := range map[string]func(*directory){
		"refused":         func(d *directory) { d.refuse = true },
		"another user":    func(d *directory) { d.answerFor = userB },
		"another client":  func(d *directory) { d.answerApp = binding().BlueprintAppId },
		"no client":       func(d *directory) { d.answerApp = "-" },
		"another tenant":  func(d *directory) { d.answerTid = uuid.NewString() },
		"not for Graph":   func(d *directory) { d.answerAud = binding().BlueprintAppId },
		"already expired": func(d *directory) { d.graphLife = 30 * time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			f := setupDelegation(t)
			change(f.dir)
			issued, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
			refusedWith(t, err, "exchange-refused")
			if issued.GraphToken != "" {
				t.Fatal("a token was returned with the refusal")
			}
			if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.issued"); n != "0" {
				t.Fatalf("issued evidence = %s", n)
			}
			// A failed exchange is itself on the record.
			if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.refused"); n != "1" {
				t.Fatalf("refused evidence = %s", n)
			}
		})
	}
}

func TestADelegationWithoutEvidenceIsNotIssued(t *testing.T) {
	f := setupDelegation(t)
	d, err := NewDelegator(registry.New(f.conn, failingSigner{}), quiet, f.client)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := d.Delegate(context.Background(), f.actor, muistamov1.KnowledgeDelegationRequest{UserToken: f.dir.token(userClaims(userA))})
	if !errors.Is(err, registry.ErrEvidence) || issued.GraphToken != "" {
		t.Fatalf("delegation without evidence = %+v, %v", issued, err)
	}
	// A refusal that cannot be recorded is not reported as a recorded refusal either.
	_, err = d.Delegate(context.Background(), f.actor, muistamov1.KnowledgeDelegationRequest{UserToken: "obviously-fake-not-a-jwt"})
	var refused *registry.DelegationRefused
	if !errors.Is(err, registry.ErrEvidence) || errors.As(err, &refused) {
		t.Fatalf("unrecorded refusal = %v", err)
	}
}

// A leaver that holds the person's lock commits before the decision reads the agent's state.
func TestADelegationWaitsForALeaverInProgress(t *testing.T) {
	f := setupDelegation(t)
	ctx := context.Background()
	token := f.dir.token(userClaims(userA))
	if _, err := f.delegate(t, token, nil); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, testTenant.String()+"/HR-PERSON"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_instances SET state='suspended', document=jsonb_set(document,'{spec,state}','"suspended"') WHERE name=$1`, f.name); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.delegate(t, token, nil)
		done <- err
	}()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM pg_stat_activity WHERE wait_event_type='Lock' AND wait_event='advisory'`) != "0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the delegation never waited on the person lock")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	refusedWith(t, <-done, "no-active-agent")
}

func TestSigningKeysAreFetchedAtABoundedRate(t *testing.T) {
	dir := newDirectory(t)
	c, err := New(binding(), func(context.Context, string, string) (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	c.http = &http.Client{Transport: dir.transport(func(r *http.Request) (*http.Response, error) {
		t.Errorf("unexpected call %s", r.URL)
		return response(r, 500, nil), nil
	})}
	ctx := context.Background()
	now := time.Now()
	if _, err := c.ValidateUserToken(ctx, dir.token(userClaims(userA)), now); err != nil {
		t.Fatal(err)
	}
	// Unknown key ids cannot make every request fetch the keys.
	for i := 0; i < 5; i++ {
		if _, err := c.ValidateUserToken(ctx, sign(t, dir.key, "unknown-key", userClaims(userA)), now.Add(time.Second)); !errors.Is(err, ErrUserToken) {
			t.Fatal(err)
		}
	}
	if dir.keyFetches != 1 {
		t.Fatalf("key fetches = %d", dir.keyFetches)
	}
	// A rotated key is found once the refresh interval has passed.
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	retired := dir.key
	dir.key, dir.kid = rotated, "rotated-key"
	if _, err := c.ValidateUserToken(ctx, dir.token(userClaims(userA)), now.Add(keysMinRefresh+time.Second)); err != nil {
		t.Fatalf("rotated key = %v", err)
	}
	if dir.keyFetches != 2 {
		t.Fatalf("key fetches = %d", dir.keyFetches)
	}
	// The retired key, no longer published, is no longer trusted.
	if _, err := c.ValidateUserToken(ctx, sign(t, retired, "test-signing-key", userClaims(userA)), now.Add(2*keysMinRefresh+2*time.Second)); !errors.Is(err, ErrUserToken) {
		t.Fatalf("retired key id = %v", err)
	}
}

func TestOnlyTheThreeTokenRequestsReachTheTokenEndpoint(t *testing.T) {
	c := testClient(t, &fakeGraph{})
	agent := testIdentity.String()
	blueprint := url.Values{"grant_type": {"client_credentials"}, "client_id": {binding().BlueprintAppId}, "scope": {graphScope}, "client_secret": {fakeSecret}}
	t1 := url.Values{"grant_type": {"client_credentials"}, "client_id": {binding().BlueprintAppId}, "scope": {exchangeScope}, "fmi_path": {agent}, "client_secret": {fakeSecret}}
	obo := url.Values{"grant_type": {jwtBearerGrant}, "client_id": {agent}, "client_assertion_type": {assertionType}, "client_assertion": {"t1"}, "assertion": {"tc"}, "requested_token_use": {"on_behalf_of"}, "scope": {graphScope}}
	for _, form := range []url.Values{blueprint, t1, obo} {
		if !c.allowedTokenForm(form) {
			t.Fatalf("refused %v", form.Get("grant_type"))
		}
	}
	changed := func(form url.Values, key string, values ...string) url.Values {
		out := url.Values{}
		for k, v := range form {
			out[k] = v
		}
		if values == nil {
			delete(out, key)
		} else {
			out[key] = values
		}
		return out
	}
	for name, form := range map[string]url.Values{
		"extra parameter":            changed(blueprint, "fmi_path", agent),
		"another client":             changed(blueprint, "client_id", uuid.NewString()),
		"no secret":                  changed(blueprint, "client_secret"),
		"another scope":              changed(blueprint, "scope", "https://graph.microsoft.com/User.Read.All"),
		"two scopes":                 changed(blueprint, "scope", graphScope, exchangeScope),
		"assertion for no agent":     changed(t1, "fmi_path"),
		"assertion for a non-id":     changed(t1, "fmi_path", "../"+agent),
		"exchange with a secret":     changed(obo, "client_secret", fakeSecret),
		"exchange for another use":   changed(obo, "requested_token_use", "other"),
		"exchange for other scope":   changed(obo, "scope", exchangeScope),
		"exchange without assertion": changed(obo, "assertion", ""),
		"exchange by a non-id":       changed(obo, "client_id", "agent"),
		"another grant":              changed(obo, "grant_type", "password"),
	} {
		if c.allowedTokenForm(form) {
			t.Errorf("%s: allowed", name)
		}
	}
	// A refused form is never sent.
	if _, _, err := c.requestToken(context.Background(), "test", changed(blueprint, "scope", "other")); err == nil || !strings.Contains(err.Error(), "destination_refused") {
		t.Fatalf("refused form = %v", err)
	}
}

// Only the tenant's own key set, read without parameters, is reachable on the login host.
func TestOnlyTheTenantsSigningKeysAreReadFromTheLoginHost(t *testing.T) {
	c := testClient(t, &fakeGraph{})
	c.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("request to unapproved destination")
		return nil, nil
	})
	tenant := "https://login.microsoftonline.com/" + binding().EntraTenantId
	for target, method := range map[string]string{
		tenant + "/discovery/v2.0/keys?appid=x":                        http.MethodGet,
		"https://login.microsoftonline.com/common/discovery/v2.0/keys": http.MethodGet,
		tenant + "/discovery/keys":                                     http.MethodGet,
		tenant + "/oauth2/v2.0/token":                                  http.MethodGet,
		tenant + "/discovery/v2.0/keys":                                http.MethodPost,
	} {
		if _, err := c.send(context.Background(), "test", method, target, nil, nil, uuid.New(), false); err == nil {
			t.Fatalf("accepted %s %s", method, target)
		}
	}
}

// Keys not meant for RS256 signatures, too short, or published twice under one id are never trusted.
func TestSigningKeysThatCannotBeTrustedAreIgnored(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string][]jose.JSONWebKey{
		"too short":      {{Key: &weak.PublicKey, KeyID: "k", Use: "sig"}},
		"for encryption": {{Key: &strong.PublicKey, KeyID: "k", Use: "enc"}},
		"another alg":    {{Key: &strong.PublicKey, KeyID: "k", Algorithm: "PS256"}},
		"duplicate id":   {{Key: &strong.PublicKey, KeyID: "k"}, {Key: &second.PublicKey, KeyID: "k"}},
		"not an RSA key": {{Key: []byte("obviously-fake-symmetric-key-000"), KeyID: "k"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := testClient(t, &fakeGraph{})
			c.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return response(r, 200, map[string]any{"keys": keys}), nil
			})
			signer := strong
			if name == "too short" {
				signer = weak
			}
			if _, err := c.ValidateUserToken(context.Background(), sign(t, signer, "k", userClaims(userA)), time.Now()); !errors.Is(err, ErrUserToken) {
				t.Fatalf("validated with %s: %v", name, err)
			}
		})
	}
}

// The registry refuses an exchange answer it cannot use, whatever the exchange reports.
func TestTheRegistryRefusesAnEmptyOrExpiredExchangeAnswer(t *testing.T) {
	f := setupDelegation(t)
	for name, answer := range map[string]struct {
		token   string
		expires time.Time
	}{"empty": {"", time.Now().Add(time.Hour)}, "expired": {"obviously-fake-graph-token", time.Now().Add(-time.Second)}} {
		f.actor.RequestID = uuid.NewString()
		_, err := f.svc.Delegate(context.Background(), f.actor, registry.DelegationRequest{BindingVersion: uuid.MustParse(binding().BindingVersion), EntraTenant: uuid.MustParse(binding().EntraTenantId), User: userA},
			func(context.Context, uuid.UUID) (string, time.Time, error) { return answer.token, answer.expires, nil })
		if !errors.As(err, new(*registry.DelegationRefused)) {
			t.Fatalf("%s: %v", name, err)
		}
		refusedWith(t, err, "exchange-refused")
	}
}

// Each user token is exchanged for itself: a cached answer is never served for another token.
func TestExchangedTokensAreCachedPerUserToken(t *testing.T) {
	f := setupDelegation(t)
	ctx := context.Background()
	user := func(oid uuid.UUID) (string, UserClaims) {
		token := f.dir.token(userClaims(oid))
		claims, err := f.client.ValidateUserToken(ctx, token, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return token, claims
	}
	tokenA, claimsA := user(userA)
	tokenB, claimsB := user(userB)
	graphA, _, err := f.client.OnBehalfOf(ctx, testTenant, testIdentity, tokenA, claimsA)
	if err != nil {
		t.Fatal(err)
	}
	graphB, _, err := f.client.OnBehalfOf(ctx, testTenant, testIdentity, tokenB, claimsB)
	if err != nil {
		t.Fatal(err)
	}
	if graphA == graphB || f.dir.exchanges != 2 || f.dir.assertions != 1 {
		t.Fatalf("exchanges = %d, assertions = %d, same token = %t", f.dir.exchanges, f.dir.assertions, graphA == graphB)
	}
	// Another tenant's request never uses this binding's client.
	if _, _, err := f.client.OnBehalfOf(ctx, uuid.New(), testIdentity, tokenA, claimsA); !errors.Is(err, ErrScope) {
		t.Fatalf("another tenant = %v", err)
	}
}

// After the tenant enrols another binding, the old one stops validating and exchanging at once,
// and agents of the old blueprint cannot act under the new one.
func TestDelegationNeedsTheEnrolledBindingVersion(t *testing.T) {
	f := setupDelegation(t)
	ctx := context.Background()
	next := binding()
	next.BindingVersion = uuid.NewString()
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, next); err != nil {
		t.Fatal(err)
	}
	// Only an operator migration re-enrols a tenant; the test does it directly.
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE hr_events DROP CONSTRAINT hr_identity_enrollment`)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE identity_enrollments SET binding_version=$1`, next.BindingVersion)
	_, err := f.delegate(t, f.dir.token(userClaims(userA)), nil)
	refusedWith(t, err, "identity-not-ready")
	c, err := New(next, func(context.Context, string, string) (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	c.http = f.client.http
	d, err := NewDelegator(f.svc, quiet, c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Delegate(ctx, f.actor, muistamov1.KnowledgeDelegationRequest{UserToken: f.dir.token(userClaims(userA))})
	refusedWith(t, err, "identity-not-ready")
	if f.dir.exchanges != 0 {
		t.Fatal("a binding that is not enrolled reached the exchange")
	}
}

// The exchange runs holding no lock, and a suspension that lands during it is seen afterwards.
func TestTheExchangeHoldsNoLockAndIsDecidedAgainAfterwards(t *testing.T) {
	f := setupDelegation(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	exchanged := false
	issued, err := f.svc.Delegate(ctx, f.actor, registry.DelegationRequest{BindingVersion: uuid.MustParse(binding().BindingVersion), EntraTenant: uuid.MustParse(binding().EntraTenantId), User: userA},
		func(context.Context, uuid.UUID) (string, time.Time, error) {
			exchanged = true
			var free bool
			if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, testTenant.String()+"/HR-PERSON").Scan(&free); err != nil || !free {
				t.Errorf("the person lock was held during the exchange: %v", err)
			}
			if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, testTenant.String()+"/HR-PERSON"); err != nil {
				t.Error(err)
			}
			if _, err := conn.Exec(ctx, `UPDATE agent_instances SET state='suspended', document=jsonb_set(document,'{spec,state}','"suspended"') WHERE name=$1`, f.name); err != nil {
				t.Error(err)
			}
			return "obviously-fake-graph-token", time.Now().Add(time.Hour), nil
		})
	if !exchanged {
		t.Fatal("no exchange")
	}
	refusedWith(t, err, "no-active-agent")
	if issued.GraphToken != "" {
		t.Fatal("the token was returned after the agent was suspended")
	}
	if n := evidenceCount(t, f.adapterFixture, "knowledge.delegation.issued"); n != "0" {
		t.Fatalf("issued evidence = %s", n)
	}
}

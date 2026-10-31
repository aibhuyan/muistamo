package api_test

// HUMAN REVIEW REQUIRED: the knowledge service's signed delegation route.

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/signature"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

const fakeUserToken = "obviously-fake-user-token-0123456789"

// fakeDelegator answers with err, or issues a fixed delegation, and records what it was asked.
type fakeDelegator struct {
	mu    sync.Mutex
	asked []registry.Actor
	err   error
}

func (d *fakeDelegator) Delegate(_ context.Context, actor registry.Actor, req muistamov1.KnowledgeDelegationRequest) (muistamov1.KnowledgeDelegation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.asked = append(d.asked, actor)
	if d.err != nil {
		return muistamov1.KnowledgeDelegation{}, d.err
	}
	return muistamov1.KnowledgeDelegation{Instance: "analyst-person", AgentIdentity: uuid.New(), Person: "HR-PERSON", Packs: []muistamov1.KnowledgePackRef{},
		GraphToken: "obviously-fake-graph-token", ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func newDelegationHarness(t *testing.T, delegator api.Delegator, logs *strings.Builder) harness {
	t.Helper()
	db := testdb.New(t)
	conn, err := store.Open(context.Background(), db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	srv := httptest.NewServer(api.HandlerWithDelegator(registry.New(conn, key), api.InsecureDevHeaders{}, nil, delegator, slog.New(slog.NewJSONHandler(logs, nil))))
	t.Cleanup(srv.Close)
	return harness{db: db, key: key, url: srv.URL}
}

func knowledgeSecret(t *testing.T, h harness, tenant uuid.UUID) []byte {
	t.Helper()
	secret := []byte("obviously-fake-knowledge-secret-" + tenant.String())
	if err := store.SetKnowledgeSecret(context.Background(), h.db.OwnerURL, tenant, secret); err != nil {
		t.Fatal(err)
	}
	return secret
}

func delegationBody(nonce string) string {
	return `{"userToken":"` + fakeUserToken + `","nonce":"` + nonce + `"}`
}

func newNonce() string { return strings.ReplaceAll(uuid.NewString(), "-", "") }

func (h harness) postDelegation(t *testing.T, tenant uuid.UUID, key []byte, at time.Time, body string) response {
	t.Helper()
	return h.call(t, tenant, http.MethodPost, "/v1/internal/knowledge/delegations", body, "X-Muistamo-Signature", signature.Sign(key, []byte(body), at))
}

func TestDelegationRequestsAreSignedForTheirDirectionAndUsedOnce(t *testing.T) {
	d := &fakeDelegator{}
	var logs strings.Builder
	h := newDelegationHarness(t, d, &logs)
	tenant, other := h.tenant(t, "acme"), h.tenant(t, "globex")
	secret := knowledgeSecret(t, h, tenant)
	otherSecret := knowledgeSecret(t, h, other)
	key := signature.DirectionKey(secret, signature.KnowledgeToControlPlane, tenant.String())
	body := delegationBody(newNonce())
	umbrella := h.tenant(t, "umbrella")

	ok := h.postDelegation(t, tenant, key, time.Now(), body)
	if ok.status != http.StatusOK || ok.body["graphToken"] != "obviously-fake-graph-token" || ok.cacheControl != "no-store" {
		t.Fatalf("signed request = %d %s", ok.status, ok.raw)
	}
	if len(d.asked) != 1 || d.asked[0].Tenant != tenant || d.asked[0].Name != "knowledge:"+tenant.String() {
		t.Fatalf("delegator asked as %+v", d.asked)
	}
	for name, res := range map[string]response{
		// The control plane signs its calls to the knowledge service with the secret itself.
		"the other direction's key": h.postDelegation(t, tenant, secret, time.Now(), delegationBody(newNonce())),
		"another tenant's key":      h.postDelegation(t, tenant, signature.DirectionKey(otherSecret, signature.KnowledgeToControlPlane, other.String()), time.Now(), delegationBody(newNonce())),
		"stale":                     h.postDelegation(t, tenant, key, time.Now().Add(-6*time.Minute), delegationBody(newNonce())),
		"replayed nonce":            h.postDelegation(t, tenant, key, time.Now(), body),
		"tenant without a secret":   h.postDelegation(t, h.tenant(t, "initech"), key, time.Now(), delegationBody(newNonce())),
		// Without a secret the derived key would be public: such a tenant accepts nothing.
		"key derived from no secret": h.postDelegation(t, umbrella, signature.DirectionKey(nil, signature.KnowledgeToControlPlane, umbrella.String()), time.Now(), delegationBody(newNonce())),
		"dev headers only":           h.call(t, tenant, http.MethodPost, "/v1/internal/knowledge/delegations", delegationBody(newNonce())),
	} {
		if res.status != http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, res.status, res.raw)
		}
	}
	if len(d.asked) != 1 {
		t.Fatalf("an unauthenticated request reached the delegator: %d", len(d.asked))
	}
	// Two tenants given the same secret by mistake still have different keys.
	shared := h.tenant(t, "shared")
	if err := store.SetKnowledgeSecret(context.Background(), h.db.OwnerURL, shared, secret); err != nil {
		t.Fatal(err)
	}
	if res := h.postDelegation(t, shared, key, time.Now(), delegationBody(newNonce())); res.status != http.StatusUnauthorized {
		t.Fatalf("a request signed for another tenant with the same secret = %d %s", res.status, res.raw)
	}
	// The same nonce is another request in another tenant.
	if res := h.postDelegation(t, other, signature.DirectionKey(otherSecret, signature.KnowledgeToControlPlane, other.String()), time.Now(), body); res.status != http.StatusOK {
		t.Fatalf("other tenant, same nonce = %d %s", res.status, res.raw)
	}
	// A bad body never echoes the user token, and neither do the logs.
	bad := `{"userToken":"` + fakeUserToken + `","nonce":"short"}`
	if res := h.postDelegation(t, tenant, key, time.Now(), bad); res.status != http.StatusUnprocessableEntity || strings.Contains(res.raw, fakeUserToken) {
		t.Fatalf("invalid body = %d %s", res.status, res.raw)
	}
	if strings.Contains(logs.String(), fakeUserToken) || strings.Contains(logs.String(), "obviously-fake-graph-token") {
		t.Fatalf("a token was logged: %s", logs.String())
	}
}

func TestDelegationOutcomesMapToTheirResponses(t *testing.T) {
	for name, want := range map[string]struct {
		err    error
		status int
		reason string
	}{
		"refused":          {&registry.DelegationRefused{Reason: "user-unlinked"}, http.StatusForbidden, "user-unlinked"},
		"not recorded":     {registry.ErrEvidence, http.StatusServiceUnavailable, "evidence-unavailable"},
		"not configured":   {registry.ErrDelegationNotConfigured, http.StatusNotImplemented, ""},
		"unexpected error": {fmt.Errorf("decide delegation: instance analyst-secret: %w", registry.ErrNotFound), http.StatusInternalServerError, ""},
	} {
		t.Run(name, func(t *testing.T) {
			var logs strings.Builder
			h := newDelegationHarness(t, &fakeDelegator{err: want.err}, &logs)
			tenant := h.tenant(t, "acme")
			key := signature.DirectionKey(knowledgeSecret(t, h, tenant), signature.KnowledgeToControlPlane, tenant.String())
			res := h.postDelegation(t, tenant, key, time.Now(), delegationBody(newNonce()))
			if res.status != want.status || (want.reason != "" && res.body["reason"] != want.reason) || res.body["graphToken"] != nil {
				t.Fatalf("%d %s", res.status, res.raw)
			}
			// Nothing about an unexpected failure leaves the server.
			if strings.Contains(res.raw, "analyst-secret") {
				t.Fatalf("failure detail leaked: %s", res.raw)
			}
		})
	}
}

func TestWithoutADelegatorTheRouteAnswersNotImplemented(t *testing.T) {
	var logs strings.Builder
	h := newDelegationHarness(t, nil, &logs)
	tenant := h.tenant(t, "acme")
	key := signature.DirectionKey(knowledgeSecret(t, h, tenant), signature.KnowledgeToControlPlane, tenant.String())
	if res := h.postDelegation(t, tenant, key, time.Now(), delegationBody(newNonce())); res.status != http.StatusNotImplemented {
		t.Fatalf("%d %s", res.status, res.raw)
	}
	// Still authenticated first.
	if res := h.postDelegation(t, tenant, []byte("obviously-wrong"), time.Now(), delegationBody(newNonce())); res.status != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d %s", res.status, res.raw)
	}
}

func TestDelegationNoncesArePrunedOnlyAfterTheSignatureWindow(t *testing.T) {
	var logs strings.Builder
	h := newDelegationHarness(t, &fakeDelegator{}, &logs)
	tenant := h.tenant(t, "acme")
	conn, err := store.Open(context.Background(), h.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	svc := registry.New(conn, h.key)
	old, recent := newNonce(), newNonce()
	for _, nonce := range []string{old, recent} {
		if err := svc.UseDelegationNonce(context.Background(), tenant, nonce); err != nil {
			t.Fatal(err)
		}
	}
	testdb.Exec(t, h.db.OwnerURL, `UPDATE delegation_nonces SET seen_at = now() - interval '16 minutes' WHERE nonce=$1`, old)
	testdb.Exec(t, h.db.OwnerURL, `UPDATE delegation_nonces SET seen_at = now() - interval '14 minutes' WHERE nonce=$1`, recent)
	if err := svc.UseDelegationNonce(context.Background(), tenant, newNonce()); err != nil {
		t.Fatal(err)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM delegation_nonces WHERE nonce=$1`, old); n != 0 {
		t.Fatal("an expired nonce was kept")
	}
	if err := svc.UseDelegationNonce(context.Background(), tenant, recent); err == nil {
		t.Fatal("a nonce was accepted twice inside fifteen minutes")
	}
	// The application role can never rewrite a nonce's time.
	if err := testdb.ExecErr(h.db.AppURL, tenant, `UPDATE delegation_nonces SET seen_at = now() - interval '1 hour'`); err == nil {
		t.Fatal("the application role updated a nonce")
	}
}

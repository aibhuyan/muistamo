package api_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Step 3a of docs/agentgateway-plan.md: issuing and revoking virtual keys.

const gatewayAdmin = "gw-admin@example.invalid"

// The contract's own pattern (virtualkeyissued.json).
var secretPattern = regexp.MustCompile(`^mvk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)

func keyRequest(instance, alias, extra string) string {
	return `{"instance":"` + instance + `","aliases":["` + alias + `"],"monthlyBudget":{"amount":"25.50","currency":"EUR"}` + extra + `}`
}

// keyTenant gives a tenant an instance whose model alias is approved, and one gateway admin.
func keyTenant(t *testing.T, h harness, name string) uuid.UUID {
	t.Helper()
	tenant := h.tenant(t, name)
	if got := h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("template = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, tenant, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON); got.status != http.StatusCreated {
		t.Fatalf("instance = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, tenant, http.MethodPost, "/v1/instances/analyst-intern-person-a/transitions", `{"to":"active"}`, "If-Match", `"1"`); got.status != http.StatusOK {
		t.Fatalf("activate = %d: %s", got.status, got.raw)
	}
	if err := registry.ConfigureGatewayAdmins(t.Context(), h.db.OwnerURL, registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: uuid.NewString()}, []string{"dev:" + gatewayAdmin}, h.key); err != nil {
		t.Fatal(err)
	}
	return tenant
}

func TestVirtualKeysAreForGatewayAdminsOnly(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := keyTenant(t, h, "tenant-a")
	issued := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", ""), as(gatewayAdmin)...)
	if issued.status != http.StatusCreated {
		t.Fatalf("admin issues = %d: %s", issued.status, issued.raw)
	}
	id := issued.body["key"].(map[string]any)["id"].(string)
	// The default caller is the instance's own person, not an admin: refused everything.
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", "")},
		{http.MethodGet, "/v1/virtual-keys", ""},
		{http.MethodGet, "/v1/virtual-keys/" + id, ""},
		{http.MethodPost, "/v1/virtual-keys/" + id + "/revocation", `{"reason":"operator"}`},
	} {
		if got := h.call(t, a, c.method, c.path, c.body); got.status != http.StatusForbidden {
			t.Errorf("non-admin %s %s = %d, want 403", c.method, c.path, got.status)
		}
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM virtual_keys WHERE status = 'active'`); n != 1 {
		t.Errorf("active keys = %d, want only the admin's", n)
	}
}

func TestAnIssuedSecretIsShownOnceAndStoredOnlyAsItsHash(t *testing.T) {
	var logs bytes.Buffer
	h := newHarnessLogging(t, api.InsecureDevHeaders{}, nil, &logs)
	a := keyTenant(t, h, "tenant-a")
	got := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", ""), as(gatewayAdmin)...)
	if got.status != http.StatusCreated {
		t.Fatalf("issue = %d: %s", got.status, got.raw)
	}
	secret := got.body["secret"].(string)
	if got.cacheControl != "no-store" {
		t.Errorf("one-time secret response Cache-Control = %q, want no-store", got.cacheControl)
	}
	key := got.body["key"].(map[string]any)
	if !secretPattern.MatchString(secret) {
		t.Fatalf("secret %q does not match the contract", secret)
	}
	id, raw, err := registry.ParseKey(secret)
	if err != nil || id.String() != key["id"] {
		t.Fatalf("ParseKey = %s, %v; want the key's id %s", id, err, key["id"])
	}
	if key["status"] != "active" || key["createdBy"] != "dev:"+gatewayAdmin || key["monthlyBudget"].(map[string]any)["amount"] != "25.5" {
		t.Errorf("key = %v", key)
	}
	second := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", ""), as(gatewayAdmin)...)
	if second.status != http.StatusCreated {
		t.Fatalf("second issue = %d", second.status)
	}
	_, otherRaw, err := registry.ParseKey(second.body["secret"].(string))
	if err != nil || bytes.Equal(raw, otherRaw) {
		t.Fatal("distinct keys reused the same secret bytes")
	}
	sum := sha256.Sum256(raw)
	if stored := testdb.Scalar(t, h.db.OwnerURL, `SELECT encode(secret_sha256, 'hex') FROM virtual_keys WHERE id = $1`, id); stored != hex.EncodeToString(sum[:]) {
		t.Errorf("stored hash %s is not SHA-256 of the decoded secret", stored)
	}
	// Nowhere but the response: not the database, not evidence, not the logs, not later reads.
	encoded := secret[len("mvk_")+37:]
	for name, text := range map[string]string{
		"database": testdb.Scalar(t, h.db.OwnerURL, `SELECT coalesce(string_agg(to_jsonb(k)::text, ''), '') FROM virtual_keys k`),
		"evidence": testdb.Scalar(t, h.db.OwnerURL, `SELECT coalesce(string_agg(to_jsonb(e)::text, ''), '') FROM evidence_events e`),
		"logs":     logs.String(),
		"get":      h.call(t, a, http.MethodGet, "/v1/virtual-keys/"+id.String(), "", as(gatewayAdmin)...).raw,
		"list":     h.call(t, a, http.MethodGet, "/v1/virtual-keys", "", as(gatewayAdmin)...).raw,
	} {
		if strings.Contains(text, encoded) || strings.Contains(text, secret) {
			t.Errorf("the secret appears in the %s", name)
		}
	}
	if raw := testdb.Scalar(t, h.db.OwnerURL, `SELECT coalesce(string_agg(to_jsonb(e)::text, ''), '') FROM evidence_events e WHERE action = 'gateway.key.issued'`); !strings.Contains(raw, id.String()) || strings.Contains(raw, hex.EncodeToString(sum[:])) {
		t.Errorf("issue evidence = %s; want the key id and never its hash", raw)
	}
}

func TestIssuingRefusesKeysTheInstanceCannotUse(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := keyTenant(t, h, "tenant-a")
	admin := as(gatewayAdmin)
	for name, c := range map[string]struct {
		body   string
		status int
	}{
		"an unknown instance":          {keyRequest("nobody", "reasoning-default", ""), http.StatusNotFound},
		"another model alias":          {keyRequest("analyst-intern-person-a", "something-else", ""), http.StatusUnprocessableEntity},
		"a budget in another currency": {strings.Replace(keyRequest("analyst-intern-person-a", "reasoning-default", ""), `"EUR"`, `"USD"`, 1), http.StatusUnprocessableEntity},
		"an expiry in the past":        {keyRequest("analyst-intern-person-a", "reasoning-default", `,"expiresAt":"2020-01-01T00:00:00Z"`), http.StatusUnprocessableEntity},
		"a malformed budget":           {strings.Replace(keyRequest("analyst-intern-person-a", "reasoning-default", ""), `"25.50"`, `"25.5.0"`, 1), http.StatusUnprocessableEntity},
	} {
		if got := h.call(t, a, http.MethodPost, "/v1/virtual-keys", c.body, admin...); got.status != c.status {
			t.Errorf("%s = %d, want %d: %s", name, got.status, c.status, got.raw)
		}
	}
	// An approved, compliant alias that is not this instance's own is still refused.
	testdb.ApprovedModelAlias(t, h.db.OwnerURL, a, "other-alias")
	if got := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "other-alias", ""), admin...); got.status != http.StatusUnprocessableEntity || !strings.Contains(got.raw, "is not the model alias") {
		t.Errorf("another instance's alias = %d: %s", got.status, got.raw)
	}
	// A model that is no longer approved makes its alias unusable for new keys.
	testdb.Exec(t, h.db.OwnerURL, `UPDATE model_catalogue SET approval_status = 'revoked', decided_by = 'seed:dpo',
		decision_reason = 'test', decided_at = now() WHERE tenant_id = $1`, a)
	if got := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", ""), admin...); got.status != http.StatusUnprocessableEntity || !strings.Contains(got.raw, "not compliant") {
		t.Errorf("non-compliant alias = %d: %s", got.status, got.raw)
	}
	// A retired instance gets no keys.
	testdb.Exec(t, h.db.OwnerURL, `UPDATE agent_instances SET document = jsonb_set(document, '{spec,state}', '"retired"') WHERE tenant_id = $1`, a)
	if got := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", ""), admin...); got.status != http.StatusConflict {
		t.Errorf("retired instance = %d: %s", got.status, got.raw)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM virtual_keys`); n != 0 {
		t.Errorf("keys stored despite refusals: %d", n)
	}
}

func TestRevocationIsFinalAndEvidenced(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := keyTenant(t, h, "tenant-a")
	admin := as(gatewayAdmin)
	issued := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", ""), admin...)
	id := issued.body["key"].(map[string]any)["id"].(string)
	path := "/v1/virtual-keys/" + id + "/revocation"

	if got := h.call(t, a, http.MethodPost, path, `{"reason":"leaver person-a@example.invalid"}`, admin...); got.status != http.StatusUnprocessableEntity {
		t.Errorf("a reason with an email = %d, want 422", got.status)
	}
	got := h.call(t, a, http.MethodPost, path, `{"reason":"leaver"}`, admin...)
	if got.status != http.StatusOK || got.body["status"] != "revoked" || got.body["revokedBy"] != "dev:"+gatewayAdmin {
		t.Fatalf("revoke = %d: %s", got.status, got.raw)
	}
	if again := h.call(t, a, http.MethodPost, path, `{"reason":"operator"}`, admin...); again.status != http.StatusConflict {
		t.Errorf("second revoke = %d, want 409", again.status)
	}
	if actor := testdb.Scalar(t, h.db.OwnerURL, `SELECT actor FROM evidence_events WHERE action = 'gateway.key.revoked' AND subject_name = $1`, id); actor != "dev:"+gatewayAdmin {
		t.Errorf("revocation evidence actor = %q", actor)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action = 'gateway.key.revoked'`); n != 1 {
		t.Errorf("revocation events = %d, want 1", n)
	}
}

func TestExpiryIsReportedNeverStored(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := keyTenant(t, h, "tenant-a")
	admin := as(gatewayAdmin)
	soon := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	issued := h.call(t, a, http.MethodPost, "/v1/virtual-keys", keyRequest("analyst-intern-person-a", "reasoning-default", `,"expiresAt":"`+soon+`"`), admin...)
	id := issued.body["key"].(map[string]any)["id"].(string)
	// Move the key into the past, as the owner would see it a day later.
	testdb.Exec(t, h.db.OwnerURL, `ALTER TABLE virtual_keys DISABLE TRIGGER virtual_keys_stamp`)
	testdb.Exec(t, h.db.OwnerURL, `UPDATE virtual_keys SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, id)
	testdb.Exec(t, h.db.OwnerURL, `ALTER TABLE virtual_keys ENABLE TRIGGER virtual_keys_stamp`)
	if got := h.call(t, a, http.MethodGet, "/v1/virtual-keys/"+id, "", admin...); got.body["status"] != "expired" {
		t.Errorf("status = %v, want expired", got.body["status"])
	}
	if stored := testdb.Scalar(t, h.db.OwnerURL, `SELECT status FROM virtual_keys WHERE id = $1`, id); stored != "active" {
		t.Errorf("stored status = %q; expiry must never be written", stored)
	}
}

func TestParseKeyAcceptsOnlyCanonicalKeys(t *testing.T) {
	id := uuid.New().String()
	good := "mvk_" + id + "_" + strings.Repeat("A", 42) + "E"
	if _, _, err := registry.ParseKey(good); err != nil {
		t.Fatalf("canonical key refused: %v", err)
	}
	for name, k := range map[string]string{
		"no prefix":               strings.TrimPrefix(good, "mvk_"),
		"another prefix":          "mhr_" + strings.TrimPrefix(good, "mvk_"),
		"upper-case id":           "mvk_" + strings.ToUpper(id) + "_" + strings.Repeat("A", 42) + "E",
		"short secret":            "mvk_" + id + "_" + strings.Repeat("A", 42),
		"padded secret":           "mvk_" + id + "_" + strings.Repeat("A", 42) + "E=",
		"non-canonical last char": "mvk_" + id + "_" + strings.Repeat("A", 42) + "F",
		"standard base64":         "mvk_" + id + "_" + strings.Repeat("+", 42) + "E",
		"empty":                   "",
	} {
		if _, _, err := registry.ParseKey(k); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	hash := sha256.Sum256([]byte("0123456789abcdef0123456789abcdef"))
	if !registry.KeyMatches(hash[:], []byte("0123456789abcdef0123456789abcdef")) || registry.KeyMatches(hash[:], []byte("0123456789abcdef0123456789abcdeX")) || registry.KeyMatches(hash[:5], []byte("x")) {
		t.Error("KeyMatches compares wrongly")
	}
}

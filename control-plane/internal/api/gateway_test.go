package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Step 2 of docs/agentgateway-plan.md: the schema's own guarantees, before any code writes it.
// Every statement here runs as the server's role, which row-level security binds.

const (
	insertKey = `INSERT INTO virtual_keys (tenant_id, id, instance, aliases, budget_amount, budget_currency,
		secret_sha256, created_by) VALUES ($1, $2, 'analyst-intern-person-a', ARRAY['reasoning-default'], 10, 'EUR',
		decode(repeat('ab', 32), 'hex'), 'dev:person-a@example.invalid')`
	insertModelCall = `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, cost_centre, kind,
		alias, provider, model, price_currency, input_per_mtok, output_per_mtok)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'cc-1', 'model',
		'reasoning-default', 'test', 'test-model', 'EUR', 3, 15)`
	insertUsage = `INSERT INTO usage_records (tenant_id, request_id, input_tokens, output_tokens, cost_amount, cost_currency)
		VALUES ($1, $2, 11, 7, 0.000138, 'EUR')`
)

// seedGateway gives tenant one instance, one key, one authorized model call and its usage.
func seedGateway(t *testing.T, h harness, tenant uuid.UUID) (key, call uuid.UUID) {
	t.Helper()
	if got := h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed template = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, tenant, http.MethodPut, "/v1/instances/analyst-intern-person-a", instanceJSON); got.status != http.StatusCreated {
		t.Fatalf("seed instance = %d: %s", got.status, got.raw)
	}
	key, call = uuid.New(), uuid.New()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{insertKey, []any{tenant, key}},
		{insertModelCall, []any{tenant, call, key}},
		{insertUsage, []any{tenant, call}},
	} {
		testdb.ExecIn(t, h.db.AppURL, tenant, s.sql, s.args...)
	}
	return key, call
}

func TestGatewaySchemaLetsTheServerOnlyIssueAndRevokeKeys(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	key, call := seedGateway(t, h, a)
	app := h.db.AppURL

	// Nothing but the revocation columns can change: not the secret, scope, budget or owner.
	for _, stmt := range []string{
		`UPDATE virtual_keys SET secret_sha256 = decode(repeat('cd', 32), 'hex') WHERE id = $1`,
		`UPDATE virtual_keys SET budget_amount = 1000000 WHERE id = $1`,
		`UPDATE virtual_keys SET aliases = ARRAY['anything'] WHERE id = $1`,
		`UPDATE virtual_keys SET instance = 'someone-else' WHERE id = $1`,
		`UPDATE virtual_keys SET expires_at = NULL WHERE id = $1`,
		`DELETE FROM virtual_keys WHERE id = $1`,
	} {
		if err := testdb.ExecErr(app, a, stmt, key); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: err = %v, want permission denied", stmt, err)
		}
	}
	// A revocation needs who, when and why.
	if err := testdb.ExecErr(app, a, `UPDATE virtual_keys SET status = 'revoked' WHERE id = $1`, key); err == nil {
		t.Error("revoking without revoked_at/by/reason succeeded")
	}
	testdb.ExecIn(t, app, a, `UPDATE virtual_keys SET status = 'revoked', revoked_at = now(),
		revoked_by = 'dev:owner@example.invalid', revoke_reason = 'leaver' WHERE id = $1`, key)
	if n := testdb.CountIn(t, app, a, `SELECT count(*) FROM virtual_keys WHERE id = $1 AND status = 'revoked'`, key); n != 1 {
		t.Fatalf("revoked keys = %d, want 1", n)
	}
	// And it is final, whoever writes: neither the server nor the owner can bring it back.
	for _, url := range []string{app, h.db.OwnerURL} {
		err := testdb.ExecErr(url, a, `UPDATE virtual_keys SET status = 'active', revoked_at = NULL,
			revoked_by = NULL, revoke_reason = NULL WHERE id = $1`, key)
		if err == nil || !strings.Contains(err.Error(), "revocation is final") {
			t.Errorf("un-revoke: err = %v, want revocation is final", err)
		}
	}

	// The call and usage ledgers are append-only.
	for _, stmt := range []string{
		`UPDATE gateway_calls SET input_per_mtok = 0 WHERE request_id = $1`,
		`DELETE FROM gateway_calls WHERE request_id = $1`,
		`UPDATE usage_records SET cost_amount = 0 WHERE request_id = $1`,
		`DELETE FROM usage_records WHERE request_id = $1`,
	} {
		if err := testdb.ExecErr(app, a, stmt, call); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: err = %v, want permission denied", stmt, err)
		}
	}
}

func TestGatewaySchemaRefusesIncompleteRecords(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	key, call := seedGateway(t, h, a)
	app := h.db.AppURL
	for name, s := range map[string]struct {
		sql  string
		args []any
	}{
		"a key for an instance that does not exist": {strings.Replace(insertKey, "'analyst-intern-person-a'", "'nobody'", 1), []any{a, uuid.New()}},
		"a key whose secret hash is not 32 bytes": {strings.Replace(insertKey, "repeat('ab', 32)", "repeat('ab', 16)", 1), []any{a, uuid.New()}},
		"a key with no aliases": {strings.Replace(insertKey, "ARRAY['reasoning-default']", "ARRAY[]::text[]", 1), []any{a, uuid.New()}},
		"a key with a negative budget": {strings.Replace(insertKey, ", 10, 'EUR'", ", -1, 'EUR'", 1), []any{a, uuid.New()}},
		"a model call with no price snapshot": {strings.Replace(insertModelCall, "'EUR', 3, 15", "NULL, NULL, NULL", 1), []any{a, uuid.New(), key}},
		"a call for an unknown key": {insertModelCall, []any{a, uuid.New(), uuid.New()}},
		"an MCP call with no method": {`INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind)
			VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp')`, []any{a, uuid.New(), key}},
		"usage for a call that was never authorized": {insertUsage, []any{a, uuid.New()}},
		"a second usage record for one call":          {insertUsage, []any{a, call}},
		"usage with negative tokens":                  {strings.Replace(insertUsage, "11, 7", "-1, 7", 1), []any{a, call}},
	} {
		if err := testdb.ExecErr(app, a, s.sql, s.args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGatewayEndpointsSayTheyAreNotBuiltYet(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	id := uuid.NewString()
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/virtual-keys", ""},
		{http.MethodPost, "/v1/virtual-keys", `{"instance":"x","aliases":["a"],"monthlyBudget":{"amount":"10","currency":"EUR"}}`},
		{http.MethodGet, "/v1/virtual-keys/" + id, ""},
		{http.MethodPost, "/v1/virtual-keys/" + id + "/revocation", `{"reason":"r"}`},
		{http.MethodGet, "/v1/usage", ""},
	} {
		got := h.call(t, a, c.method, c.path, c.body)
		if got.status != http.StatusNotImplemented || !strings.Contains(got.raw, "agentgateway-plan") {
			t.Errorf("%s %s = %d: %s, want an honest 501", c.method, c.path, got.status, got.raw)
		}
	}
}

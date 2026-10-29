package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

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
	insertMCPCall = `INSERT INTO gateway_calls (tenant_id, request_id, key_id, instance, person, kind, mcp_method, mcp_tool)
		VALUES ($1, $2, $3, 'analyst-intern-person-a', 'dev:person-a@example.invalid', 'mcp', 'tools/call', 'lookup')`
	// 11 input and 7 output tokens at 3 and 15 EUR per million: 0.000138 EUR, exactly.
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
	testdb.ExecIn(t, h.db.AppURL, tenant, insertKey, tenant, key)
	testdb.ExecIn(t, h.db.AppURL, tenant, insertModelCall, tenant, call, key)
	testdb.ExecIn(t, h.db.AppURL, tenant, insertUsage, tenant, call)
	return key, call
}

// sqlstate is the PostgreSQL error class, so each refusal is proven for the intended reason.
func sqlstate(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

const (
	checkViolation      = "23514"
	foreignKeyViolation = "23503"
	uniqueViolation     = "23505"
	insufficientPriv    = "42501"
	raised              = "P0001" // RAISE EXCEPTION in a trigger
)

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
		`UPDATE virtual_keys SET created_at = now() WHERE id = $1`,
		`DELETE FROM virtual_keys WHERE id = $1`,
	} {
		if err := testdb.ExecErr(app, a, stmt, key); sqlstate(err) != insufficientPriv {
			t.Errorf("%s: err = %v, want permission denied", stmt, err)
		}
	}
	// A revocation needs who and why; when is the database's.
	if err := testdb.ExecErr(app, a, `UPDATE virtual_keys SET status = 'revoked' WHERE id = $1`, key); sqlstate(err) != checkViolation {
		t.Errorf("revoking without revoked_by/reason: err = %v, want a check violation", err)
	}
	testdb.ExecIn(t, app, a, `UPDATE virtual_keys SET status = 'revoked', revoked_at = '2000-01-01',
		revoked_by = 'dev:owner@example.invalid', revoke_reason = 'leaver' WHERE id = $1`, key)
	if n := testdb.CountIn(t, app, a, `SELECT count(*) FROM virtual_keys WHERE id = $1 AND status = 'revoked'
		AND revoked_at > now() - interval '1 minute'`, key); n != 1 {
		t.Fatalf("revoked now (not backdated) = %d, want 1", n)
	}
	// Final, and its record immutable, whoever writes; only erasure's pseudonym may replace revoked_by.
	for _, url := range []string{app, h.db.OwnerURL} {
		for _, stmt := range []string{
			`UPDATE virtual_keys SET status = 'active', revoked_at = NULL, revoked_by = NULL, revoke_reason = NULL WHERE id = $1`,
			`UPDATE virtual_keys SET revoke_reason = 'something else' WHERE id = $1`,
			`UPDATE virtual_keys SET revoked_by = 'dev:someone-else@example.invalid' WHERE id = $1`,
			`UPDATE virtual_keys SET revoked_at = now() - interval '1 day' WHERE id = $1`,
		} {
			if err := testdb.ExecErr(url, a, stmt, key); sqlstate(err) != raised || !strings.Contains(err.Error(), "revocation is final") {
				t.Errorf("%s: err = %v, want revocation is final", stmt, err)
			}
		}
	}
	if err := testdb.ExecErr(app, a, `UPDATE virtual_keys SET revoked_by = 'erased:`+uuid.NewString()+`' WHERE id = $1`, key); err != nil {
		t.Errorf("pseudonymising revoked_by: %v", err)
	}

	// The call and usage ledgers are append-only.
	for _, stmt := range []string{
		`UPDATE gateway_calls SET input_per_mtok = 0 WHERE request_id = $1`,
		`DELETE FROM gateway_calls WHERE request_id = $1`,
		`UPDATE usage_records SET cost_amount = 0 WHERE request_id = $1`,
		`DELETE FROM usage_records WHERE request_id = $1`,
		// Deleting a call without usage would reset a key's cap.
		`UPDATE calls_without_usage SET recorded_at = now() WHERE request_id = $1`,
		`DELETE FROM calls_without_usage WHERE request_id = $1`,
		// Deleting a failed call would put it back in flight.
		`UPDATE failed_calls SET status_code = 500 WHERE request_id = $1`,
		`DELETE FROM failed_calls WHERE request_id = $1`,
	} {
		if err := testdb.ExecErr(app, a, stmt, call); sqlstate(err) != insufficientPriv {
			t.Errorf("%s: err = %v, want permission denied", stmt, err)
		}
	}
}

func TestGatewaySchemaStampsItsOwnTimes(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	key, _ := seedGateway(t, h, a)
	app := h.db.AppURL
	backdatedKey, backdatedCall := uuid.New(), uuid.New()
	testdb.ExecIn(t, app, a, strings.Replace(strings.Replace(insertKey, "secret_sha256, created_by)", "secret_sha256, created_by, created_at)", 1),
		"'dev:person-a@example.invalid')", "'dev:person-a@example.invalid', '2000-01-01')", 1), a, backdatedKey)
	testdb.ExecIn(t, app, a, strings.Replace(strings.Replace(insertModelCall, "output_per_mtok)", "output_per_mtok, authorized_at)", 1),
		"'EUR', 3, 15)", "'EUR', 3, 15, '2000-01-01')", 1), a, backdatedCall, key)
	for _, q := range []string{
		`SELECT count(*) FROM virtual_keys WHERE id = $1 AND created_at > now() - interval '1 minute'`,
		`SELECT count(*) FROM gateway_calls WHERE request_id = $1 AND authorized_at > now() - interval '1 minute'`,
	} {
		id := backdatedKey
		if strings.Contains(q, "gateway_calls") {
			id = backdatedCall
		}
		if n := testdb.CountIn(t, app, a, q, id); n != 1 {
			t.Errorf("%s: a backdated time was kept", q)
		}
	}
}

func TestGatewaySchemaPricesUsageAtProviderCostOnly(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	key, _ := seedGateway(t, h, a)
	app := h.db.AppURL
	call := func() uuid.UUID {
		id := uuid.New()
		testdb.ExecIn(t, app, a, insertModelCall, a, id, key)
		return id
	}
	mcp := uuid.New()
	testdb.ExecIn(t, app, a, insertMCPCall, a, mcp, key)
	for name, s := range map[string]struct {
		sql  string
		args []any
		code string
	}{
		"a marked-up cost":     {strings.Replace(insertUsage, "0.000138", "0.000139", 1), []any{a, call()}, raised},
		"a discounted cost":    {strings.Replace(insertUsage, "0.000138", "0.000100", 1), []any{a, call()}, raised},
		"another currency":     {strings.Replace(insertUsage, "'EUR')", "'USD')", 1), []any{a, call()}, raised},
		"usage on an MCP call": {insertUsage, []any{a, mcp}, raised},
		// Priced exactly, (5-6)*3 + 6*3 + 7*15 = 120 per million, so only the CHECK can refuse it.
		"more cached than input tokens": {`INSERT INTO usage_records (tenant_id, request_id, input_tokens, cached_input_tokens,
			output_tokens, cost_amount, cost_currency) VALUES ($1, $2, 5, 6, 7, 0.000120, 'EUR')`, []any{a, call()}, checkViolation},
	} {
		if err := testdb.ExecErr(app, a, s.sql, s.args...); sqlstate(err) != s.code {
			t.Errorf("%s: err = %v, want SQLSTATE %s", name, err, s.code)
		}
	}
	// Exact provider cost, cached tokens included (no cached rate in this snapshot: the input rate).
	testdb.ExecIn(t, app, a, `INSERT INTO usage_records (tenant_id, request_id, input_tokens, cached_input_tokens,
		output_tokens, cost_amount, cost_currency) VALUES ($1, $2, 11, 4, 7, 0.000138, 'EUR')`, a, call())
	// With a cached rate, cached tokens are billed at it: (7*3 + 4*0.3 + 7*15) / 1e6.
	cached := uuid.New()
	testdb.ExecIn(t, app, a, strings.Replace(strings.Replace(insertModelCall, "input_per_mtok, output_per_mtok)",
		"input_per_mtok, cached_input_per_mtok, output_per_mtok)", 1), "'EUR', 3, 15)", "'EUR', 3, 0.3, 15)", 1), a, cached, key)
	testdb.ExecIn(t, app, a, `INSERT INTO usage_records (tenant_id, request_id, input_tokens, cached_input_tokens,
		output_tokens, cost_amount, cost_currency) VALUES ($1, $2, 11, 4, 7, 0.0001272, 'EUR')`, a, cached)
}

func TestGatewaySchemaRefusesIncompleteRecords(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	key, call := seedGateway(t, h, a)
	app := h.db.AppURL
	fresh := func() uuid.UUID {
		id := uuid.New()
		testdb.ExecIn(t, app, a, insertModelCall, a, id, key)
		return id
	}
	for name, s := range map[string]struct {
		sql  string
		args []any
		code string
	}{
		"a key for an instance that does not exist":  {strings.Replace(insertKey, "'analyst-intern-person-a'", "'nobody'", 1), []any{a, uuid.New()}, foreignKeyViolation},
		"a key whose secret hash is not 32 bytes":    {strings.Replace(insertKey, "repeat('ab', 32)", "repeat('ab', 16)", 1), []any{a, uuid.New()}, checkViolation},
		"a key with no aliases":                      {strings.Replace(insertKey, "ARRAY['reasoning-default']", "ARRAY[]::text[]", 1), []any{a, uuid.New()}, checkViolation},
		"a key with a negative budget":               {strings.Replace(insertKey, ", 10, 'EUR'", ", -1, 'EUR'", 1), []any{a, uuid.New()}, checkViolation},
		"a key id reused":                            {insertKey, []any{a, key}, uniqueViolation},
		"a model call with no price snapshot":        {strings.Replace(insertModelCall, "'EUR', 3, 15", "NULL, NULL, NULL", 1), []any{a, uuid.New(), key}, checkViolation},
		"a call for an unknown key":                  {insertModelCall, []any{a, uuid.New(), uuid.New()}, foreignKeyViolation},
		"a call billed to another instance":          {strings.Replace(insertModelCall, "VALUES ($1, $2, $3, 'analyst-intern-person-a'", "VALUES ($1, $2, $3, 'someone-else'", 1), []any{a, uuid.New(), key}, foreignKeyViolation},
		"an MCP call with no method":                 {strings.Replace(insertMCPCall, "'tools/call'", "NULL", 1), []any{a, uuid.New(), key}, checkViolation},
		"usage for a call that was never authorized": {insertUsage, []any{a, uuid.New()}, raised},
		"a second usage record for one call":         {insertUsage, []any{a, call}, uniqueViolation},
		// Priced exactly, -1*3 + 7*15 = 102 per million, so only the CHECK can refuse it.
		"usage with negative tokens": {strings.Replace(strings.Replace(insertUsage, "11, 7", "-1, 7", 1), "0.000138", "0.000102", 1), []any{a, fresh()}, checkViolation},
	} {
		if err := testdb.ExecErr(app, a, s.sql, s.args...); sqlstate(err) != s.code {
			t.Errorf("%s: err = %v, want SQLSTATE %s", name, err, s.code)
		}
	}
}

func TestGatewayKeyTenantLookupRevealsOnlyTheTenant(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a, b := h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	keyA, _ := seedGateway(t, h, a)
	// The check holds only a key: with no tenant set, it learns the key's tenant and nothing else.
	if got := testdb.ScalarIn(t, h.db.AppURL, uuid.Nil, `SELECT virtual_key_tenant($1)::text`, keyA); got != a.String() {
		t.Errorf("tenant of A's key = %q, want %s", got, a)
	}
	if got := testdb.ScalarIn(t, h.db.AppURL, b, `SELECT coalesce(virtual_key_tenant($1)::text, 'none')`, uuid.New()); got != "none" {
		t.Errorf("unknown key resolved to %q", got)
	}
	// It is not a way to read keys: the table itself stays invisible without the tenant.
	if n := testdb.CountIn(t, h.db.AppURL, uuid.Nil, `SELECT count(*) FROM virtual_keys`); n != 0 {
		t.Errorf("keys visible with no tenant set: %d", n)
	}
}

func TestUsageEndpointListsCallsAndRefusesBadCursors(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a := h.tenant(t, "tenant-a")
	for _, path := range []string{"/v1/usage", "/v1/usage?unmetered=true&limit=10"} {
		if got := h.call(t, a, http.MethodGet, path, ""); got.status != http.StatusOK || !strings.Contains(got.raw, `"items":[]`) {
			t.Errorf("GET %s = %d: %s, want an empty page", path, got.status, got.raw)
		}
	}
	if got := h.call(t, a, http.MethodGet, "/v1/usage?cursor=%21%21", ""); got.status != http.StatusBadRequest && got.status != http.StatusUnprocessableEntity {
		t.Errorf("GET /v1/usage with a bad cursor = %d: %s", got.status, got.raw)
	}
}

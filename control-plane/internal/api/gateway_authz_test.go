//go:build authz

package api_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Tenant B, as the server's own role, attacks tenant A's virtual keys, authorized calls and usage.
// Never skip or weaken (AGENTS.md).
func TestAuthzGatewayRecordsAreTenantScoped(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	a, b := h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	keyA, callA := seedGateway(t, h, a)
	keyB, _ := seedGateway(t, h, b) // B has rows of its own, so "matches nothing" proves isolation
	app := h.db.AppURL

	for _, table := range []string{"virtual_keys", "gateway_calls", "usage_records"} {
		if n := testdb.CountIn(t, app, b, "SELECT count(*) FROM "+table+" WHERE tenant_id = $1", a); n != 0 {
			t.Errorf("%s: B sees %d of A's rows, want 0", table, n)
		}
		if n := testdb.CountIn(t, app, uuid.Nil, "SELECT count(*) FROM "+table); n != 0 {
			t.Errorf("%s: %d rows visible with no tenant set, want 0", table, n)
		}
	}

	// Planting rows in A fails on row-level security, though every value is otherwise valid.
	for name, s := range map[string]struct {
		sql  string
		args []any
	}{
		"a key for A's instance": {insertKey, []any{a, uuid.New()}},
		"a call on A's key":      {insertModelCall, []any{a, uuid.New(), keyA}},
		"usage on A's call":      {insertUsage, []any{a, callA}},
	} {
		err := testdb.ExecErr(app, b, s.sql, s.args...)
		if err == nil || !strings.Contains(err.Error(), "row-level security") {
			t.Errorf("%s as B: err = %v, want a row-level security violation", name, err)
		}
	}
	// B cannot bill a call to A's key from its own tenant either: the key does not exist for B.
	if err := testdb.ExecErr(app, b, insertModelCall, b, uuid.New(), keyA); err == nil {
		t.Error("B recorded a call against A's key")
	}

	// Revoking or retargeting A's key as B matches nothing; A's key stays active.
	if err := testdb.ExecErr(app, b, `UPDATE virtual_keys SET status = 'revoked', revoked_at = now(),
		revoked_by = 'x', revoke_reason = 'x' WHERE tenant_id = $1`, a); err != nil {
		t.Fatalf("UPDATE as B: %v", err)
	}
	if err := testdb.ExecErr(app, b, `UPDATE virtual_keys SET tenant_id = $1 WHERE id = $2`, a, keyB); err == nil ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("retarget B's key to A: err = %v, want permission denied", err)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM virtual_keys WHERE tenant_id = $1 AND status = 'active'`, a); n != 1 {
		t.Errorf("A's active keys = %d, want 1", n)
	}
}

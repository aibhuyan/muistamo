package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Migrations must upgrade databases that hold data, not only empty ones. 00012 backfills an
// identity row for every existing instance into a table with a deferred foreign key; the
// pending check must not block the row-level security ALTERs that follow.
func TestIdentityJournalUpgradesADatabaseWithInstances(t *testing.T) {
	db := testdb.NewAt(t, 11)
	tenant := uuid.New()
	testdb.Exec(t, db.OwnerURL, `INSERT INTO tenants (id, name) VALUES ($1, 'acme')`, tenant)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO agent_templates (tenant_id, name, latest_version) VALUES ($1, 'analyst-intern', 1)`, tenant)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO agent_template_versions (tenant_id, name, version, digest, document, created_by)
		VALUES ($1, 'analyst-intern', 1, 'seed', '{}', 'seed')`, tenant)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO agent_instances (tenant_id, name, template_name, template_version, state, revision, document)
		VALUES ($1, 'analyst-intern-person-a', 'analyst-intern', 1, 'active', 1, '{}')`, tenant)

	if err := store.Migrate(context.Background(), db.OwnerURL); err != nil {
		t.Fatalf("upgrade of a database with an instance: %v", err)
	}
	got := testdb.ScalarIn(t, db.OwnerURL, tenant, `SELECT provider_mode || ' ' || observed_state FROM instance_identities
		WHERE instance_name = 'analyst-intern-person-a'`)
	if got != "simulated simulated" {
		t.Fatalf("backfilled identity = %q, want simulated simulated", got)
	}
}

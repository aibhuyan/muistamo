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
// pending check must not block the row-level security ALTERs that follow. The backfill must also
// be complete when the owner is subject to row-level security (managed PostgreSQL), across
// tenants.
func TestIdentityJournalUpgradesADatabaseWithInstances(t *testing.T) {
	for name, at := range map[string]func(*testing.T, int64) testdb.DB{"superuser owner": testdb.NewAt, "restricted owner": testdb.NewRestrictedAt} {
		t.Run(name, func(t *testing.T) { upgradeWithInstances(t, at(t, 11)) })
	}
}

func upgradeWithInstances(t *testing.T, db testdb.DB) {
	tenants := []uuid.UUID{uuid.New(), uuid.New()}
	for i, tenant := range tenants {
		seedInstance(t, db, tenant, []string{"acme", "beta"}[i])
	}
	if err := store.Migrate(context.Background(), db.OwnerURL); err != nil {
		t.Fatalf("upgrade of a database with instances: %v", err)
	}
	// The backfill lifts FORCE on agent_instances only inside the migration.
	if forced := testdb.Scalar(t, db.OwnerURL, `SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 'agent_instances'`); forced != "true" {
		t.Fatalf("agent_instances FORCE ROW LEVEL SECURITY after upgrade = %s, want true", forced)
	}
	for _, tenant := range tenants {
		got := testdb.ScalarIn(t, db.OwnerURL, tenant, `SELECT provider_mode || ' ' || observed_state FROM instance_identities
			WHERE instance_name = 'analyst-intern-person-a'`)
		if got != "simulated simulated" {
			t.Fatalf("tenant %s backfilled identity = %q, want simulated simulated", tenant, got)
		}
	}
}

func seedInstance(t *testing.T, db testdb.DB, tenant uuid.UUID, name string) {
	t.Helper()
	testdb.Exec(t, db.OwnerURL, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenant, name)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO agent_templates (tenant_id, name, latest_version) VALUES ($1, 'analyst-intern', 1)`, tenant)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO agent_template_versions (tenant_id, name, version, digest, document, created_by)
		VALUES ($1, 'analyst-intern', 1, 'seed', '{}', 'seed')`, tenant)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO agent_instances (tenant_id, name, template_name, template_version, state, revision, document)
		VALUES ($1, 'analyst-intern-person-a', 'analyst-intern', 1, 'active', 1, '{}')`, tenant)
}

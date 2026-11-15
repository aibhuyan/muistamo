package store_test

import (
	"context"
	"strings"
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

// 00011 backfills occurred_at on every retained HR event before making it NOT NULL. Under a
// restricted owner, forced row-level security would hide the rows and fail the upgrade.
func TestHRDispatchUpgradesADatabaseWithEvents(t *testing.T) {
	for name, at := range map[string]func(*testing.T, int64) testdb.DB{"superuser owner": testdb.NewAt, "restricted owner": testdb.NewRestrictedAt} {
		t.Run(name, func(t *testing.T) {
			db := at(t, 10)
			tenant := uuid.New()
			testdb.Exec(t, db.OwnerURL, `INSERT INTO tenants (id, name) VALUES ($1, 'acme')`, tenant)
			testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO hr_events (tenant_id, event_id, type, person_id, workflow_id, payload)
				VALUES ($1, 'ev-1', 'joiner', 'P-1', 'joiner-ev-1', '{"occurredAt": "2026-10-01T09:00:00Z"}')`, tenant)
			if err := store.MigrateTo(context.Background(), db.OwnerURL, 11); err != nil {
				t.Fatalf("upgrade of a database with HR events: %v", err)
			}
			if got := testdb.ScalarIn(t, db.OwnerURL, tenant, `SELECT (occurred_at = '2026-10-01T09:00:00Z')::text FROM hr_events WHERE event_id = 'ev-1'`); got != "true" {
				t.Fatalf("backfilled occurred_at matches the event's source time = %s", got)
			}
			if forced := testdb.Scalar(t, db.OwnerURL, `SELECT relforcerowsecurity::text FROM pg_class WHERE relname = 'hr_events'`); forced != "true" {
				t.Fatalf("hr_events FORCE ROW LEVEL SECURITY after upgrade = %s, want true", forced)
			}
		})
	}
}

// 00021 records each enrolled tenant's Entra directory and makes it unique across tenants
// (docs/entra-directory-guard-plan.md). The backfill reads two tables with forced row-level
// security, so it must be complete under a restricted owner too.
func TestDirectoryGuardUpgradesEnrolledTenants(t *testing.T) {
	for name, at := range map[string]func(*testing.T, int64) testdb.DB{"superuser owner": testdb.NewAt, "restricted owner": testdb.NewRestrictedAt} {
		t.Run(name, func(t *testing.T) {
			db := at(t, 20)
			directories := map[uuid.UUID]uuid.UUID{}
			for _, tenantName := range []string{"acme", "beta"} {
				tenant, directory := uuid.New(), uuid.New()
				seedEnrollment(t, db, tenant, tenantName, directory)
				directories[tenant] = directory
			}
			if err := store.Migrate(context.Background(), db.OwnerURL); err != nil {
				t.Fatalf("upgrade of a database with enrolled tenants: %v", err)
			}
			for tenant, directory := range directories {
				if got := testdb.ScalarIn(t, db.OwnerURL, tenant, `SELECT entra_tenant_id::text FROM identity_enrollments WHERE tenant_id = $1`, tenant); got != directory.String() {
					t.Fatalf("tenant %s backfilled directory = %s, want %s", tenant, got, directory)
				}
			}
			for _, table := range []string{"identity_enrollments", "entra_bindings"} {
				if forced := testdb.Scalar(t, db.OwnerURL, `SELECT relforcerowsecurity::text FROM pg_class WHERE relname = $1`, table); forced != "true" {
					t.Fatalf("%s FORCE ROW LEVEL SECURITY after upgrade = %s, want true", table, forced)
				}
			}
		})
	}
}

// Two tenants already enrolled in one directory: the upgrade stops and changes nothing. It never
// chooses which tenant keeps the directory, and its error names neither tenant nor directory.
func TestDirectoryGuardRefusesToUpgradeADoubleEnrollment(t *testing.T) {
	for name, at := range map[string]func(*testing.T, int64) testdb.DB{"superuser owner": testdb.NewAt, "restricted owner": testdb.NewRestrictedAt} {
		t.Run(name, func(t *testing.T) {
			db := at(t, 20)
			directory := uuid.New()
			tenants := []uuid.UUID{uuid.New(), uuid.New()}
			for i, tenant := range tenants {
				seedEnrollment(t, db, tenant, []string{"acme", "beta"}[i], directory)
			}
			err := store.Migrate(context.Background(), db.OwnerURL)
			if err == nil {
				t.Fatal("upgraded a database where two tenants are enrolled in one directory")
			}
			if !strings.Contains(err.Error(), "1 Entra directory") {
				t.Fatalf("the refusal does not say why: %v", err)
			}
			for _, secret := range []string{directory.String(), tenants[0].String(), tenants[1].String()} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("the refusal names an identifier: %v", err)
				}
			}
			if n := testdb.Scalar(t, db.OwnerURL, `SELECT count(*)::text FROM information_schema.columns WHERE table_name = 'identity_enrollments' AND column_name = 'entra_tenant_id'`); n != "0" {
				t.Fatal("the refused upgrade left the new column behind")
			}
			for _, table := range []string{"identity_enrollments", "entra_bindings"} {
				if forced := testdb.Scalar(t, db.OwnerURL, `SELECT relforcerowsecurity::text FROM pg_class WHERE relname = $1`, table); forced != "true" {
					t.Fatalf("%s FORCE ROW LEVEL SECURITY after the refused upgrade = %s, want true", table, forced)
				}
			}
		})
	}
}

func seedEnrollment(t *testing.T, db testdb.DB, tenant uuid.UUID, name string, directory uuid.UUID) {
	t.Helper()
	version := uuid.New()
	testdb.Exec(t, db.OwnerURL, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenant, name)
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO entra_bindings (tenant_id, binding_version, config_digest, entra_tenant_id, blueprint_app_id)
		VALUES ($1, $2, repeat('0', 64), $3, $4)`, tenant, version, directory, uuid.New())
	testdb.ExecIn(t, db.OwnerURL, tenant, `INSERT INTO identity_enrollments (tenant_id, binding_version) VALUES ($1, $2)`, tenant, version)
}

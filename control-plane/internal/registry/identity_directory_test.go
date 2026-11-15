package registry_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// enrolledDirectory enrols the fixture's tenant in a directory and returns a second tenant whose
// registered, not yet enrolled, binding names the same directory.
func enrolledDirectory(t *testing.T, f fixture) (first muistamov1.EntraIdentityBinding, second registry.Actor, same muistamov1.EntraIdentityBinding) {
	t.Helper()
	ctx := context.Background()
	first = identityBinding(f.actor.Tenant)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, first); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnrollIdentityTenant(ctx, f.actor, uuid.MustParse(first.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	tenant, err := store.CreateTenant(ctx, f.db.OwnerURL, "second")
	if err != nil {
		t.Fatal(err)
	}
	second = f.actor
	second.Tenant = tenant
	same = identityBinding(tenant)
	same.EntraTenantId = first.EntraTenantId
	// Registering is not refused: a binding that is not enrolled is inert.
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, second, same); err != nil {
		t.Fatalf("register a binding for a directory another tenant enrolled: %v", err)
	}
	return first, second, same
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

func constraintOf(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.ConstraintName
	}
	return ""
}

// One Entra directory is enrolled by at most one tenant (docs/entra-directory-guard-plan.md): a
// token's directory must never name two tenants.
func TestADirectoryIsEnrolledByOneTenantOnly(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	first, second, same := enrolledDirectory(t, f)
	before, err := f.svc.IdentityEnrollment(ctx, f.actor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.EnrollIdentityTenant(ctx, second, uuid.MustParse(same.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("a second tenant enrolled the same directory: %v", err)
	}
	if _, err := f.svc.IdentityEnrollment(ctx, second); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("the refused tenant has an enrollment: %v", err)
	}
	if n := testdb.CountIn(t, f.db.AppURL, second.Tenant, `SELECT count(*) FROM evidence_events WHERE action = 'identity.tenant-enrolled'`); n != 0 {
		t.Fatalf("the refused enrollment left %d evidence events", n)
	}
	after, err := f.svc.IdentityEnrollment(ctx, f.actor)
	if err != nil || after != before {
		t.Fatalf("the first tenant's enrollment changed: %+v, was %+v (%v)", after, before, err)
	}
	if got := testdb.ScalarIn(t, f.db.AppURL, f.actor.Tenant, `SELECT entra_tenant_id::text FROM identity_enrollments`); got != first.EntraTenantId {
		t.Fatalf("enrolled directory = %s, want the binding's %s", got, first.EntraTenantId)
	}

	// The refusal does not strand the second tenant: its own directory still enrols.
	own := identityBinding(second.Tenant)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, second, own); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnrollIdentityTenant(ctx, second, uuid.MustParse(own.BindingVersion)); err != nil {
		t.Fatalf("a tenant with its own directory was refused: %v", err)
	}
}

// The rule is the database's, not only the service's: the application role cannot write a second
// enrollment for a directory, nor an enrollment whose directory is not its binding's.
func TestTheDatabaseRefusesASecondTenantForADirectory(t *testing.T) {
	f := setup(t)
	_, second, same := enrolledDirectory(t, f)
	insert := func(directory string) error {
		return testdb.ExecErr(f.db.AppURL, second.Tenant, fmt.Sprintf(
			"INSERT INTO identity_enrollments(tenant_id,binding_version,entra_tenant_id) VALUES('%s','%s',%s)", second.Tenant, same.BindingVersion, directory))
	}
	if err := insert("'" + same.EntraTenantId + "'"); constraintOf(err) != "identity_enrollment_one_tenant_per_directory" {
		t.Fatalf("duplicate directory: %v", err)
	}
	if err := insert("'" + uuid.NewString() + "'"); constraintOf(err) != "identity_enrollment_directory" {
		t.Fatalf("a directory that is not the binding's: %v", err)
	}
	if err := insert("NULL"); err == nil {
		t.Fatal("an enrollment without a directory was accepted")
	}
	if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, fmt.Sprintf("UPDATE identity_enrollments SET entra_tenant_id='%s'", uuid.NewString())); err == nil {
		t.Fatal("the application role changed an enrolled directory")
	}
}

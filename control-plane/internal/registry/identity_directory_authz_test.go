//go:build authz

package registry_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Tenant B tries to enrol the Entra directory tenant A is enrolled in, through the service and
// then directly as the application role. Either would let one directory's tokens name two
// tenants. Never skip or weaken (AGENTS.md).
func TestAuthzADirectoryBelongsToOneTenant(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	_, b, same := enrolledDirectory(t, f)
	if _, err := f.svc.EnrollIdentityTenant(ctx, b, uuid.MustParse(same.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("B enrolled A's directory: %v", err)
	}
	err := testdb.ExecErr(f.db.AppURL, b.Tenant, fmt.Sprintf(
		"INSERT INTO identity_enrollments(tenant_id,binding_version,entra_tenant_id) VALUES('%s','%s','%s')", b.Tenant, same.BindingVersion, same.EntraTenantId))
	if constraintOf(err) != "identity_enrollment_one_tenant_per_directory" {
		t.Fatalf("B wrote an enrollment for A's directory: %v", err)
	}
	if n := testdb.CountIn(t, f.db.AppURL, b.Tenant, `SELECT count(*) FROM identity_enrollments`); n != 0 {
		t.Fatalf("B has %d enrollments", n)
	}
}

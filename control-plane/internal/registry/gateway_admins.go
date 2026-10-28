package registry

// HUMAN REVIEW REQUIRED: operator-only credential administration and the erasure fence.

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// ConfigureGatewayAdmins runs only with the operator's database-owner credentials. The server
// role has no write grant on gateway_admins. The change and its evidence commit atomically.
func ConfigureGatewayAdmins(ctx context.Context, ownerURL string, actor Actor, admins []string, signer evidence.Signer) error {
	if actor.Tenant == uuid.Nil || strings.TrimSpace(actor.Name) == "" || actor.RequestID == "" {
		return fmt.Errorf("tenant, operator and request id are required: %w", ErrInvalid)
	}
	if signer == nil {
		return ErrEvidence
	}
	names := slices.Clone(admins)
	slices.Sort(names)
	for i, name := range names {
		if len(name) < 3 || strings.TrimSpace(name) != name || strings.HasPrefix(name, "erased:") || (i > 0 && names[i-1] == name) {
			return fmt.Errorf("administrators must be distinct nonempty identities: %w", ErrInvalid)
		}
	}
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return fmt.Errorf("connect gateway administration: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, actor.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return store.ErrUnknownTenant
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id',$1,true)`, actor.Tenant.String()); err != nil {
			return err
		}
		// Exclusive: serialize configuration with key writes, other changes and erasure.
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, true); err != nil {
			return err
		}
		for _, name := range names {
			keys := []string{store.HRFenceKey(actor.Tenant, "identifier", name), store.HRFenceKey(actor.Tenant, "identifier", strings.TrimPrefix(name, "dev:"))}
			at, err := store.HRFenceTime(ctx, tx, keys)
			if err != nil {
				return err
			}
			if at != nil {
				return fmt.Errorf("an erased identity cannot become a gateway administrator: %w", ErrConflict)
			}
		}
		before := []string{}
		// Owner connections bypass RLS, so every operator query also scopes explicitly.
		rows, err := tx.Query(ctx, `SELECT admin FROM gateway_admins WHERE tenant_id=$1 ORDER BY admin`, actor.Tenant)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			before = append(before, name)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gateway_admins WHERE tenant_id=$1`, actor.Tenant); err != nil {
			return fmt.Errorf("replace gateway administrators: %w", err)
		}
		for _, name := range names {
			if _, err := tx.Exec(ctx, `INSERT INTO gateway_admins(tenant_id,admin) VALUES($1,$2)`, actor.Tenant, name); err != nil {
				return fmt.Errorf("store gateway administrator: %w", err)
			}
		}
		return recordEvidence(ctx, tx, signer, actor, "gateway.admins.configured", "GatewayAdminSet", actor.Tenant.String(),
			map[string]any{"admins": before}, map[string]any{"admins": names})
	})
}

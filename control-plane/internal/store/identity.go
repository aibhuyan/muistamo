package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// IdentityEnrollmentVersion reads the persisted tenant mode while the caller holds the
// privacy boundary. Absence means simulation; database/configuration errors never do.
func IdentityEnrollmentVersion(ctx context.Context, tx pgx.Tx) (*uuid.UUID, error) {
	var version uuid.UUID
	err := tx.QueryRow(ctx, `SELECT binding_version FROM identity_enrollments`).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read identity enrollment: %w", err)
	}
	return &version, nil
}

// HRIdentityRoute reads only committed receipt metadata, never a worker environment flag.
func HRIdentityRoute(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, eventID string) (muistamov1.HRIdentityRoute, error) {
	route := muistamov1.HRIdentityRoute{TenantId: tenant}
	err := tx.QueryRow(ctx, `SELECT receipt_id,identity_mode,identity_binding_version FROM hr_events WHERE event_id=$1`, eventID).Scan(&route.ReceiptId, &route.ProviderMode, &route.BindingVersion)
	return route, err
}

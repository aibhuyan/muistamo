package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// LockHRPrivacy serializes erasure with HR acceptance and durable handoff intents. All callers
// take this tenant lock before person/row locks. Hash collisions only conservatively serialize.
func LockHRPrivacy(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, exclusive bool) error {
	query := `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`
	if exclusive {
		query = `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`
	}
	if _, err := tx.Exec(ctx, query, "hr-privacy/"+tenant.String()); err != nil {
		return fmt.Errorf("lock HR privacy boundary: %w", err)
	}
	return nil
}

// HRFenceKey correlates a known HR person or alias to a retained erasure proof without storing
// that raw identifier. It is a data digest, not a change to evidence signing or chain format.
func HRFenceKey(tenant uuid.UUID, kind, value string) string {
	sum := sha256.Sum256([]byte(tenant.String() + "\x00" + kind + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

// HRFenceTime reads the latest retained erasure boundary for known scoped keys.
func HRFenceTime(ctx context.Context, tx pgx.Tx, keys []string) (*time.Time, error) {
	var at *time.Time
	err := tx.QueryRow(ctx, `SELECT max(completed_at) FROM erasure_requests WHERE proof->'hrFenceKeys' ?| $1::text[]`, keys).Scan(&at)
	return at, err
}

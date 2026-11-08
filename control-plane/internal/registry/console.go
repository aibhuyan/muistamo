package registry

// HUMAN REVIEW REQUIRED (AGENTS.md): authorisation. Which app ids the tenant's console uses at the
// control plane (migration 00020).

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrUnavailable is a check that could not be made (a directory's keys or the database could not
// be reached): the request is refused as "try again", never as "not allowed".
var ErrUnavailable = errors.New("a required check could not be made")

type requestIDKey struct{}

// WithRequestID carries the server's request id to code that runs before the actor exists.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFrom returns the request id WithRequestID set, or "".
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// ConsoleClient is the tenant's console app (a token's azp) and its control-plane API app (aud).
type ConsoleClient struct {
	ClientApp uuid.UUID
	APIApp    uuid.UUID
}

// ConsoleClientOf returns the tenant's console client, or ok=false when it has none (its console
// callers are then refused).
func (s *Service) ConsoleClientOf(ctx context.Context, tenant uuid.UUID) (ConsoleClient, bool, error) {
	var c ConsoleClient
	found := false
	err := s.db.InTenant(ctx, tenant, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT client_app, api_app FROM console_clients`).Scan(&c.ClientApp, &c.APIApp)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read console client: %w", err)
		}
		found = true
		return nil
	})
	return c, found, err
}

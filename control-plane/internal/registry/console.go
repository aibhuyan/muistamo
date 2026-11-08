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

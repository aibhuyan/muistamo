// Package store owns the control plane's PostgreSQL access.
//
// Every query against tenant data runs inside InTenant, which sets muistamo.tenant_id for the
// transaction only. Row-level security does the filtering; nothing here adds tenant predicates,
// so a forgotten predicate cannot widen access.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrUnknownTenant means the tenant id does not exist.
var ErrUnknownTenant = errors.New("unknown tenant")

// DB is the server's connection pool. It must connect as a role that is a member of
// muistamo_app and does not own the tables.
type DB struct {
	pool *pgxpool.Pool
}

// Open connects and verifies the connection.
func Open(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &DB{pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.pool.Close() }

// InTenant runs fn in a transaction that row-level security scopes to tenant. The transaction
// commits only if fn returns nil.
func (db *DB) InTenant(ctx context.Context, tenant uuid.UUID, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, tenant).Scan(&exists); err != nil {
			return fmt.Errorf("check tenant: %w", err)
		}
		if !exists {
			return ErrUnknownTenant
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id', $1, true)`, tenant.String()); err != nil {
			return fmt.Errorf("scope transaction to tenant: %w", err)
		}
		return fn(tx)
	})
}

// Migrate applies all pending migrations. url must connect as the table owner.
func Migrate(ctx context.Context, url string) error {
	config, err := pgx.ParseConfig(url)
	if err != nil {
		return fmt.Errorf("parse migrate url: %w", err)
	}
	sqlDB := stdlib.OpenDB(*config)
	defer func() { _ = sqlDB.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrationsFS())
	if err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

// RegisterSigningKey records an evidence signing key's public half. url must connect as the
// table owner; the server role can only read keys.
func RegisterSigningKey(ctx context.Context, url, keyID string, public []byte) error {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `INSERT INTO evidence_signing_keys (key_id, algorithm, public_key) VALUES ($1, 'ed25519', $2)`,
		keyID, public); err != nil {
		return fmt.Errorf("register signing key %s: %w", keyID, err)
	}
	return nil
}

// SetHRSecret stores a tenant's HR webhook secret. url must connect as the table owner; the
// server role can only read secrets. An existing secret is not replaced (rotation is not built).
func SetHRSecret(ctx context.Context, url string, tenant uuid.UUID, secret []byte) error {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `INSERT INTO hr_webhook_secrets (tenant_id, secret) VALUES ($1, $2)`, tenant, secret); err != nil {
		return fmt.Errorf("store HR secret for tenant %s: %w", tenant, err)
	}
	return nil
}

// SetKnowledgeSecret stores the secret the leaver workflow signs knowledge-service calls with.
// url must connect as the table owner.
func SetKnowledgeSecret(ctx context.Context, url string, tenant uuid.UUID, secret []byte) error {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO knowledge_service_secrets (tenant_id, secret) VALUES ($1, $2)
			ON CONFLICT (tenant_id) DO UPDATE SET secret = EXCLUDED.secret, created_at = now()`, tenant, secret); err != nil {
			return fmt.Errorf("store knowledge secret for tenant %s: %w", tenant, err)
		}
		return nil
	})
}

// SetCatalogueApprovers replaces a tenant's catalogue approver list. url must connect as the
// table owner: the server role can read approvers but never change them.
func SetCatalogueApprovers(ctx context.Context, url string, tenant uuid.UUID, approvers []string) error {
	return replaceTenantList(ctx, url, tenant, "catalogue_approvers", "approver", approvers)
}

// SetPrivacyOfficers replaces the tenant's privacy officers, who may file erasure and access
// requests (FR-309). Like the approver list, only an operator changes it, as owner.
func SetPrivacyOfficers(ctx context.Context, url string, tenant uuid.UUID, officers []string) error {
	return replaceTenantList(ctx, url, tenant, "privacy_officers", "officer", officers)
}

// replaceTenantList replaces one tenant's rows in a (tenant_id, value) table. table and column are
// constants from this package, never input.
func replaceTenantList(ctx context.Context, url string, tenant uuid.UUID, table, column string, values []string) error {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE tenant_id = $1`, tenant); err != nil {
			return fmt.Errorf("clear %s: %w", table, err)
		}
		for _, v := range values {
			if _, err := tx.Exec(ctx, `INSERT INTO `+table+` (tenant_id, `+column+`) VALUES ($1, $2)`, tenant, v); err != nil {
				return fmt.Errorf("add %s %q: %w", column, v, err)
			}
		}
		return nil
	})
}

// SigningKeyRegistered reports whether keyID is a registered evidence signing key.
func (db *DB) SigningKeyRegistered(ctx context.Context, keyID string) (bool, error) {
	var ok bool
	if err := db.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM evidence_signing_keys WHERE key_id = $1)`, keyID).Scan(&ok); err != nil {
		return false, fmt.Errorf("check signing key: %w", err)
	}
	return ok, nil
}

func migrationsFS() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(fmt.Errorf("embedded migrations: %w", err))
	}
	return sub
}

// CreateTenant inserts a tenant. url must connect as the table owner; the server role cannot.
func CreateTenant(ctx context.Context, url, name string) (uuid.UUID, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return uuid.Nil, fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	id := uuid.New()
	if _, err := conn.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, id, name); err != nil {
		return uuid.Nil, fmt.Errorf("create tenant %q: %w", name, err)
	}
	return id, nil
}

// Package testdb gives tests a freshly migrated database in the dev PostgreSQL cluster.
//
// It fails the test when PostgreSQL is unreachable; it never skips. Start it with `make dev`
// (or let `make test` do it).
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// Obviously fake credentials for the test-only login role.
const (
	appUser     = "muistamo_server_test"
	appPassword = "test-only-not-a-secret"
)

// DB describes one throwaway database.
type DB struct {
	// OwnerURL connects as the table owner, which bypasses row-level security.
	OwnerURL string
	// AppURL connects as a member of muistamo_app, exactly as the server does.
	AppURL string
}

// New creates, migrates and (on cleanup) drops a database.
func New(t *testing.T) DB {
	t.Helper()
	ctx := context.Background()
	admin := os.Getenv("MUISTAMO_TEST_DATABASE_URL")
	if admin == "" {
		admin = "postgres://muistamo:dev-only-not-a-secret@127.0.0.1:5432/muistamo"
	}

	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("PostgreSQL unreachable at MUISTAMO_TEST_DATABASE_URL (run make dev): %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	if err := ensureRoles(ctx, conn); err != nil {
		t.Fatalf("ensure roles: %v", err)
	}

	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "muistamo_test_" + hex.EncodeToString(suffix)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), admin)
		if err != nil {
			t.Errorf("drop database %s: %v", name, err)
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		if _, err := c.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
	})

	db := DB{OwnerURL: withDatabase(t, admin, name, nil), AppURL: withDatabase(t, admin, name, url.UserPassword(appUser, appPassword))}
	if err := store.Migrate(ctx, db.OwnerURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// ensureRoles creates the cluster-wide roles once. Test packages run in parallel, so it holds
// an advisory lock and tolerates a concurrent creator.
func ensureRoles(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(727001)"); err != nil {
		return fmt.Errorf("lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(727001)") }()

	statements := []string{
		"CREATE ROLE muistamo_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE",
		fmt.Sprintf("CREATE ROLE %s LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '%s' IN ROLE muistamo_app", appUser, appPassword),
	}
	for _, stmt := range statements {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "42710" { // duplicate_object
				continue
			}
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

func withDatabase(t *testing.T, base, database string, user *url.Userinfo) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse MUISTAMO_TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + database
	if user != nil {
		u.User = user
	}
	return u.String()
}

// Exec runs one statement against url, failing the test on error.
func Exec(t *testing.T, url, sql string, args ...any) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// SigningKey creates an evidence signing key and registers it in db.
func SigningKey(t *testing.T, db DB) evidence.LocalKey {
	t.Helper()
	key, _, err := evidence.GenerateLocalKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterSigningKey(context.Background(), db.OwnerURL, key.KeyID(), key.Public()); err != nil {
		t.Fatal(err)
	}
	return key
}

// ExecErr runs one statement against url inside a transaction scoped to tenant (none when
// tenant is uuid.Nil), rolls it back, and returns the statement's error.
func ExecErr(url string, tenant uuid.UUID, sql string, args ...any) error {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tenant != uuid.Nil {
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id', $1, true)`, tenant.String()); err != nil {
			return fmt.Errorf("set tenant: %w", err)
		}
	}
	_, err = tx.Exec(ctx, sql, args...)
	return err
}

// CountIn returns SELECT count(*) for query, run against url in a transaction scoped to tenant
// (none when tenant is uuid.Nil).
func CountIn(t *testing.T, url string, tenant uuid.UUID, query string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tenant != uuid.Nil {
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id', $1, true)`, tenant.String()); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
	}
	var n int
	if err := tx.QueryRow(ctx, query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// Scalar returns a single text value for query, run against url.
func Scalar(t *testing.T, url, query string, args ...any) string {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var v string
	if err := conn.QueryRow(context.Background(), query, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

// Count returns SELECT count(*) for query, run against url.
func Count(t *testing.T, url, query string, args ...any) int {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var n int
	if err := conn.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// ApprovedModelAlias gives tenant an approved catalogue model and an alias on it, so templates
// naming alias can be published (E5.4). It writes as the owner, standing in for an operator
// and a privacy officer; tests of the approval rules themselves go through the API.
func ApprovedModelAlias(t *testing.T, ownerURL string, tenant uuid.UUID, alias string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	model := alias + "-model"
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO model_catalogue (tenant_id, name, revision, digest, document, approval_status,
			decided_by, decision_reason, decided_at, updated_by)
			VALUES ($1, $2, 1, 'seed', jsonb_build_object('apiVersion', 'muistamo.dev/v1', 'kind', 'ModelCatalogueItem',
			  'metadata', jsonb_build_object('name', $2::text),
			  'spec', jsonb_build_object('provider', 'test', 'model', 'test-model', 'region', 'eu-test', 'termsRef', 'test-terms',
			    'priceSheet', jsonb_build_object('currency', 'EUR', 'inputPerMTok', 0, 'outputPerMTok', 0))),
			  'approved', 'seed:privacy-officer', 'test fixture', now(), 'seed:operator')
			ON CONFLICT DO NOTHING`, tenant, model); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO model_aliases (tenant_id, name, target, revision, digest, document, updated_by)
			VALUES ($1, $2, $3, 1, 'seed', jsonb_build_object('apiVersion', 'muistamo.dev/v1', 'kind', 'ModelAlias',
			  'metadata', jsonb_build_object('name', $2::text), 'spec', jsonb_build_object('target', $3::text)), 'seed:operator')
			ON CONFLICT DO NOTHING`, tenant, alias, model)
		return err
	})
	if err != nil {
		t.Fatalf("seed approved model alias %s: %v", alias, err)
	}
}

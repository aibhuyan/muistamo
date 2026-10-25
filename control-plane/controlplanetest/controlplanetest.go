// Package controlplanetest starts a real control plane on a throwaway database, for tests outside
// the control-plane tree (the Terraform provider's acceptance tests). It is test support only.
package controlplanetest

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Server is a running control plane that trusts the development identity headers.
type Server struct {
	URL      string
	Tenant   uuid.UUID
	OwnerURL string
}

// New starts a control plane with one tenant. It fails, never skips, without PostgreSQL.
func New(t *testing.T) Server {
	t.Helper()
	db := testdb.New(t)
	ctx := context.Background()
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	tenant, err := store.CreateTenant(ctx, db.OwnerURL, "terraform-test")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.Handler(registry.New(conn, testdb.SigningKey(t, db)), api.InsecureDevHeaders{}, nil,
		slog.New(slog.DiscardHandler)))
	t.Cleanup(srv.Close)
	return Server{URL: srv.URL, Tenant: tenant, OwnerURL: db.OwnerURL}
}

// SetCatalogueApprovers replaces the tenant's catalogue approvers.
func (s Server) SetCatalogueApprovers(t *testing.T, approvers ...string) {
	t.Helper()
	if err := store.SetCatalogueApprovers(context.Background(), s.OwnerURL, s.Tenant, approvers); err != nil {
		t.Fatal(err)
	}
}

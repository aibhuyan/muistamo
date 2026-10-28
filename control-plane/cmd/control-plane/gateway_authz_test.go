package main

import (
	"strings"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/gateway"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestGatewayConfigRejectsUnknownFieldsAndInvalidRoutes(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"tenantId":"bad","models":[]}`,
		`{"tenantId":"11111111-1111-4111-8111-111111111111","models":[],"secret":"fake-secret"}`,
	} {
		if _, err := parseGatewayConfig([]byte(raw)); err == nil {
			t.Errorf("invalid gateway config accepted: %s", raw)
		}
	}
	a := muistamov1.GatewayAuthzConfig{}
	a.Models = []muistamov1.GatewayModelRoute{{Alias: "a", Model: "model-a"}}
	b := a
	b.Models = []muistamov1.GatewayModelRoute{{Alias: "a", Model: "model-b"}}
	if gateway.ConfigDigest(a) == gateway.ConfigDigest(b) {
		t.Fatal("route target change did not change fingerprint")
	}
}

func TestGatewayAuthorizationRequiresExplicitDevelopmentMode(t *testing.T) {
	cmd := gatewayAuthorizationCmd()
	cmd.SetArgs([]string{"--config", "unused.json"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "requires --insecure-development") {
		t.Fatalf("unapproved production mode started or development gate was skipped: %v", err)
	}
}

func TestGatewayDatabaseRoleCannotBypassRLS(t *testing.T) {
	db := testdb.New(t)
	for _, c := range []struct {
		url   string
		allow bool
	}{{db.AppURL, true}, {db.OwnerURL, false}} {
		conn, err := store.Open(t.Context(), c.url)
		if err != nil {
			t.Fatal(err)
		}
		err = conn.RequireApplicationRole(t.Context())
		conn.Close()
		if (err == nil) != c.allow {
			t.Errorf("database role check allow=%v err=%v", c.allow, err)
		}
	}
}

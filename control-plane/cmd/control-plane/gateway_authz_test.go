package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/gateway"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
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

func TestGatewayRenderWritesTheCheckersDigestAndReplacesWhole(t *testing.T) {
	dir := t.TempDir()
	cfgPath, out := filepath.Join(dir, "authz.json"), filepath.Join(dir, "agentgateway.yaml")
	raw := `{"tenantId":"6f19b972-b333-446e-802b-d8145231a2ac","models":[{"alias":"reasoning-default","aliasRevision":1,"catalogueName":"fake-model","modelRevision":1,"provider":"openai","model":"test-model","region":"eu-test","baseUrl":"http://provider:18080/v1","credentialEnv":"FAKE_PROVIDER_KEY"}]}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := gatewayRenderCmd()
	cmd.SetArgs([]string{"--config", cfgPath, "--authz-host", "authz:18081", "--out", out})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseGatewayConfig([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "stale") || !strings.Contains(string(got), gateway.ConfigDigest(cfg)) || !strings.Contains(string(got), "failureMode: deny") {
		t.Fatalf("rendered file:\n%s", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestGatewayRenderRefusesACredentialValue(t *testing.T) {
	raw := `{"tenantId":"6f19b972-b333-446e-802b-d8145231a2ac","models":[{"alias":"a","aliasRevision":1,"catalogueName":"c","modelRevision":1,"provider":"openai","model":"m","region":"r","baseUrl":"http://p/v1","credentialEnv":"sk-fake-value"}]}`
	if _, err := parseGatewayConfig([]byte(raw)); err == nil {
		t.Fatal("a credential value was accepted as a reference")
	}
}

func TestWorkerRevokesRealKeys(t *testing.T) {
	svc := registry.New(nil, evidence.LocalKey{})
	legacy := workerActivities(svc, &lifecycle.Simulated{})
	live := entraWorkerActivities(svc, nil)
	for name, r := range map[string]lifecycle.Revoker{"legacy": legacy.Revoker, "entra": live.Revoker} {
		if k, ok := r.(lifecycle.KeyRevoker); !ok || k.Registry != svc {
			t.Errorf("%s worker revoker = %T, want the registry's KeyRevoker", name, r)
		}
	}
}

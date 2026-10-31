package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func workerBindingFile(t *testing.T) string {
	t.Helper()
	b := muistamov1.EntraIdentityBinding{TenantId: uuid.NewString(), BindingVersion: uuid.NewString(), EntraTenantId: uuid.NewString(), BlueprintAppId: uuid.NewString(), BlueprintObjectId: uuid.NewString(), BlueprintPrincipalId: uuid.NewString(), SponsorUserIds: []string{uuid.NewString()}, CredentialRef: "fake-test-vault-ref", CredentialVersion: "fake-test-version"}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "binding.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWorkerEntraRequiresExplicitPrivateInput(t *testing.T) {
	path := workerBindingFile(t)
	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("obviously-fake-local-development-secret\n"))
	if _, err := readEntraWorkerBindings(cmd, []string{path}, false); err == nil {
		t.Fatal("worker accepted credential input without explicit development flag")
	}
	if _, err := readEntraWorkerBindings(cmd, nil, true); err == nil {
		t.Fatal("private credential flag accepted without an explicit binding")
	}
	cmd.SetIn(strings.NewReader("\n"))
	if _, err := readEntraWorkerBindings(cmd, []string{path}, true); err == nil {
		t.Fatal("empty credential accepted")
	}
}

func TestWorkerEntraCredentialsStayOutOfOutput(t *testing.T) {
	path := workerBindingFile(t)
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	secret := "obviously-fake-local-development-secret"
	cmd.SetIn(strings.NewReader(secret + "\n"))
	bindings, err := readEntraWorkerBindings(cmd, []string{path}, true)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("explicit private worker configuration: count=%d err=%v", len(bindings), err)
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("credential was printed")
	}
	cmd.SetIn(strings.NewReader(secret + "\n" + secret + "\n"))
	if _, err := readEntraWorkerBindings(cmd, []string{path, path}, true); err == nil {
		t.Fatal("duplicate binding version accepted")
	}
}

func TestWorkerEntraRequiresEnrolledHistoricalConfiguration(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	tenant, err := store.CreateTenant(ctx, db.OwnerURL, "worker-config")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	service := registry.New(conn, testdb.SigningKey(t, db))
	path := workerBindingFile(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b muistamov1.EntraIdentityBinding
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.TenantId = tenant.String()
	raw, err = json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	load := func() []workerEntraBinding {
		t.Helper()
		cmd := &cobra.Command{}
		cmd.SetIn(strings.NewReader("obviously-fake-credential\n"))
		configs, err := readEntraWorkerBindings(cmd, []string{path}, true)
		if err != nil {
			t.Fatal(err)
		}
		return configs
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := validateEntraWorkerBindings(ctx, service, load()); err == nil {
		t.Fatal("worker started without persisted enrollment")
	}
	// serve's delegations take the same checks: only an enrolled binding validates tokens.
	if _, err := entraDelegator(ctx, service, load(), quiet); err == nil {
		t.Fatal("delegations served without persisted enrollment")
	}
	actor := registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: "worker-config"}
	if _, _, err := service.RegisterIdentityBinding(ctx, actor, b); err != nil {
		t.Fatal(err)
	}
	if _, err := service.EnrollIdentityTenant(ctx, actor, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEntraWorkerBindings(ctx, service, load()); err != nil {
		t.Fatalf("exact enrolled binding refused: %v", err)
	}
	if _, err := entraDelegator(ctx, service, load(), quiet); err != nil {
		t.Fatalf("delegations refused the exact enrolled binding: %v", err)
	}
	for _, field := range []string{"version", "digest"} {
		changed := b
		if field == "version" {
			changed.BindingVersion = uuid.NewString()
		} else {
			changed.CredentialVersion = "different-version"
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := validateEntraWorkerBindings(ctx, service, load()); err == nil {
			t.Fatalf("worker started with mismatched historical %s", field)
		}
		if _, err := entraDelegator(ctx, service, load(), quiet); err == nil {
			t.Fatalf("delegations served with mismatched %s", field)
		}
	}
}

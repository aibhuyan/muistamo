package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestEntraCommandRejectsUnscopedOrUnsafeInput(t *testing.T) {
	for _, args := range [][]string{
		{"status"},
		{"status", "--instance", "test", "--operation", uuid.NewString()},
		{"status", "--instance", "test", "--tenant", "invalid", "--actor", "operator"},
		{"status", "--instance", "test", "--tenant", uuid.NewString()},
		{"reconcile", "--operation", uuid.NewString()},
		{"reconcile", "--credential-stdin", "--operation", "invalid"},
		{"reconcile", "--provider-id", uuid.NewString()},
	} {
		cmd := entraCmd()
		cmd.SetArgs(args)
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err == nil {
			t.Fatalf("unsafe command accepted: %v", args)
		}
	}
}

func TestEntraStatusIsTenantScopedAndNeedsNoSigner(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	tenant, err := store.CreateTenant(ctx, db.OwnerURL, "status-test")
	if err != nil {
		t.Fatal(err)
	}
	other, err := store.CreateTenant(ctx, db.OwnerURL, "other")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	testdb.ApprovedModelAlias(t, db.OwnerURL, tenant, "reasoning-default")
	svc := registry.New(conn, key)
	actor := registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: "status-fixture"}
	var template muistamov1.AgentTemplate
	template.ApiVersion, template.Kind, template.Metadata.Name = "muistamo.dev/v1", "AgentTemplate", "analyst"
	template.Spec.Purpose, template.Spec.ModelAlias = "status fixture", "reasoning-default"
	if _, _, err := svc.ApplyTemplate(ctx, actor, template); err != nil {
		t.Fatal(err)
	}
	var instance muistamov1.AgentInstance
	instance.ApiVersion, instance.Kind, instance.Metadata.Name = "muistamo.dev/v1", "AgentInstance", "analyst-person"
	instance.Spec.TemplateRef.Name, instance.Spec.TemplateRef.Version = "analyst", "1"
	instance.Spec.Binding.Type, instance.Spec.Binding.Ref, instance.Spec.State = "user", "person@example.invalid", "requested"
	if _, _, err := svc.ApplyInstance(ctx, actor, instance, ""); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MUISTAMO_DATABASE_URL", db.AppURL)
	t.Setenv("MUISTAMO_EVIDENCE_KEY_FILE", "")
	for _, id := range []uuid.UUID{tenant, other} {
		cmd := entraCmd()
		out := &bytes.Buffer{}
		cmd.SetOut(out)
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"status", "--tenant", id.String(), "--actor", "operator:test", "--instance", instance.Metadata.Name})
		err := cmd.Execute()
		if id == other {
			if !errors.Is(err, registry.ErrNotFound) || strings.Contains(out.String(), tenant.String()) {
				t.Fatalf("foreign status exposed: %s %v", out, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var status muistamov1.InstanceIdentityStatus
		if err := json.Unmarshal(out.Bytes(), &status); err != nil || status.TenantId != tenant || status.ProviderMode != "simulated" {
			t.Fatalf("scoped status: %s %v", out, err)
		}
	}
}

func TestEntraPrivateInputPrecedesBoundedDatabasePhase(t *testing.T) {
	tenant := uuid.NewString()
	binding := muistamov1.EntraIdentityBinding{TenantId: tenant, BindingVersion: uuid.NewString(), EntraTenantId: uuid.NewString(), BlueprintAppId: uuid.NewString(), BlueprintObjectId: uuid.NewString(), BlueprintPrincipalId: uuid.NewString(), SponsorUserIds: []string{uuid.NewString()}, CredentialRef: "fake-vault-ref", CredentialVersion: "fake-version"}
	raw, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "binding.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MUISTAMO_DATABASE_URL", "postgres://fake:fake@127.0.0.1:1/fake?connect_timeout=1")
	input, writer := io.Pipe()
	defer func() { _ = input.Close() }()
	defer func() { _ = writer.Close() }()
	cmd := entraCmd()
	cmd.SetIn(input)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"reconcile", "--tenant", tenant, "--actor", "operator:test", "--operation", uuid.NewString(), "--binding", path, "--credential-stdin"})
	finished := make(chan error, 1)
	go func() { finished <- cmd.Execute() }()
	select {
	case err := <-finished:
		t.Fatalf("database/provider phase started before private input completed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	_ = writer.Close()
	select {
	case err := <-finished:
		if err == nil || err.Error() != "credential input unavailable" {
			t.Fatalf("private input error exposed another phase: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closed private input blocked command completion")
	}
}

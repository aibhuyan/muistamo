package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestServeRefusesWithoutARegisteredKey(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	dir := t.TempDir()

	if _, err := loadSigner(ctx, conn, filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("missing key file: want refusal")
	}

	_, pemBytes, err := evidence.GenerateLocalKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "unregistered.key")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(ctx, conn, path); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("unregistered key: err = %v, want refusal", err)
	}

	key, err := evidence.LoadLocalKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterSigningKey(ctx, db.OwnerURL, key.KeyID(), key.Public()); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigner(ctx, conn, path); err != nil {
		t.Fatalf("registered key: %v", err)
	}
}

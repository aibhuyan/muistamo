package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"muistamo.dev/muistamo/control-plane/evidencechain"
)

func TestVerifyAnExportOffline(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "evidence.pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	var lines []string
	prev := evidencechain.GenesisHash
	for seq := int64(1); seq <= 3; seq++ {
		e := evidencechain.Event{
			Tenant: "00000000-0000-0000-0000-000000000001", Seq: seq,
			OccurredAt: time.Date(2026, 10, 25, 10, 0, int(seq), 123456000, time.UTC),
			Actor:      "dev:person-a@example.invalid", Action: "template.version.created",
			Subject:  evidencechain.Subject{Kind: "AgentTemplate", Name: "analyst-intern"},
			After:    json.RawMessage(`{"version":1}`),
			PrevHash: prev, RequestID: "req", KeyID: evidencechain.KeyID(pub),
		}
		e.Hash, _ = evidencechain.Hash(e)
		digest, _ := hex.DecodeString(e.Hash)
		e.Signature = evidencechain.EncodeSignature(ed25519.Sign(priv, digest))
		line, _ := json.Marshal(e)
		lines = append(lines, string(line))
		prev = e.Hash
	}
	export := filepath.Join(dir, "chain.jsonl")
	if err := os.WriteFile(export, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := readPublicKeys([]string{keyFile})
	if err != nil {
		t.Fatal(err)
	}
	events, err := readExport(export)
	if err != nil {
		t.Fatal(err)
	}
	if err := evidencechain.Verify(events, keys); err != nil {
		t.Fatalf("good export: %v", err)
	}

	tampered := strings.Replace(lines[1], `"version":1`, `"version":2`, 1)
	if err := os.WriteFile(export, []byte(lines[0]+"\n"+tampered+"\n"+lines[2]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err = readExport(export)
	if err != nil {
		t.Fatal(err)
	}
	var verr *evidencechain.VerifyError
	if err := evidencechain.Verify(events, keys); !errors.As(err, &verr) || verr.Seq != 2 {
		t.Fatalf("tampered export: err = %v, want failure at seq 2", err)
	}
}

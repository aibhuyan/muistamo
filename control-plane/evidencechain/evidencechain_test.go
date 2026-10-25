package evidencechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func goldenEvent() Event {
	return Event{
		Tenant:     "00000000-0000-0000-0000-000000000001",
		Seq:        1,
		OccurredAt: time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC),
		Actor:      "dev:person-a@example.invalid",
		Action:     "template.version.created",
		Subject:    Subject{Kind: "AgentTemplate", Name: "analyst-intern"},
		After:      json.RawMessage(`{"version": 1, "digest": "ab"}`),
		RequestID:  "req-1",
		PrevHash:   GenesisHash,
	}
}

// contracts/testdata/evidence-golden.json is shared with the Python implementation
// (knowledge/tests/test_evidence.py); both must reproduce it exactly. It was computed with an
// independent RFC 8785 implementation (Python rfc8785). If this test fails, the stored chain
// format changed: every existing event would stop verifying.
func TestGoldenVector(t *testing.T) {
	raw, err := os.ReadFile("../../contracts/testdata/evidence-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Canonical, Hash, TestSeedHex, PublicKeyHex, KeyID, Signature string
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}

	canonical, err := Canonical(goldenEvent())
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != golden.Canonical {
		t.Fatalf("canonical body:\n%s\nwant:\n%s", canonical, golden.Canonical)
	}
	hash, _ := Hash(goldenEvent())
	if hash != golden.Hash {
		t.Fatalf("hash = %s, want %s", hash, golden.Hash)
	}

	seed, _ := hex.DecodeString(golden.TestSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != golden.PublicKeyHex || KeyID(pub) != golden.KeyID {
		t.Fatalf("public key %x / key id %s, want %s / %s", pub, KeyID(pub), golden.PublicKeyHex, golden.KeyID)
	}
	digest, _ := hex.DecodeString(hash)
	if sig := EncodeSignature(ed25519.Sign(priv, digest)); sig != golden.Signature {
		t.Fatalf("signature = %s, want %s", sig, golden.Signature)
	}
}

func TestCanonicalIgnoresKeyOrderAndWhitespace(t *testing.T) {
	a, b := goldenEvent(), goldenEvent()
	b.After = json.RawMessage("{\n  \"digest\":\"ab\",\n  \"version\":1\n}")
	ha, _ := Hash(a)
	hb, _ := Hash(b)
	if ha != hb {
		t.Fatalf("hashes differ for the same JSON value: %s vs %s", ha, hb)
	}
}

func TestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{KeyID(pub): pub}
	chain := buildChain(t, priv, 4)

	if err := Verify(chain, keys); err != nil {
		t.Fatalf("good chain: %v", err)
	}

	cases := map[string]struct {
		tamper  func([]Event) []Event
		wantSeq int64
	}{
		"edited field":  {func(c []Event) []Event { c[2].After = json.RawMessage(`{"version":99}`); return c }, 3},
		"edited actor":  {func(c []Event) []Event { c[0].Actor = "dev:someone-else"; return c }, 1},
		"deleted event": {func(c []Event) []Event { return append(c[:1], c[2:]...) }, 2},
		"reordered":     {func(c []Event) []Event { c[1], c[2] = c[2], c[1]; return c }, 2},
		"wrong signature": {func(c []Event) []Event {
			c[3].Signature = c[2].Signature
			return c
		}, 4},
		"unknown key":  {func(c []Event) []Event { c[1].KeyID = "00112233445566778899aabbccddeeff"; return c }, 2},
		"gap at start": {func(c []Event) []Event { return c[1:] }, 1},
		"hash rewritten to match edit": {func(c []Event) []Event {
			// An attacker without the key recomputes the hash; the signature and link still fail.
			c[1].After = json.RawMessage(`{"version":7}`)
			c[1].Hash, _ = Hash(c[1])
			return c
		}, 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := tc.tamper(buildChainCopy(chain))
			err := Verify(tampered, keys)
			var verr *VerifyError
			if !errors.As(err, &verr) || verr.Seq != tc.wantSeq {
				t.Fatalf("err = %v, want failure at seq %d", err, tc.wantSeq)
			}
		})
	}
}

func buildChain(t *testing.T, priv ed25519.PrivateKey, n int) []Event {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	prev := GenesisHash
	var chain []Event
	for i := 1; i <= n; i++ {
		e := goldenEvent()
		e.Seq = int64(i)
		e.After = json.RawMessage(`{"version":` + string(rune('0'+i)) + `}`)
		e.PrevHash = prev
		hash, err := Hash(e)
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := hex.DecodeString(hash)
		e.Hash, e.KeyID, e.Signature = hash, KeyID(pub), EncodeSignature(ed25519.Sign(priv, digest))
		chain = append(chain, e)
		prev = hash
	}
	return chain
}

func buildChainCopy(chain []Event) []Event { return append([]Event(nil), chain...) }

func goldenKeys(t *testing.T) (ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/testdata/evidence-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct{ TestSeedHex string }
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(golden.TestSeedHex)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, map[string]ed25519.PublicKey{KeyID(pub): pub}
}

// The fixture Python verifies (knowledge/tests/test_evidence.py test_verifies_go_chain).
// Regenerate with MUISTAMO_UPDATE_FIXTURES=1.
func TestGoChainFixtureIsCurrent(t *testing.T) {
	priv, _ := goldenKeys(t)
	pub := priv.Public().(ed25519.PublicKey)
	var lines []string
	prev := GenesisHash
	for seq := int64(1); seq <= 3; seq++ {
		e := Event{
			Tenant: "00000000-0000-0000-0000-000000000002", Seq: seq,
			OccurredAt: time.Date(2026, 10, 25, 11, 0, int(seq), 654321000, time.UTC),
			Actor:      "workflow:joiner-x", Action: "instance.transitioned",
			Subject:   Subject{Kind: "AgentInstance", Name: "analyst-intern-e-1001"},
			Before:    json.RawMessage(`{"state":"requested"}`),
			After:     json.RawMessage(`{"state":"active","revision":2,"note":"äö <ok> & \"quoted\""}`),
			RequestID: "hr-event:ev", PrevHash: prev, KeyID: KeyID(pub),
		}
		e.Hash, _ = Hash(e)
		digest, _ := hex.DecodeString(e.Hash)
		e.Signature = EncodeSignature(ed25519.Sign(priv, digest))
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(line))
		prev = e.Hash
	}
	path := "../../contracts/testdata/evidence-chain-go.jsonl"
	want := strings.Join(lines, "\n") + "\n"
	if os.Getenv("MUISTAMO_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("%s is stale (err %v); regenerate with MUISTAMO_UPDATE_FIXTURES=1", path, err)
	}
}

// A chain produced by the Python knowledge service verifies in Go.
func TestVerifiesPythonChain(t *testing.T) {
	_, keys := goldenKeys(t)
	raw, err := os.ReadFile("../../contracts/testdata/evidence-chain-python.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var events []Event
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if len(events) != 3 {
		t.Fatalf("events = %d", len(events))
	}
	if err := Verify(events, keys); err != nil {
		t.Fatalf("Python chain does not verify in Go: %v", err)
	}
}

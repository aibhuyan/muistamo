package evidencechain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// The expected values were computed independently (Python: sorted keys, compact separators,
// SHA-256), which equals RFC 8785 output for this ASCII, integer-only body. If this test fails,
// the stored chain format changed: every existing event would stop verifying.
func TestGoldenVector(t *testing.T) {
	const (
		wantCanonical = `{"action":"template.version.created","actor":"dev:person-a@example.invalid","after":{"digest":"ab","version":1},"before":null,"occurredAt":"2026-10-25T10:00:00.000000Z","prevHash":"0000000000000000000000000000000000000000000000000000000000000000","requestId":"req-1","seq":1,"subject":{"kind":"AgentTemplate","name":"analyst-intern"},"tenant":"00000000-0000-0000-0000-000000000001"}`
		wantHash      = "ebe569a43f8ee8c172bbd93f0e74190d65b535ab966213c9f90a40a25a9d64c5"
	)
	canonical, err := Canonical(goldenEvent())
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != wantCanonical {
		t.Fatalf("canonical body:\n%s\nwant:\n%s", canonical, wantCanonical)
	}
	if hash, _ := Hash(goldenEvent()); hash != wantHash {
		t.Fatalf("hash = %s, want %s", hash, wantHash)
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

// Package evidencechain defines the evidence event format and verifies chains of events.
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): this is the evidence hash chain and signature format.
//
// Each tenant has one chain. An event's hash is SHA-256 over the RFC 8785 (JCS) canonical JSON of
// its body, the body includes the previous event's hash, and the hash is signed with Ed25519.
// Changing anything here changes the meaning of every stored event: the golden vector in the
// tests must fail first.
package evidencechain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
)

// TimeFormat is how occurredAt appears in the hashed body: UTC, microseconds.
const TimeFormat = "2006-01-02T15:04:05.000000Z"

// GenesisHash is the prevHash of every chain's first event.
var GenesisHash = hex.EncodeToString(make([]byte, sha256.Size))

// Subject is what an event is about.
type Subject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Event is one entry in a tenant's chain, as stored and exported.
type Event struct {
	Tenant     string          `json:"tenant"`
	Seq        int64           `json:"seq"`
	OccurredAt time.Time       `json:"occurredAt"`
	Actor      string          `json:"actor"`
	Action     string          `json:"action"`
	Subject    Subject         `json:"subject"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	RequestID  string          `json:"requestId"`
	PrevHash   string          `json:"prevHash"`
	Hash       string          `json:"hash"`
	KeyID      string          `json:"keyId"`
	Signature  string          `json:"signature"`
}

// body is exactly what is hashed. Hash, KeyID and Signature are not part of it.
type body struct {
	Tenant     string          `json:"tenant"`
	Seq        int64           `json:"seq"`
	OccurredAt string          `json:"occurredAt"`
	Actor      string          `json:"actor"`
	Action     string          `json:"action"`
	Subject    Subject         `json:"subject"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	RequestID  string          `json:"requestId"`
	PrevHash   string          `json:"prevHash"`
}

// Canonical returns the RFC 8785 canonical JSON of the event's hashed body.
func Canonical(e Event) ([]byte, error) {
	raw, err := json.Marshal(body{
		Tenant:     e.Tenant,
		Seq:        e.Seq,
		OccurredAt: e.OccurredAt.UTC().Format(TimeFormat),
		Actor:      e.Actor,
		Action:     e.Action,
		Subject:    e.Subject,
		Before:     orNull(e.Before),
		After:      orNull(e.After),
		RequestID:  e.RequestID,
		PrevHash:   e.PrevHash,
	})
	if err != nil {
		return nil, fmt.Errorf("encode event body: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("canonicalise event body: %w", err)
	}
	return canonical, nil
}

// Hash returns the hex SHA-256 of the event's canonical body.
func Hash(e Event) (string, error) {
	canonical, err := Canonical(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// KeyID identifies a public key: the first 16 bytes of its SHA-256, in hex.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// EncodeSignature and DecodeSignature convert between raw and exported signatures.
func EncodeSignature(sig []byte) string { return base64.StdEncoding.EncodeToString(sig) }

// DecodeSignature is the inverse of EncodeSignature.
func DecodeSignature(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// VerifyError names the first event that fails verification.
type VerifyError struct {
	Seq    int64
	Reason string
}

func (e *VerifyError) Error() string { return fmt.Sprintf("evidence seq %d: %s", e.Seq, e.Reason) }

// Verify checks a complete chain for one tenant, in order from seq 1: contiguous sequence,
// each prevHash equal to the previous hash, each hash recomputed from the body, and each
// signature valid under a key in keys (keyed by KeyID). The keys must come from the verifier,
// never from the system being verified.
func Verify(events []Event, keys map[string]ed25519.PublicKey) error {
	if len(events) == 0 {
		return &VerifyError{Seq: 0, Reason: "no events to verify"}
	}
	prev := GenesisHash
	for i, e := range events {
		want := int64(i + 1)
		switch {
		case e.Seq != want:
			return &VerifyError{Seq: want, Reason: fmt.Sprintf("missing or out of order: found seq %d", e.Seq)}
		case e.Tenant != events[0].Tenant:
			return &VerifyError{Seq: e.Seq, Reason: "belongs to a different tenant's chain"}
		case e.PrevHash != prev:
			return &VerifyError{Seq: e.Seq, Reason: "prevHash does not match the previous event's hash"}
		}
		hash, err := Hash(e)
		if err != nil {
			return &VerifyError{Seq: e.Seq, Reason: err.Error()}
		}
		if hash != e.Hash {
			return &VerifyError{Seq: e.Seq, Reason: "content does not match its hash"}
		}
		key, ok := keys[e.KeyID]
		if !ok {
			return &VerifyError{Seq: e.Seq, Reason: fmt.Sprintf("signed by unknown key %s", e.KeyID)}
		}
		digest, err := hex.DecodeString(e.Hash)
		if err != nil {
			return &VerifyError{Seq: e.Seq, Reason: "hash is not hex"}
		}
		sig, err := DecodeSignature(e.Signature)
		if err != nil || !ed25519.Verify(key, digest, sig) {
			return &VerifyError{Seq: e.Seq, Reason: "signature is not valid"}
		}
		prev = e.Hash
	}
	return nil
}

func orNull(raw json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 {
		return json.RawMessage("null")
	}
	return raw
}

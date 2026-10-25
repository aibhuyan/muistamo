// Package evidence appends signed, hash-chained events to a tenant's evidence log.
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): signing keys and the evidence chain.
//
// Append runs inside the caller's transaction, so an action and its evidence commit together or
// not at all (invariant 4). It locks the tenant's chain head, which serialises evidence writes per
// tenant and keeps the sequence gap-free.
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/control-plane/evidencechain"
)

// ErrNotRecorded wraps every failure to record evidence. Callers must abort the action.
var ErrNotRecorded = errors.New("evidence could not be recorded")

// Signer signs event hashes.
type Signer interface {
	KeyID() string
	Sign(digest []byte) ([]byte, error)
}

// LocalKey is an Ed25519 key held in a local file. Release 1 only; KMS-backed signers replace it.
type LocalKey struct {
	priv ed25519.PrivateKey
}

// KeyID identifies the key in events and in evidence_signing_keys.
func (k LocalKey) KeyID() string { return evidencechain.KeyID(k.Public()) }

// Public returns the public half.
func (k LocalKey) Public() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }

// Sign signs a digest.
func (k LocalKey) Sign(digest []byte) ([]byte, error) { return ed25519.Sign(k.priv, digest), nil }

// GenerateLocalKey creates a key and returns it with its PKCS#8 PEM encoding.
func GenerateLocalKey() (LocalKey, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return LocalKey{}, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return LocalKey{}, nil, fmt.Errorf("encode key: %w", err)
	}
	return LocalKey{priv: priv}, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadLocalKey reads a PKCS#8 PEM Ed25519 private key.
func LoadLocalKey(path string) (LocalKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return LocalKey{}, fmt.Errorf("read evidence key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return LocalKey{}, errors.New("evidence key: expected a PKCS#8 PEM PRIVATE KEY block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return LocalKey{}, fmt.Errorf("parse evidence key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return LocalKey{}, errors.New("evidence key: not an Ed25519 key")
	}
	return LocalKey{priv: priv}, nil
}

// EncodePublicKey returns the PKIX PEM encoding of a public key, the form verifiers are given.
func EncodePublicKey(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Entry is what a caller records; Append adds sequence, links, hash and signature.
type Entry struct {
	Tenant      uuid.UUID
	Actor       string
	Action      string
	SubjectKind string
	SubjectName string
	Before      any
	After       any
	RequestID   string
}

// Append records entry as the next event in its tenant's chain, inside tx.
func Append(ctx context.Context, tx pgx.Tx, signer Signer, entry Entry) (evidencechain.Event, error) {
	event, err := appendEvent(ctx, tx, signer, entry)
	if err != nil {
		return evidencechain.Event{}, fmt.Errorf("%s for %s %q: %w: %w", entry.Action, entry.SubjectKind, entry.SubjectName, ErrNotRecorded, err)
	}
	return event, nil
}

func appendEvent(ctx context.Context, tx pgx.Tx, signer Signer, entry Entry) (evidencechain.Event, error) {
	if _, err := tx.Exec(ctx, `
		INSERT INTO evidence_heads (tenant_id, seq, hash) VALUES ($1, 0, $2)
		ON CONFLICT (tenant_id) DO NOTHING`, entry.Tenant, evidencechain.GenesisHash); err != nil {
		return evidencechain.Event{}, fmt.Errorf("initialise chain head: %w", err)
	}
	var seq int64
	var prev string
	if err := tx.QueryRow(ctx, `SELECT seq, hash FROM evidence_heads WHERE tenant_id = $1 FOR UPDATE`, entry.Tenant).Scan(&seq, &prev); err != nil {
		return evidencechain.Event{}, fmt.Errorf("lock chain head: %w", err)
	}

	before, err := encode(entry.Before)
	if err != nil {
		return evidencechain.Event{}, err
	}
	after, err := encode(entry.After)
	if err != nil {
		return evidencechain.Event{}, err
	}
	event := evidencechain.Event{
		Tenant:     entry.Tenant.String(),
		Seq:        seq + 1,
		OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		Actor:      entry.Actor,
		Action:     entry.Action,
		Subject:    evidencechain.Subject{Kind: entry.SubjectKind, Name: entry.SubjectName},
		Before:     before,
		After:      after,
		RequestID:  entry.RequestID,
		PrevHash:   prev,
		KeyID:      signer.KeyID(),
	}
	if event.Hash, err = evidencechain.Hash(event); err != nil {
		return evidencechain.Event{}, err
	}
	digest, err := hex.DecodeString(event.Hash)
	if err != nil {
		return evidencechain.Event{}, fmt.Errorf("decode hash: %w", err)
	}
	sig, err := signer.Sign(digest)
	if err != nil {
		return evidencechain.Event{}, fmt.Errorf("sign: %w", err)
	}
	event.Signature = evidencechain.EncodeSignature(sig)

	if _, err := tx.Exec(ctx, `
		INSERT INTO evidence_events (tenant_id, seq, occurred_at, actor, action, subject_kind, subject_name,
		                             before, after, request_id, prev_hash, hash, key_id, signature)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		entry.Tenant, event.Seq, event.OccurredAt, event.Actor, event.Action, event.Subject.Kind, event.Subject.Name,
		nullable(before), nullable(after), event.RequestID, event.PrevHash, event.Hash, event.KeyID, event.Signature); err != nil {
		return evidencechain.Event{}, fmt.Errorf("insert event: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE evidence_heads SET seq = $2, hash = $3 WHERE tenant_id = $1`,
		entry.Tenant, event.Seq, event.Hash); err != nil {
		return evidencechain.Event{}, fmt.Errorf("advance chain head: %w", err)
	}
	return event, nil
}

// List returns the tenant's events after afterSeq, in order. Row-level security scopes tx.
func List(ctx context.Context, tx pgx.Tx, afterSeq int64, limit int) ([]evidencechain.Event, error) {
	rows, err := tx.Query(ctx, `
		SELECT tenant_id, seq, occurred_at, actor, action, subject_kind, subject_name,
		       before, after, request_id, prev_hash, hash, key_id, signature
		FROM evidence_events WHERE seq > $1 ORDER BY seq LIMIT $2`, afterSeq, limit)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	defer rows.Close()
	events := []evidencechain.Event{}
	for rows.Next() {
		var e evidencechain.Event
		var tenant uuid.UUID
		var before, after []byte
		if err := rows.Scan(&tenant, &e.Seq, &e.OccurredAt, &e.Actor, &e.Action, &e.Subject.Kind, &e.Subject.Name,
			&before, &after, &e.RequestID, &e.PrevHash, &e.Hash, &e.KeyID, &e.Signature); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		e.Tenant, e.OccurredAt = tenant.String(), e.OccurredAt.UTC()
		e.Before, e.After = rawOrNull(before), rawOrNull(after)
		events = append(events, e)
	}
	return events, rows.Err()
}

func encode(v any) (json.RawMessage, error) {
	if v == nil {
		return json.RawMessage("null"), nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode evidence payload: %w", err)
	}
	return raw, nil
}

// nullable stores JSON null as SQL NULL, so the database never holds two spellings of "nothing".
func nullable(raw json.RawMessage) any {
	if string(raw) == "null" {
		return nil
	}
	return []byte(raw)
}

func rawOrNull(b []byte) json.RawMessage {
	if b == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(b)
}

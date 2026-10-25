// Package signature signs and checks request bodies with a shared secret: the HR webhook
// scheme, also used for service calls to the knowledge service.
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): credential handling.
//
// The header value is t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body">. The knowledge service
// implements the same scheme in muistamo_knowledge/auth.py.
package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// Sign returns the X-Muistamo-Signature value for body at time t.
func Sign(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + hex.EncodeToString(MAC(secret, ts, body))
}

// MAC is HMAC-SHA256 of "ts.body" under secret.
func MAC(secret []byte, ts string, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(ts))
	h.Write([]byte("."))
	h.Write(body)
	return h.Sum(nil)
}

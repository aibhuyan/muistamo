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

// KnowledgeToControlPlane names the key the knowledge service signs control-plane calls with.
// Calls the other way are signed with the tenant secret itself, so a request signed for one
// direction is never accepted in the other.
const KnowledgeToControlPlane = "muistamo/v1 knowledge→control-plane"

// DirectionKey derives a tenant's signing key for one direction from its shared secret:
// HMAC-SHA256 of "<direction>\n<tenant id>" under the secret. The tenant id is bound in too, so
// two tenants given the same secret by mistake still cannot replay each other's requests.
func DirectionKey(secret []byte, direction, tenant string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(direction + "\n" + tenant))
	return h.Sum(nil)
}

// MAC is HMAC-SHA256 of "ts.body" under secret.
func MAC(secret []byte, ts string, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(ts))
	h.Write([]byte("."))
	h.Write(body)
	return h.Sum(nil)
}

// knowledgeV2 separates v2 MACs from v1 and from any other use of the secret.
const knowledgeV2 = "muistamo/v2 control-plane→knowledge"

// MACv2 is HMAC-SHA256 under secret of the v2 domain, ts, method, the decoded path (no query)
// and body, joined by newlines: a request signed for one review, method or route verifies for
// no other (docs/signature-plan.md).
func MACv2(secret []byte, ts, method, path string, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(knowledgeV2 + "\n" + ts + "\n" + method + "\n" + path + "\n"))
	h.Write(body)
	return h.Sum(nil)
}

// SignRequest returns the X-Muistamo-Signature value for a control-plane call to the knowledge
// service: t=<unix seconds>,v2=<hex MACv2>. The v1 overlap is over
// (docs/signature-retirement-plan.md): v1 (Sign) remains only for the HR webhook and the
// knowledge-to-control-plane direction.
func SignRequest(secret []byte, method, path string, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v2=" + hex.EncodeToString(MACv2(secret, ts, method, path, body))
}

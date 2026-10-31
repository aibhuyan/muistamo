package signature

import (
	"encoding/hex"
	"testing"
	"time"
)

// The knowledge service derives and signs the same way (muistamo_knowledge/delegation.py, which
// asserts these same values): a change on either side breaks this vector.
func TestDirectionKeyVector(t *testing.T) {
	key := DirectionKey([]byte("obviously-fake-knowledge-secret"), KnowledgeToControlPlane, "11111111-1111-4111-8111-111111111111")
	if got := hex.EncodeToString(key); got != "1857a5c5dbdbb6187f7ab198a211d42b752236b2efbbaa9f4e19444924375ccf" {
		t.Fatalf("direction key = %s", got)
	}
	if got := Sign(key, []byte("{}"), time.Unix(1700000000, 0)); got != "t=1700000000,v1=5e444998662526fd33a0cd6b5e3077cc315afeb5499b8c576da8e3db0092fac3" {
		t.Fatalf("signature = %s", got)
	}
}

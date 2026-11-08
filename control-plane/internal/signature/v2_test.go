package signature

import (
	"strings"
	"testing"
	"time"
)

// The knowledge service checks the same bytes (knowledge/tests/test_signature_v2.py): this
// vector fails here and there if either side's v2 input ever changes.
const v2Vector = "06f5c6495ddb43878640ea4dbc89ff130059f4c155f9a8808832406e5dbacb44"

func TestSignRequestBindsMethodAndPath(t *testing.T) {
	secret := []byte("mks_test-only-not-a-secret-0123456789abcdef")
	path := "/v1/knowledge/internal/leaver-reviews/entra-leaver:r/expire"
	at := time.Unix(1700000000, 0)
	got := SignRequest(secret, "POST", path, nil, at)
	// v2 only: the v1 overlap is over (docs/signature-retirement-plan.md).
	if got != "t=1700000000,v2="+v2Vector {
		t.Fatalf("SignRequest = %s", got)
	}
	for name, other := range map[string]string{
		"another review": SignRequest(secret, "POST", strings.Replace(path, "entra-leaver:r", "entra-leaver:s", 1), nil, at),
		"another method": SignRequest(secret, "PUT", path, nil, at),
		"another route":  SignRequest(secret, "POST", strings.Replace(path, "/expire", "/cancel", 1), nil, at),
	} {
		if strings.HasSuffix(other, ",v2="+v2Vector) {
			t.Errorf("%s has the same v2 MAC", name)
		}
	}
}

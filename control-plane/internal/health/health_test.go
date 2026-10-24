package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func TestHandlerReportsOK(t *testing.T) {
	rec := httptest.NewRecorder()

	Handler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var got muistamov1.HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Status != muistamov1.HealthStatusStatusOk || got.Service != service {
		t.Fatalf("body = %+v", got)
	}
}

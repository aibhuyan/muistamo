// Package health serves the control plane's health endpoint.
package health

import (
	"encoding/json"
	"net/http"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

const service = "control-plane"

// Handler responds with the contract's HealthStatus.
func Handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body := muistamov1.HealthStatus{Status: muistamov1.HealthStatusStatusOk, Service: service}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		http.Error(w, "encode health status", http.StatusInternalServerError)
	}
}

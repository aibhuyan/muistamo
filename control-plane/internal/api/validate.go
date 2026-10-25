package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"muistamo.dev/muistamo/contracts"
)

const maxBody = 1 << 20

// validateDocuments checks request bodies against the contract schemas before decoding. The
// generated types drop unknown fields silently, so this is where they are rejected.
func validateDocuments(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var validate func([]byte) error
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/"):
			validate = contracts.Validate
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/transitions"):
			validate = func(b []byte) error { return contracts.ValidateAgainst("instancetransition.json", b) }
		case r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch:
			// Fail closed: a write route without a schema mapping must not reach a handler.
			writeProblem(w, http.StatusInternalServerError, "No contract validation for this route", "")
			return
		default:
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			writeProblem(w, http.StatusRequestEntityTooLarge, "Request body too large", "")
			return
		}
		if !json.Valid(body) {
			writeProblem(w, http.StatusBadRequest, "Request body is not valid JSON", "")
			return
		}
		if err := validate(body); err != nil {
			writeProblem(w, http.StatusUnprocessableEntity, "Document does not match its contract", err.Error())
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{"title": title, "status": status}
	if detail != "" {
		body["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(body)
}

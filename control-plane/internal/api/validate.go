package api

import (
	"bytes"
	"encoding/json"
	"errors"
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
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/publication") && strings.HasPrefix(r.URL.Path, "/v1/templates/"):
			validate = emptyBody
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/catalogue/requests/") && strings.HasSuffix(r.URL.Path, "/decision"):
			validate = func(b []byte) error { return contracts.ValidateAgainst("cataloguedecision.json", b) }
		case r.Method == http.MethodPost && r.URL.Path == hrEventsPath:
			validate = func(b []byte) error { return contracts.ValidateAgainst("hrevent.json", b) }
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/clones/") && strings.HasSuffix(r.URL.Path, "/sync"):
			validate = emptyBody
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/models/") && strings.HasSuffix(r.URL.Path, "/approval"):
			validate = func(b []byte) error { return contracts.ValidateAgainst("modelapprovaldecision.json", b) }
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/model-aliases/") && strings.HasSuffix(r.URL.Path, "/rollouts"):
			validate = func(b []byte) error { return contracts.ValidateAgainst("rolloutrequest.json", b) }
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/rollouts/") && strings.HasSuffix(r.URL.Path, "/rollback"):
			validate = func(b []byte) error { return contracts.ValidateAgainst("rollbackrequest.json", b) }
		case r.Method == http.MethodPost && r.URL.Path == "/v1/policy/decisions":
			validate = func(b []byte) error { return contracts.ValidateAgainst("policydecisionrequest.json", b) }
		case r.Method == http.MethodPost && r.URL.Path == "/v1/policy/simulate":
			validate = func(b []byte) error { return contracts.ValidateAgainst("policysimulationrequest.json", b) }
		case r.Method == http.MethodPost && r.URL.Path == "/v1/privacy/erasures":
			validate = func(b []byte) error { return contracts.ValidateAgainst("erasurerequest.json", b) }
		case r.Method == http.MethodPost && r.URL.Path == "/v1/privacy/access":
			validate = func(b []byte) error { return contracts.ValidateAgainst("accessrequest.json", b) }
		case r.Method == http.MethodPost && r.URL.Path == "/v1/virtual-keys":
			validate = func(b []byte) error { return contracts.ValidateAgainst("virtualkeyrequest.json", b) }
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/virtual-keys/") && strings.HasSuffix(r.URL.Path, "/revocation"):
			validate = func(b []byte) error { return contracts.ValidateAgainst("virtualkeyrevocation.json", b) }
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
		if len(body) > 0 && !json.Valid(body) {
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

// emptyBody accepts a request that carries no document.
func emptyBody(b []byte) error {
	if len(bytes.TrimSpace(b)) > 0 && string(bytes.TrimSpace(b)) != "{}" {
		return errors.New("this request takes no body")
	}
	return nil
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

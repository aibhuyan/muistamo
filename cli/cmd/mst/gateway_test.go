package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

func TestGatewayCLIUsesGeneratedContractsAndShowsSecretOnlyOnIssue(t *testing.T) {
	id := uuid.New()
	secret := "mvk_" + id.String() + "_" + strings.Repeat("A", 42) + "E"
	key := muistamov1.VirtualKey{Id: id, Instance: "test-agent", Aliases: []string{"reasoning-default"},
		MonthlyBudget: muistamov1.Money{Amount: "25.5", Currency: "EUR"}, Status: "active", CreatedAt: time.Now(), CreatedBy: "dev:admin@example.invalid"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Muistamo-Actor") != "admin@example.invalid" {
			t.Error("missing acting identity")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/virtual-keys":
			var req muistamov1.VirtualKeyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Instance != key.Instance || req.MonthlyBudget.Amount != "25.50" || req.Aliases[0] != key.Aliases[0] {
				t.Errorf("issue request = %+v, %v", req, err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(muistamov1.VirtualKeyIssued{Key: key, Secret: secret})
		case r.Method == http.MethodPost:
			var req muistamov1.VirtualKeyRevocation
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Reason != "operator" {
				t.Errorf("revocation = %+v, %v", req, err)
			}
			key.Status = "revoked"
			_ = json.NewEncoder(w).Encode(key)
		case r.URL.Path == "/v1/virtual-keys":
			if r.URL.Query().Get("instance") != key.Instance {
				t.Error("missing instance filter")
			}
			_ = json.NewEncoder(w).Encode(muistamov1.VirtualKeyPage{Items: []muistamov1.VirtualKey{key}})
		default:
			_ = json.NewEncoder(w).Encode(key)
		}
	}))
	defer srv.Close()
	for _, args := range [][]string{
		{"keys", "issue", "--instance", key.Instance, "--alias", key.Aliases[0], "--budget", "25.50"},
		{"keys", "list", "--instance", key.Instance},
		{"keys", "get", id.String()},
		{"keys", "revoke", id.String(), "--reason", "operator"},
	} {
		cmd := gatewayCmd(&options{server: srv.URL, tenant: uuid.NewString(), actor: "admin@example.invalid"})
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		want := 0
		if args[1] == "issue" {
			want = 1
		}
		if n := strings.Count(output.String(), secret); n != want {
			t.Errorf("%s printed secret %d times, want %d", args[1], n, want)
		}
	}
}

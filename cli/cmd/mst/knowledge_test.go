package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const verificationJSON = `{"pack":"rules","version":"0.2.0","entry":{"key":"expenses"},
 "decay":{"status":"current","verifiedBy":"dev:reviewer-r@example.invalid","dueAt":"2027-01-01T00:00:00+00:00","expiresAt":"2027-01-31T00:00:00+00:00"},
 "provenance":{"score":70,"factors":[]}}`

func runKnowledge(t *testing.T, handler http.HandlerFunc, args ...string) (string, error) {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()
	opts := &options{knowledgeServer: srv.URL, tenant: "11111111-2222-4333-8444-555555555555", actor: "reviewer-r@example.invalid"}
	cmd := knowledgeCmd(opts)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestVerifySendsTheReasonAsTheCaller(t *testing.T) {
	var got struct {
		method, path, tenant, actor string
		body                        map[string]string
	}
	out, err := runKnowledge(t, func(w http.ResponseWriter, r *http.Request) {
		got.method, got.path = r.Method, r.URL.EscapedPath()
		got.tenant, got.actor = r.Header.Get("X-Muistamo-Tenant"), r.Header.Get("X-Muistamo-Actor")
		_ = json.NewDecoder(r.Body).Decode(&got.body)
		_, _ = io.WriteString(w, verificationJSON)
	}, "verify", "rules", "expenses", "--reason", "still policy")
	if err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.path != "/v1/knowledge/packs/rules/entries/expenses/verification" {
		t.Errorf("request = %s %s", got.method, got.path)
	}
	if got.actor != "reviewer-r@example.invalid" || got.tenant == "" || got.body["reason"] != "still policy" {
		t.Errorf("headers %q %q, body %v", got.tenant, got.actor, got.body)
	}
	if !strings.Contains(out, "rules/expenses\tcurrent") || !strings.Contains(out, "provenance 70") {
		t.Errorf("output = %q", out)
	}
}

func TestVerifyRequiresAReasonAndReportsRefusals(t *testing.T) {
	if _, err := runKnowledge(t, func(http.ResponseWriter, *http.Request) {
		t.Error("no request should be sent without a reason")
	}, "verify", "rules", "expenses"); err == nil {
		t.Error("verify without --reason succeeded")
	}
	_, err := runKnowledge(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"title":"Forbidden","status":403,"detail":"nobody can confirm their own entry"}`)
	}, "verify", "rules", "expenses", "--reason", "mine")
	if err == nil || !strings.Contains(err.Error(), "nobody can confirm their own entry") {
		t.Errorf("refusal = %v", err)
	}
}

func TestVerificationsListsTheQueue(t *testing.T) {
	out, err := runKnowledge(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/knowledge/verifications" {
			t.Errorf("path = %s", r.URL.Path)
		}
		mandatory := `{"pack":"company-rules","version":"0.1.0","mandatory":true,"entry":{"key":"data-handling"},
		 "decay":{"status":"due","verifiedBy":"dev:dpo@example.invalid","dueAt":"2026-02-01T00:00:00+00:00"},"provenance":{"score":50,"factors":[]}}`
		_, _ = io.WriteString(w, `{"items":[`+verificationJSON+`,`+mandatory+`]}`)
	}, "verifications")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "rules/expenses") || !strings.Contains(out, "company-rules/data-handling\tdue") ||
		!strings.Contains(out, "expires never (mandatory)") {
		t.Errorf("output = %q", out)
	}
	empty, err := runKnowledge(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"items":[]}`)
	}, "verifications")
	if err != nil || !strings.Contains(empty, "nothing to confirm") {
		t.Errorf("empty queue = %q, %v", empty, err)
	}
}

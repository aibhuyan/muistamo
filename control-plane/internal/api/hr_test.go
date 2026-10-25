package api_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestHREventIsAcceptedOnceAndEvidenced(t *testing.T) {
	d := &fakeDispatcher{}
	h := newHarnessWithHR(t, api.DenyAll{}, d) // HR events never use the user resolver
	tenant := h.tenant(t, "acme")
	secret := h.hrSecret(t, tenant)
	body := hrEvent("ev-1", "joiner", "E-1001")

	first := h.postHR(t, tenant, secret, time.Now(), body)
	if first.status != http.StatusAccepted || first.body["duplicate"] != false || first.body["workflowId"] == "" {
		t.Fatalf("first delivery = %d %s, want 202 with a workflow id", first.status, first.raw)
	}
	again := h.postHR(t, tenant, secret, time.Now(), body)
	if again.status != http.StatusOK || again.body["duplicate"] != true || again.body["workflowId"] != first.body["workflowId"] {
		t.Fatalf("re-delivery = %d %s, want 200 duplicate with the same workflow id", again.status, again.raw)
	}
	if d.count() != 1 {
		t.Fatalf("dispatches = %d, want exactly 1", d.count())
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action = 'hr.event.received' AND actor = $1`, "hris:"+tenant.String()); n != 1 {
		t.Fatalf("hr.event.received evidence = %d, want 1", n)
	}
}

func TestHREventAuthenticationFailsClosed(t *testing.T) {
	d := &fakeDispatcher{}
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, d)
	tenant, other := h.tenant(t, "acme"), h.tenant(t, "globex")
	secret, otherSecret := h.hrSecret(t, tenant), h.hrSecret(t, other)
	noSecret := h.tenant(t, "initech")
	body := hrEvent("ev-1", "joiner", "E-1001")

	cases := map[string]response{
		"wrong secret":            h.postHR(t, tenant, []byte("mhr_wrong-and-fake"), time.Now(), body),
		"another tenant's secret": h.postHR(t, tenant, otherSecret, time.Now(), body),
		"stale signature":         h.postHR(t, tenant, secret, time.Now().Add(-6*time.Minute), body),
		"future signature":        h.postHR(t, tenant, secret, time.Now().Add(6*time.Minute), body),
		"tenant without a secret": h.postHR(t, noSecret, secret, time.Now(), body),
		"unknown tenant":          h.postHR(t, uuid.New(), secret, time.Now(), body),
		"no signature":            h.call(t, tenant, http.MethodPost, "/v1/hr/events", body),
		"malformed signature":     h.call(t, tenant, http.MethodPost, "/v1/hr/events", body, "X-Muistamo-Signature", "v1=zz"),
		// Dev headers authenticate users, never HR events.
		"dev headers only": h.call(t, tenant, http.MethodPost, "/v1/hr/events", body, "X-Muistamo-Signature", ""),
	}
	tampered := h.call(t, tenant, http.MethodPost, "/v1/hr/events", hrEvent("ev-1", "leaver", "E-1001"),
		"X-Muistamo-Signature", api.Sign(secret, []byte(body), time.Now()))
	cases["body changed after signing"] = tampered

	for name, got := range cases {
		if got.status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401: %s", name, got.status, got.raw)
		}
	}
	if d.count() != 0 {
		t.Fatalf("dispatches = %d, want none", d.count())
	}
}

func TestHREventMustMatchItsContract(t *testing.T) {
	h := newHarnessWithHR(t, api.DenyAll{}, &fakeDispatcher{})
	tenant := h.tenant(t, "acme")
	secret := h.hrSecret(t, tenant)

	for name, body := range map[string]string{
		"unknown type":  hrEvent("ev-1", "mover", "E-1001"),
		"unknown field": `{"id":"ev-2","type":"joiner","occurredAt":"2026-10-25T09:00:00Z","surprise":1,"person":{"id":"E","email":"a@example.invalid","jobCode":"X"}}`,
		"no person":     `{"id":"ev-3","type":"joiner","occurredAt":"2026-10-25T09:00:00Z"}`,
	} {
		if got := h.postHR(t, tenant, secret, time.Now(), body); got.status != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422: %s", name, got.status, got.raw)
		}
	}
}

func TestHREventIsNotRecordedWhenDispatchFails(t *testing.T) {
	d := &fakeDispatcher{fail: errors.New("temporal unavailable (test)")}
	h := newHarnessWithHR(t, api.DenyAll{}, d)
	tenant := h.tenant(t, "acme")
	secret := h.hrSecret(t, tenant)

	got := h.postHR(t, tenant, secret, time.Now(), hrEvent("ev-1", "leaver", "E-1001"))
	if got.status != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 so the HR system retries: %s", got.status, got.raw)
	}
	if n := testdb.Count(t, h.db.OwnerURL, `SELECT count(*) FROM hr_events`); n != 0 {
		t.Fatalf("hr_events = %d, want 0: a failed dispatch must not be recorded as received", n)
	}

	d.fail = nil
	if got := h.postHR(t, tenant, secret, time.Now(), hrEvent("ev-1", "leaver", "E-1001")); got.status != http.StatusAccepted {
		t.Fatalf("retry after recovery = %d, want 202", got.status)
	}
}

func TestHREventsRefusedWithoutAWorkflowEngine(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, nil)
	tenant := h.tenant(t, "acme")
	secret := h.hrSecret(t, tenant)
	if got := h.postHR(t, tenant, secret, time.Now(), hrEvent("ev-1", "joiner", "E-1001")); got.status != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 when HR intake is not configured", got.status)
	}
}

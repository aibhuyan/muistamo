//go:build authz

package api_test

// HUMAN REVIEW REQUIRED: who reads people and HR events through the console, and that no part of
// the HR payload or an agent's binding reaches them (docs/console-management-plan.md, slice 3;
// D70). Run by `make test-authz`; never skip or weaken.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// labelledInstanceJSON is instanceJSON labelled with person A's HR id, as the joiner workflow
// labels the agents it creates.
var labelledInstanceJSON = strings.Replace(instanceJSON, `"metadata":{"name":"analyst-intern-person-a"}`,
	`"metadata":{"name":"analyst-intern-person-a","labels":{"`+registry.PersonLabel+`":"A-PERSON"}}`, 1)

func TestAuthzConsolePeopleAndHREventsAreForAdministrators(t *testing.T) {
	var signedInto uuid.UUID
	h := newHarnessWithHR(t, api.WithConsole{Console: consoleAs{&signedInto}, Fallback: api.InsecureDevHeaders{}}, &fakeDispatcher{})
	a, b := h.tenant(t, "tenant-a"), h.tenant(t, "tenant-b")
	if !strings.Contains(labelledInstanceJSON, registry.PersonLabel) {
		t.Fatal("the fixture instance carries no person label")
	}
	if got := h.call(t, a, http.MethodPut, "/v1/templates/analyst-intern", templateJSON); got.status != http.StatusCreated {
		t.Fatalf("seed template = %d: %s", got.status, got.raw)
	}
	secretA, secretB := h.hrSecret(t, a), h.hrSecret(t, b)
	// Every HR event's payload carries the person's email and job code; neither may come back.
	post := func(tenant uuid.UUID, secret []byte, body string) {
		t.Helper()
		if got := h.postHR(t, tenant, secret, time.Now(), body); got.status != http.StatusAccepted {
			t.Fatalf("HR event = %d: %s", got.status, got.raw)
		}
	}
	post(a, secretA, hrEvent("ev-1", "joiner", "A-PERSON"))
	// The agent A's joiner creates, labelled with A's HR id as only the joiner may label it
	// (docs/hr-person-label-plan.md). A development caller cannot label one by hand.
	if got := h.call(t, a, http.MethodPut, "/v1/instances/analyst-intern-person-a", labelledInstanceJSON); got.status != http.StatusUnprocessableEntity {
		t.Fatalf("labelled agent by hand = %d, want 422: %s", got.status, got.raw)
	}
	// The same agent without the label is accepted, under its own name, and is no one's.
	unlabelled := strings.ReplaceAll(instanceJSON, "analyst-intern-person-a", "hand-made-agent")
	if got := h.call(t, a, http.MethodPut, "/v1/instances/hand-made-agent", unlabelled); got.status != http.StatusCreated {
		t.Fatalf("unlabelled agent by hand = %d, want 201: %s", got.status, got.raw)
	}
	conn, err := store.Open(t.Context(), h.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var doc muistamov1.AgentInstance
	if err := json.Unmarshal([]byte(instanceJSON), &doc); err != nil {
		t.Fatal(err)
	}
	worker := registry.Actor{Tenant: a, Name: "workflow:test", RequestID: "hr-event:ev-1"}
	if _, _, err := registry.New(conn, h.key).CreateHRInstance(t.Context(), worker, doc, "A-PERSON", "ev-1"); err != nil {
		t.Fatalf("A's joiner agent: %v", err)
	}
	// B's worker cannot label an agent with A's person from A's joiner event.
	inB := registry.Actor{Tenant: b, Name: "workflow:attack", RequestID: "hr-event:ev-1"}
	if _, _, err := registry.New(conn, h.key).CreateHRInstance(t.Context(), inB, doc, "A-PERSON", "ev-1"); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("B's worker with A's joiner event = %v, want ErrConflict", err)
	}
	// A leaves. From then on A's joiner event creates nothing, under any name.
	post(a, secretA, strings.Replace(hrEvent("ev-2", "leaver", "A-PERSON"), "2026-10-25T09:00", "2026-10-26T09:00", 1))
	post(b, secretB, hrEvent("ev-b", "joiner", "B-PERSON"))
	late := doc
	late.Metadata.Name = "analyst-intern-person-a-2"
	if _, _, err := registry.New(conn, h.key).CreateHRInstance(t.Context(), worker, late, "A-PERSON", "ev-1"); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("A's joiner after A's leaver = %v, want ErrConflict", err)
	}
	const admin, auditor, nobody, adminOfB = "entra:aaaaaaaa-0000-4000-8000-00000000000a", "entra:aaaaaaaa-0000-4000-8000-00000000000b",
		"entra:aaaaaaaa-0000-4000-8000-00000000000c", "entra:bbbbbbbb-0000-4000-8000-00000000000a"
	role := func(tenant uuid.UUID, role string, people ...string) {
		t.Helper()
		op := registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: uuid.NewString()}
		if err := registry.ConfigureConsoleRole(t.Context(), h.db.OwnerURL, op, role, people, h.key); err != nil {
			t.Fatal(err)
		}
	}
	role(a, registry.ConsoleAdministrator, admin)
	role(a, registry.ConsoleAuditor, auditor)
	role(b, registry.ConsoleAdministrator, adminOfB)
	console := func(person, path string) response {
		t.Helper()
		return h.call(t, uuid.Nil, http.MethodGet, path, "", "Authorization", "Bearer "+person)
	}
	// Nothing from the payload or the binding: the email, the job code.
	leaks := func(raw string) bool {
		return strings.Contains(raw, "person-a@example.invalid") || strings.Contains(raw, "ANALYST_INTERN") || strings.Contains(raw, "@example")
	}

	signedInto = a
	feed := console(admin, "/v1/hr/receipts")
	if feed.status != http.StatusOK || !strings.Contains(feed.raw, `"ev-1"`) || !strings.Contains(feed.raw, `"ev-2"`) ||
		!strings.Contains(feed.raw, "A-PERSON") || strings.Contains(feed.raw, "B-PERSON") || leaks(feed.raw) {
		t.Errorf("administrator feed = %d: %s", feed.status, feed.raw)
	}
	if i, j := strings.Index(feed.raw, `"ev-2"`), strings.Index(feed.raw, `"ev-1"`); i < 0 || j < 0 || i > j {
		t.Errorf("the feed is not newest first: %s", feed.raw)
	}
	person := console(admin, "/v1/people/A-PERSON")
	if person.status != http.StatusOK || !strings.Contains(person.raw, `"analyst-intern-person-a"`) ||
		!strings.Contains(person.raw, `"ev-1"`) || leaks(person.raw) || strings.Contains(person.raw, "binding") ||
		strings.Contains(person.raw, "hand-made-agent") {
		t.Errorf("administrator person = %d: %s", person.status, person.raw)
	}
	// Not an administrator of A: an auditor, no role, and B's administrator signed in to A.
	for _, who := range []string{auditor, nobody, adminOfB} {
		for _, path := range []string{"/v1/hr/receipts", "/v1/people/A-PERSON", "/v1/people/NO-SUCH-PERSON"} {
			if got := console(who, path); got.status != http.StatusForbidden || strings.Contains(got.raw, "ev-1") || leaks(got.raw) {
				t.Errorf("%s GET %s = %d: %s", who, path, got.status, got.raw)
			}
		}
	}
	if got := console(admin, "/v1/people/NO-SUCH-PERSON"); got.status != http.StatusNotFound {
		t.Errorf("administrator, unknown person = %d, want 404", got.status)
	}

	// B's administrator in B sees B only; A's person does not exist there.
	signedInto = b
	if got := console(adminOfB, "/v1/hr/receipts"); got.status != http.StatusOK || !strings.Contains(got.raw, "B-PERSON") || strings.Contains(got.raw, "A-PERSON") {
		t.Errorf("B's administrator feed = %d: %s", got.status, got.raw)
	}
	if got := console(adminOfB, "/v1/people/A-PERSON"); got.status != http.StatusNotFound {
		t.Errorf("B's administrator, A's person = %d, want 404: %s", got.status, got.raw)
	}

	// Nothing beneath a person, and no id outside the pattern, reaches a console caller.
	signedInto = a
	for _, path := range []string{
		"/v1/people/A-PERSON/entra-link",
		"/v1/people/-A-PERSON",
		"/v1/people/A%2FPERSON",
		"/v1/people/A%20PERSON",
		"/v1/hr/events",
	} {
		if got := console(admin, path); got.status != http.StatusUnauthorized {
			t.Errorf("administrator GET %s = %d, want 401: %s", path, got.status, got.raw)
		}
	}

	// Development callers are unchanged: no console app, no role needed.
	for _, path := range []string{"/v1/hr/receipts", "/v1/people/A-PERSON"} {
		if got := h.call(t, a, http.MethodGet, path, ""); got.status != http.StatusOK || leaks(got.raw) {
			t.Errorf("development GET %s = %d: %s", path, got.status, got.raw)
		}
	}
}

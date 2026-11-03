package entra

// HUMAN REVIEW REQUIRED: live leaver reviews with the real registry and database
// (docs/live-review-plan.md): who a review names, the fence on a rehire, and what each refusal
// records. The knowledge service is a fake that checks every call's signature.

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/signature"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

const reviewSecret = "mks_test-only-not-a-secret-0123456789abcdef"

var managerUser = uuid.MustParse("5a000000-0000-4000-8000-0000000000aa")

type reviewCall struct {
	path string
	body map[string]any
}

// fakeReviews answers like the knowledge service: status with body, after checking the signature.
type fakeReviews struct {
	mu     sync.Mutex
	status int
	answer any
	calls  []reviewCall
}

func (f *fakeReviews) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	parts := map[string]string{}
	for _, p := range strings.Split(r.Header.Get("X-Muistamo-Signature"), ",") {
		if k, v, ok := strings.Cut(p, "="); ok {
			parts[k] = v
		}
	}
	given, _ := hex.DecodeString(parts["v1"])
	w.Header().Set("Content-Type", "application/json")
	if !hmac.Equal(given, signature.MAC([]byte(reviewSecret), parts["t"], raw)) || r.Header.Get("X-Muistamo-Tenant") != testTenant.String() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.calls = append(f.calls, reviewCall{path: r.URL.Path, body: body})
	status, answer := f.status, f.answer
	f.mu.Unlock()
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(answer)
}

func (f *fakeReviews) only(t *testing.T) reviewCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) != 1 {
		t.Fatalf("knowledge calls = %+v, want one", f.calls)
	}
	return f.calls[0]
}

func reviewsFixture(t *testing.T, fake *fakeReviews) (adapterFixture, *lifecycle.EntraActivities) {
	t.Helper()
	f, acts, _ := linkFixture(t)
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	if err := store.SetKnowledgeSecret(context.Background(), f.db.OwnerURL, testTenant, []byte(reviewSecret)); err != nil {
		t.Fatal(err)
	}
	acts.Knowledge = lifecycle.NewKnowledgeClient(server.URL)
	return f, acts
}

// seedPersonHR records an accepted live HR event for any person, as intake does.
func seedPersonHR(t *testing.T, f adapterFixture, id, kind, person, email, manager string, gen int64) muistamov1.EntraLifecycleRef {
	t.Helper()
	var event muistamov1.HREvent
	event.Id, event.Type = id, muistamov1.HREventType(kind)
	event.OccurredAt = time.Date(2026, 11, 3, 9, 0, int(gen), 0, time.UTC)
	event.Person.Id, event.Person.Email, event.Person.JobCode = person, email, "INTERN"
	if manager != "" {
		event.Person.ManagerEmail = &manager
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.conn.InTenant(context.Background(), f.actor.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version) VALUES($1,$2,$3,$4,'',$5,$6,$7,'accepted','pending','entra',(SELECT binding_version FROM identity_enrollments))`, f.actor.Tenant, id, kind, person, raw, event.OccurredAt, gen); err != nil {
			return err
		}
		_, err := evidence.Append(context.Background(), tx, f.key, evidence.Entry{Tenant: f.actor.Tenant, Actor: "hris:test", RequestID: id, Action: "hr.event.received", SubjectKind: "HRPerson", SubjectName: person, After: map[string]any{"eventId": id, "type": kind, "generation": gen, "decision": "accepted", "identityMode": "entra", "identityBindingVersion": binding().BindingVersion}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return adapterLifecycleRef(t, f, id)
}

// linkJoiner records the person's link as their joiner's lookup would.
func linkJoiner(t *testing.T, f adapterFixture, person string, joiner muistamov1.EntraLifecycleRef, user uuid.UUID) {
	t.Helper()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO person_entra_links (tenant_id,person_id,status,binding_version,entra_tenant_id,entra_user_object_id,receipt_id)
		VALUES ($1,$2,'matched',$3,$4,$5,$6)`, testTenant, person, binding().BindingVersion, binding().EntraTenantId, user, joiner.ReceiptId)
}

func openAnswer(id string) muistamov1.LeaverReview {
	return muistamov1.LeaverReview{Id: id, Person: "entra:" + userA.String(), Status: muistamov1.LeaverReviewStatusOpen,
		DeciderKind: muistamov1.LeaverReviewDeciderKindManager, Deadline: time.Now().Add(30 * 24 * time.Hour), EntryCount: 1}
}

// The person's leaving opens a review that names them, at its generation, and their manager, by
// the users their own joiners linked; control-plane evidence names neither user.
func TestALiveLeaverReviewNamesThePersonAndTheirManagerByUser(t *testing.T) {
	fake := &fakeReviews{status: 201}
	f, acts := reviewsFixture(t, fake)
	ctx := context.Background()
	linkJoiner(t, f, "HR-PERSON", adapterLifecycleRef(t, f, "join"), userA)
	manager := seedPersonHR(t, f, "mgr-join", "joiner", "HR-MANAGER", "manager@example.invalid", "", 1)
	linkJoiner(t, f, "HR-MANAGER", manager, managerUser)
	leave := seedPersonHR(t, f, "leave", "leaver", "HR-PERSON", "person@example.invalid", " Manager@Example.invalid ", 2)
	fake.answer = openAnswer("entra-leaver:" + leave.ReceiptId.String())

	opened, err := acts.EntraOpenReview(ctx, leave)
	if err != nil || !opened.Opened || opened.ID != "entra-leaver:"+leave.ReceiptId.String() {
		t.Fatalf("opened = %+v, %v", opened, err)
	}
	call := fake.only(t)
	person := call.body["person"].(map[string]any)
	deciders := call.body["deciders"].([]any)
	if call.path != "/v1/knowledge/internal/leaver-reviews" || call.body["id"] != opened.ID || call.body["generation"] != float64(2) ||
		person["user"] != "entra:"+userA.String() || person["email"] != nil || person["hrPersonId"] != "HR-PERSON" ||
		len(deciders) != 1 || deciders[0].(map[string]any)["user"] != "entra:"+managerUser.String() || deciders[0].(map[string]any)["email"] != nil {
		t.Fatalf("open request = %+v", call)
	}
	after := testdb.Scalar(t, f.db.OwnerURL, `SELECT after::text FROM evidence_events WHERE action='personal-layer.review-opened'`)
	if strings.Contains(after, userA.String()) || strings.Contains(after, managerUser.String()) || !strings.Contains(after, `"generation": 2`) {
		t.Fatalf("review evidence = %s", after)
	}
}

// Only a manager whose own link still stands decides; otherwise the privacy officers do.
func TestALiveLeaversManagerMustStillHoldTheirOwnLink(t *testing.T) {
	cases := map[string]func(t *testing.T, f adapterFixture){
		"no manager given": func(t *testing.T, f adapterFixture) {},
		"manager has left": func(t *testing.T, f adapterFixture) {
			linkJoiner(t, f, "HR-MANAGER", seedPersonHR(t, f, "mgr-join", "joiner", "HR-MANAGER", "manager@example.invalid", "", 1), managerUser)
			seedPersonHR(t, f, "mgr-leave", "leaver", "HR-MANAGER", "manager@example.invalid", "", 2)
		},
		"manager never linked": func(t *testing.T, f adapterFixture) {
			seedPersonHR(t, f, "mgr-join", "joiner", "HR-MANAGER", "manager@example.invalid", "", 1)
		},
		"two people share the email": func(t *testing.T, f adapterFixture) {
			linkJoiner(t, f, "HR-MANAGER", seedPersonHR(t, f, "mgr-join", "joiner", "HR-MANAGER", "manager@example.invalid", "", 1), managerUser)
			linkJoiner(t, f, "HR-OTHER", seedPersonHR(t, f, "other-join", "joiner", "HR-OTHER", "manager@example.invalid", "", 1), uuid.New())
		},
	}
	for name, seed := range cases {
		t.Run(name, func(t *testing.T) {
			fake := &fakeReviews{status: 201}
			f, acts := reviewsFixture(t, fake)
			linkJoiner(t, f, "HR-PERSON", adapterLifecycleRef(t, f, "join"), userA)
			seed(t, f)
			manager := "manager@example.invalid"
			if name == "no manager given" {
				manager = ""
			}
			leave := seedPersonHR(t, f, "leave", "leaver", "HR-PERSON", "person@example.invalid", manager, 3)
			fake.answer = openAnswer("entra-leaver:" + leave.ReceiptId.String())
			if _, err := acts.EntraOpenReview(context.Background(), leave); err != nil {
				t.Fatal(err)
			}
			if deciders := fake.only(t).body["deciders"].([]any); len(deciders) != 0 {
				t.Fatalf("deciders = %v, want none (privacy officers)", deciders)
			}
		})
	}
}

// No review is opened, and no call is made, for a person the knowledge service cannot name or a
// leaving already overtaken by a rehire; each is recorded with its reason.
func TestALiveReviewThatCannotBeOpenedIsRecordedNotSent(t *testing.T) {
	for name, seed := range map[string]func(t *testing.T, f adapterFixture) muistamov1.EntraLifecycleRef{
		"person never linked": func(t *testing.T, f adapterFixture) muistamov1.EntraLifecycleRef {
			return seedPersonHR(t, f, "leave", "leaver", "HR-PERSON", "person@example.invalid", "", 2)
		},
		"rehired before the review": func(t *testing.T, f adapterFixture) muistamov1.EntraLifecycleRef {
			linkJoiner(t, f, "HR-PERSON", adapterLifecycleRef(t, f, "join"), userA)
			leave := seedPersonHR(t, f, "leave", "leaver", "HR-PERSON", "person@example.invalid", "", 2)
			seedPersonHR(t, f, "rehire", "joiner", "HR-PERSON", "person@example.invalid", "", 3)
			return leave
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakeReviews{status: 201}
			f, acts := reviewsFixture(t, fake)
			opened, err := acts.EntraOpenReview(context.Background(), seed(t, f))
			if err != nil || opened.Opened || len(fake.calls) != 0 {
				t.Fatalf("opened = %+v, %v, calls %d", opened, err, len(fake.calls))
			}
			if n := evidenceCount(t, f, "personal-layer.review-not-opened"); n != "1" {
				t.Fatalf("not-opened evidence = %s", n)
			}
		})
	}
}

// The knowledge service's superseded refusal is final: recorded, not retried, not a failure.
func TestASupersededLiveReviewIsRecordedAsFinal(t *testing.T) {
	fake := &fakeReviews{status: 409, answer: map[string]any{"type": "https://muistamo.dev/problems/superseded", "title": "Superseded by a later HR event", "status": 409}}
	f, acts := reviewsFixture(t, fake)
	ctx := context.Background()
	linkJoiner(t, f, "HR-PERSON", adapterLifecycleRef(t, f, "join"), userA)
	leave := seedPersonHR(t, f, "leave", "leaver", "HR-PERSON", "person@example.invalid", "", 2)
	opened, err := acts.EntraOpenReview(ctx, leave)
	if err != nil || opened.Opened {
		t.Fatalf("opened = %+v, %v", opened, err)
	}
	if n := evidenceCount(t, f, "personal-layer.review-superseded"); n != "1" {
		t.Fatalf("superseded evidence = %s", n)
	}
	state, err := acts.EntraExpireReview(ctx, leave, "entra-leaver:"+leave.ReceiptId.String())
	if err != nil || !state.Closed {
		t.Fatalf("superseded expiry = %+v, %v", state, err)
	}
	// Any other refusal of an expiry is not retried either, and never reported closed.
	fake.status, fake.answer = 422, map[string]any{"title": "Invalid request", "status": 422}
	if state, err := acts.EntraExpireReview(ctx, leave, "entra-leaver:"+leave.ReceiptId.String()); err == nil || state.Closed {
		t.Fatalf("refused expiry = %+v, %v", state, err)
	}
}

// A rehire fences the person under the user their earlier review was opened with, at the
// rehire's generation; a person never linked needs no fence and gets no call.
func TestARehireFencesUnderTheEarlierUser(t *testing.T) {
	fake := &fakeReviews{status: 200}
	f, acts := reviewsFixture(t, fake)
	ctx := context.Background()
	linkJoiner(t, f, "HR-PERSON", adapterLifecycleRef(t, f, "join"), userA)
	seedPersonHR(t, f, "leave", "leaver", "HR-PERSON", "person@example.invalid", "", 2)
	rehire := seedPersonHR(t, f, "rehire", "joiner", "HR-PERSON", "person@example.invalid", "", 3)
	fake.answer = muistamov1.LeaverReviewFenced{User: "entra:" + userA.String(), Generation: 3, Cancelled: []string{"entra-leaver:x"}}
	if err := acts.EntraFenceReview(ctx, rehire); err != nil {
		t.Fatal(err)
	}
	call := fake.only(t)
	if call.path != "/v1/knowledge/internal/leaver-reviews/fence" || call.body["user"] != "entra:"+userA.String() || call.body["generation"] != float64(3) {
		t.Fatalf("fence request = %+v", call)
	}
	after := testdb.Scalar(t, f.db.OwnerURL, `SELECT after::text FROM evidence_events WHERE action='personal-layer.review-fenced'`)
	if strings.Contains(after, userA.String()) || !strings.Contains(after, "entra-leaver:x") {
		t.Fatalf("fence evidence = %s", after)
	}
	// A leaver receipt never fences.
	if err := acts.EntraFenceReview(ctx, adapterLifecycleRef(t, f, "leave")); err == nil {
		t.Fatal("a leaver sent a fence")
	}
}

func TestAPersonNeverLinkedNeedsNoFence(t *testing.T) {
	fake := &fakeReviews{status: 200}
	f, acts := reviewsFixture(t, fake)
	if err := acts.EntraFenceReview(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil || len(fake.calls) != 0 {
		t.Fatalf("fence for an unlinked person: %v, calls %d", err, len(fake.calls))
	}
}

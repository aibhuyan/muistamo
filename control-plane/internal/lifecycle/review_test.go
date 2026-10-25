package lifecycle_test

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

	"go.temporal.io/sdk/testsuite"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/signature"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

const knowledgeSecret = "mks_test-only-not-a-secret-0123456789abcdef"

// fakeKnowledge checks every call's signature exactly as the knowledge service does, and
// answers with status and review.
type fakeKnowledge struct {
	mu       sync.Mutex
	status   int
	review   muistamov1.LeaverReview
	requests []recorded
}

type recorded struct {
	path   string
	tenant string
	body   []byte
	valid  bool
}

func (f *fakeKnowledge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	parts := map[string]string{}
	for _, p := range strings.Split(r.Header.Get("X-Muistamo-Signature"), ",") {
		if k, v, ok := strings.Cut(p, "="); ok {
			parts[k] = v
		}
	}
	given, _ := hex.DecodeString(parts["v1"])
	valid := hmac.Equal(given, signature.MAC([]byte(knowledgeSecret), parts["t"], body))
	f.mu.Lock()
	f.requests = append(f.requests, recorded{path: r.URL.Path, tenant: r.Header.Get("X-Muistamo-Tenant"), body: body, valid: valid})
	status, review := f.status, f.review
	f.mu.Unlock()
	if !valid {
		status = http.StatusUnauthorized
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status < 300 {
		_ = json.NewEncoder(w).Encode(review)
		return
	}
	_, _ = w.Write([]byte(`{"title":"Invalid request","status":422,"detail":"cannot open a review: no identity mapping is configured"}`))
}

func openReview(status muistamov1.LeaverReviewStatus) muistamov1.LeaverReview {
	return muistamov1.LeaverReview{Id: "wf-test:run", Person: "dev:person-a@example.invalid", Status: status,
		DeciderKind: muistamov1.LeaverReviewDeciderKindManager, Deadline: time.Now().Add(30 * 24 * time.Hour), EntryCount: 2}
}

func reviewFixture(t *testing.T, fake *fakeKnowledge, withSecret bool) (fixture, *testsuite.TestActivityEnvironment) {
	t.Helper()
	f := setup(t)
	if fake != nil {
		srv := httptest.NewServer(fake)
		t.Cleanup(srv.Close)
		f.acts.Knowledge = lifecycle.NewKnowledgeClient(srv.URL)
	}
	if withSecret {
		if err := store.SetKnowledgeSecret(context.Background(), f.db.OwnerURL, f.scope.Tenant, []byte(knowledgeSecret)); err != nil {
			t.Fatal(err)
		}
	}
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestActivityEnvironment()
	env.RegisterActivity(f.acts)
	return f, env
}

func lastAfter(t *testing.T, f fixture, action string) map[string]any {
	t.Helper()
	raw := testdb.Scalar(t, f.db.OwnerURL, `SELECT coalesce(after::text, '') FROM evidence_events WHERE action = '`+action+`' ORDER BY seq DESC LIMIT 1`)
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("no %s event (%q): %v", action, raw, err)
	}
	return out
}

var leaver = lifecycle.Person{ID: "e-1", Email: "person-a@example.invalid", JobCode: "ANALYST_INTERN", ManagerEmail: "manager-m@example.invalid"}

func TestReviewNotOpenedIsRecordedNotSkipped(t *testing.T) {
	for name, c := range map[string]struct {
		fake       *fakeKnowledge
		withSecret bool
		reason     string
	}{
		"no knowledge service": {nil, true, "MUISTAMO_KNOWLEDGE_URL"},
		"no tenant secret":     {&fakeKnowledge{status: 201, review: openReview("open")}, false, "knowledge-secret"},
		"refused":              {&fakeKnowledge{status: 422}, true, "no identity mapping"},
	} {
		t.Run(name, func(t *testing.T) {
			f, env := reviewFixture(t, c.fake, c.withSecret)
			val, err := env.ExecuteActivity(f.acts.OpenPersonalLayerReview, f.scope, leaver, []string(nil))
			if err != nil {
				t.Fatal(err)
			}
			var got lifecycle.ReviewOpened
			if err := val.Get(&got); err != nil || got.Opened {
				t.Fatalf("opened = %+v, %v; want not opened", got, err)
			}
			if reason, _ := lastAfter(t, f, "personal-layer.review-not-opened")["reason"].(string); !strings.Contains(reason, c.reason) {
				t.Errorf("reason = %q, want it to mention %q", reason, c.reason)
			}
			if c.fake != nil && !c.withSecret && len(c.fake.requests) != 0 {
				t.Errorf("an unsigned call was made without a secret")
			}
		})
	}
}

func TestReviewOpensWithManagerThenSponsorSigned(t *testing.T) {
	fake := &fakeKnowledge{status: 201, review: openReview("open")}
	f, env := reviewFixture(t, fake, true)
	f.template(t, "analyst-intern")
	var doc muistamov1.AgentInstance
	if err := json.Unmarshal([]byte(`{"apiVersion":"muistamo.dev/v1","kind":"AgentInstance","metadata":{"name":"i-1"},
		"spec":{"templateRef":{"name":"analyst-intern","version":"1"},"binding":{"type":"user","ref":"person-a@example.invalid"},
		"state":"requested","sponsor":"sponsor-s@example.invalid"}}`), &doc); err != nil {
		t.Fatal(err)
	}
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:admin@example.invalid", RequestID: "seed"}
	if _, _, err := f.svc.ApplyInstance(context.Background(), actor, doc, ""); err != nil {
		t.Fatal(err)
	}

	val, err := env.ExecuteActivity(f.acts.OpenPersonalLayerReview, f.scope, leaver, []string{"i-1"})
	if err != nil {
		t.Fatal(err)
	}
	var got lifecycle.ReviewOpened
	if err := val.Get(&got); err != nil || !got.Opened || got.ID != "wf-test:run" {
		t.Fatalf("opened = %+v, %v", got, err)
	}
	if len(fake.requests) != 1 || !fake.requests[0].valid || fake.requests[0].tenant != f.scope.Tenant.String() {
		t.Fatalf("requests = %+v, want one validly signed call for the tenant", fake.requests)
	}
	var sent muistamov1.LeaverReviewOpen
	if err := json.Unmarshal(fake.requests[0].body, &sent); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sent.Id, "wf-test:") || sent.Person.Email != leaver.Email || *sent.Person.HrPersonId != "e-1" {
		t.Errorf("sent = %+v", sent)
	}
	if len(sent.Deciders) != 2 || sent.Deciders[0].Email != "manager-m@example.invalid" || sent.Deciders[0].Kind != "manager" ||
		sent.Deciders[1].Email != "sponsor-s@example.invalid" || sent.Deciders[1].Kind != "sponsor" {
		t.Errorf("deciders = %+v, want manager then sponsor", sent.Deciders)
	}
	if after := lastAfter(t, f, "personal-layer.review-opened"); after["review"] != "wf-test:run" || after["status"] != "open" {
		t.Errorf("evidence = %v", after)
	}
}

func TestReviewServerErrorsAreRetried(t *testing.T) {
	f, env := reviewFixture(t, &fakeKnowledge{status: 503}, true)
	if _, err := env.ExecuteActivity(f.acts.OpenPersonalLayerReview, f.scope, leaver, []string(nil)); err == nil {
		t.Fatal("a 503 from the knowledge service must fail the activity so Temporal retries it")
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action LIKE 'personal-layer.%'`); n != 0 {
		t.Errorf("a transient failure was recorded as an outcome: %d events", n)
	}
}

func TestExpireReportsKeptDeadlineOrRecordsTheOutcome(t *testing.T) {
	fake := &fakeKnowledge{status: 200, review: openReview("open")}
	f, env := reviewFixture(t, fake, true)
	val, err := env.ExecuteActivity(f.acts.ExpirePersonalLayerReview, f.scope, "e-1", "wf-test:run")
	if err != nil {
		t.Fatal(err)
	}
	var state lifecycle.ReviewState
	if err := val.Get(&state); err != nil || state.Closed || state.Deadline.IsZero() {
		t.Fatalf("kept review: state = %+v, %v", state, err)
	}
	expired := muistamov1.LeaverReviewOutcomeExpired
	fake.review = openReview("closed")
	fake.review.Outcome = &expired
	val, err = env.ExecuteActivity(f.acts.ExpirePersonalLayerReview, f.scope, "e-1", "wf-test:run")
	if err != nil {
		t.Fatal(err)
	}
	if err := val.Get(&state); err != nil || !state.Closed {
		t.Fatalf("expired review: state = %+v, %v", state, err)
	}
	if after := lastAfter(t, f, "personal-layer.review-closed"); after["outcome"] != "expired" {
		t.Errorf("evidence = %v", after)
	}
	if !strings.HasSuffix(fake.requests[0].path, "/wf-test:run/expire") {
		t.Errorf("path = %s", fake.requests[0].path)
	}
}

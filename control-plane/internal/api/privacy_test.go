package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

const (
	subjectIdentity = "dev:person-a@example.invalid"
	subjectEmail    = "person-a@example.invalid"
	officer         = "dpo@example.invalid"
)

func erasureBody(id uuid.UUID, reason string) string {
	return `{"id":"` + id.String() + `","reason":"` + reason + `",` +
		`"subject":{"identities":["` + subjectIdentity + `"],"email":"` + subjectEmail + `","hrPersonId":"A-PERSON"}}`
}

const accessBody = `{"subject":{"identities":["` + subjectIdentity + `"],"email":"` + subjectEmail + `","hrPersonId":"A-PERSON"}}`

// seedPerson makes person A appear in every place the control plane can hold them: an HR event,
// an instance bound to their email and sponsored by them, a template version, a catalogue
// request and approval, an approver role, and a policy they last changed.
func seedPerson(t *testing.T, h harness, tenant uuid.UUID) {
	t.Helper()
	if err := store.SetPrivacyOfficers(context.Background(), h.db.OwnerURL, tenant, []string{"dev:" + officer}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCatalogueApprovers(context.Background(), h.db.OwnerURL, tenant, []string{subjectIdentity, "dev:cat-2@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if got := h.postHR(t, tenant, h.hrSecret(t, tenant), time.Now(), hrEvent("ev-1", "joiner", "A-PERSON")); got.status != http.StatusAccepted {
		t.Fatalf("HR event = %d: %s", got.status, got.raw)
	}
	// This fixture's dispatcher has no worker. Explicitly finish its simulated setup so
	// privacy tests model completed work rather than an outstanding child with original PII.
	app, err := store.Open(context.Background(), h.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.New(app, h.key).SettleHRSetup(context.Background(), registry.Actor{Tenant: tenant, Name: "workflow:fake-ev-1", RequestID: "fixture-setup"}, "ev-1", 1); err != nil {
		app.Close()
		t.Fatal(err)
	}
	app.Close()
	medium := strings.Replace(templateJSON, `"modelAlias":"reasoning-default"`, `"modelAlias":"reasoning-default","riskTier":"medium"`, 1)
	for _, c := range []struct{ path, body string }{
		{"/v1/templates/analyst-intern", medium},
		{"/v1/instances/analyst-intern-person-a", strings.Replace(instanceJSON, `"state":"requested"`,
			`"state":"requested","sponsor":"`+subjectEmail+`"`, 1)},
		{"/v1/links/intern-to-market", linkJSON},
	} {
		if got := h.call(t, tenant, http.MethodPut, c.path, c.body); got.status != http.StatusCreated {
			t.Fatalf("PUT %s = %d: %s", c.path, got.status, got.raw)
		}
	}
	req := h.call(t, tenant, http.MethodPost, "/v1/templates/analyst-intern/versions/1/publication", "", "X-Muistamo-Actor", "cat-2@example.invalid")
	if req.status != http.StatusCreated {
		t.Fatalf("publication = %d: %s", req.status, req.raw)
	}
	if got := h.call(t, tenant, http.MethodPost, "/v1/catalogue/requests/"+req.body["id"].(string)+"/decision",
		`{"decision":"approve","reason":"ok"}`); got.status != http.StatusOK {
		t.Fatalf("approval by A = %d: %s", got.status, got.raw)
	}
	// A second template whose publication A requested, still pending.
	if got := h.call(t, tenant, http.MethodPut, "/v1/templates/analyst-b", strings.Replace(medium, "analyst-intern", "analyst-b", 1)); got.status != http.StatusCreated {
		t.Fatalf("second template = %d: %s", got.status, got.raw)
	}
	if got := h.call(t, tenant, http.MethodPost, "/v1/templates/analyst-b/versions/1/publication", ""); got.status != http.StatusCreated {
		t.Fatalf("A's publication request = %d: %s", got.status, got.raw)
	}
	// A clone, two models, an alias and a rolled-back rollout, all by A.
	for _, c := range []struct{ method, path, body, who string }{
		{http.MethodPut, "/v1/clones/analyst-fi", `{"apiVersion":"muistamo.dev/v1","kind":"AgentClone","metadata":{"name":"analyst-fi"},"spec":{"template":"analyst-intern","sync":"follow"}}`, ""},
		{http.MethodPut, "/v1/models/m-eu", modelJSON("m-eu", "eu-west-1"), ""},
		{http.MethodPost, "/v1/models/m-eu/approval", `{"decision":"approve","reason":"ok"}`, officer},
		{http.MethodPut, "/v1/models/m-two", modelJSON("m-two", "eu-west-1"), ""},
		{http.MethodPost, "/v1/models/m-two/approval", `{"decision":"approve","reason":"ok"}`, officer},
		{http.MethodPut, "/v1/model-aliases/a-fast", aliasJSON("a-fast", "m-eu"), ""},
	} {
		var who []string
		if c.who != "" {
			who = as(c.who)
		}
		if got := h.call(t, tenant, c.method, c.path, c.body, who...); got.status >= 300 {
			t.Fatalf("%s %s = %d: %s", c.method, c.path, got.status, got.raw)
		}
	}
	rollout := h.call(t, tenant, http.MethodPost, "/v1/model-aliases/a-fast/rollouts", `{"to":"m-two","reason":"cheaper","acknowledgeUnevaluated":true}`)
	if rollout.status != http.StatusCreated {
		t.Fatalf("rollout = %d: %s", rollout.status, rollout.raw)
	}
	if got := h.call(t, tenant, http.MethodPost, "/v1/rollouts/"+rollout.body["id"].(string)+"/rollback", `{"reason":"quality"}`); got.status != http.StatusOK {
		t.Fatalf("rollback = %d: %s", got.status, got.raw)
	}
	// A key A issued, and a gateway call made as A (step 2 of docs/agentgateway-plan.md).
	gatewayKey, gatewayCall := uuid.New(), uuid.New()
	testdb.ExecIn(t, h.db.AppURL, tenant, insertKey, tenant, gatewayKey)
	testdb.ExecIn(t, h.db.AppURL, tenant, insertModelCall, tenant, gatewayCall, gatewayKey)
	testdb.ExecIn(t, h.db.AppURL, tenant, insertUsage, tenant, gatewayCall)
	// And a key A revoked: erasure must pseudonymise revoked_by through the revocation trigger.
	revokedKey := uuid.New()
	testdb.ExecIn(t, h.db.AppURL, tenant, insertKey, tenant, revokedKey)
	testdb.ExecIn(t, h.db.AppURL, tenant, `UPDATE virtual_keys SET status = 'revoked', revoked_by = $2,
		revoke_reason = 'test' WHERE id = $1`, revokedKey, subjectIdentity)
	// A decided a model under one identity that they changed under another: erasure maps both to
	// one pseudonym, which the no-self-approval check must not turn into a failed erasure.
	conn, err := pgx.Connect(context.Background(), h.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(context.Background(), `UPDATE model_catalogue SET decided_by = $2, updated_by = $3 WHERE tenant_id = $1 AND name = 'm-two'`,
		tenant, subjectIdentity, subjectEmail); err != nil {
		t.Fatal(err)
	}
}

func retire(t *testing.T, h harness, tenant uuid.UUID) {
	t.Helper()
	for i, to := range []string{"suspended", "retired"} {
		etag := `"` + string(rune('1'+i)) + `"`
		if got := h.call(t, tenant, http.MethodPost, "/v1/instances/analyst-intern-person-a/transitions", `{"to":"`+to+`"}`, "If-Match", etag); got.status != http.StatusOK {
			t.Fatalf("to %s = %d: %s", to, got.status, got.raw)
		}
	}
}

func asOfficer() []string { return []string{"X-Muistamo-Actor", officer} }

// remaining lists, per table, the tenant's rows still holding the subject's identity or email.
// It reads as the server's role, which row-level security binds (the owner may bypass it).
func remaining(t *testing.T, h harness, tenant uuid.UUID) map[string]int {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), h.db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	out := map[string]int{}
	err = pgx.BeginFunc(context.Background(), conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `SELECT set_config('muistamo.tenant_id', $1, true)`, tenant.String()); err != nil {
			return err
		}
		for _, table := range registry.PersonalDataTables {
			rows, err := registry.RowsMentioning(context.Background(), tx, table, []string{subjectIdentity, subjectEmail})
			if err != nil {
				return err
			}
			if len(rows) > 0 {
				out[table] = len(rows)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestErasureRemovesThePersonEverywhereButEvidence(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
	a := h.tenant(t, "tenant-a")
	seedPerson(t, h, a)

	before := remaining(t, h, a)
	for _, table := range []string{"agent_template_versions", "agent_instances", "hr_events", "catalogue_approvers",
		"catalogue_requests", "catalogue_approvals", "policy_documents", "evidence_events"} {
		if before[table] == 0 {
			t.Errorf("seed left %s without the person; the test proves nothing there", table)
		}
	}

	id := uuid.New()
	// Refused while the person still has an instance that is not retired.
	if got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", erasureBody(id, "DSR-1"), asOfficer()...); got.status != http.StatusConflict {
		t.Fatalf("erasure with an active instance = %d, want 409: %s", got.status, got.raw)
	}
	retire(t, h, a)

	got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", erasureBody(id, "DSR-1"), asOfficer()...)
	if got.status != http.StatusCreated {
		t.Fatalf("erasure = %d: %s", got.status, got.raw)
	}
	if strings.Contains(got.raw, subjectEmail) || strings.Contains(got.raw, "A-PERSON") {
		t.Errorf("the proof names the person: %s", got.raw)
	}
	counts, _ := got.body["counts"].(map[string]any)
	for _, k := range []string{"agent_template_versions.created_by", "catalogue_requests.requested_by", "catalogue_approvals.approver",
		"policy_documents.updated_by", "catalogue_approvers", "agent_instances.document", "hr_events.payload",
		"virtual_keys.created_by", "virtual_keys.revoked_by", "gateway_calls.person"} {
		if n, _ := counts[k].(float64); n < 1 {
			t.Errorf("count %s = %v, want at least 1", k, counts[k])
		}
	}
	if got.body["pseudonym"] != "erased:"+id.String() || got.body["subjectDigest"] != registry.SubjectDigest(a, subject()) {
		t.Errorf("proof pseudonym/digest: %s", got.raw)
	}

	// Nothing but the retained evidence still holds the person's identity or email.
	after := remaining(t, h, a)
	if len(after) != 1 || after["evidence_events"] == 0 {
		t.Errorf("rows still naming the person after erasure: %v, want evidence_events only", after)
	}
	inst := h.call(t, a, http.MethodGet, "/v1/instances/analyst-intern-person-a", "")
	spec := inst.body["document"].(map[string]any)["spec"].(map[string]any)
	if spec["binding"].(map[string]any)["ref"] != "erased:"+id.String() || spec["sponsor"] != "erased:"+id.String() {
		t.Errorf("instance after erasure: %s", inst.raw)
	}
	// The retained instance name is still there, as the proof says.
	if inst.status != http.StatusOK {
		t.Errorf("instance = %d", inst.status)
	}

	// The proof is evidenced; repeating the request returns it unchanged and writes nothing.
	if n := events(t, h, a, "privacy.erasure.completed"); n != 1 {
		t.Errorf("privacy.erasure.completed events = %d, want 1", n)
	}
	again := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", erasureBody(id, "DSR-1"), asOfficer()...)
	if again.status != http.StatusOK || again.body["completedAt"] != got.body["completedAt"] {
		t.Errorf("repeat = %d %s, want 200 with the stored proof", again.status, again.raw)
	}
	if n := events(t, h, a, "privacy.erasure.completed"); n != 1 {
		t.Errorf("a repeat recorded another erasure: %d", n)
	}
	read := h.call(t, a, http.MethodGet, "/v1/privacy/erasures/"+id.String(), "", asOfficer()...)
	if read.status != http.StatusOK || read.body["completedAt"] != got.body["completedAt"] {
		t.Errorf("GET proof = %d %s", read.status, read.raw)
	}
	// The same id for someone else is a conflict, not a silent reuse.
	other := strings.ReplaceAll(erasureBody(id, "DSR-1"), "person-a", "person-z")
	if got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", other, asOfficer()...); got.status != http.StatusConflict {
		t.Errorf("id reused for another person = %d, want 409", got.status)
	}
}

func subject() muistamov1.PrivacySubject {
	hr := "A-PERSON"
	return muistamov1.PrivacySubject{Identities: []string{subjectIdentity}, Email: subjectEmail, HrPersonId: &hr}
}

func TestErasureAndAccessAreForPrivacyOfficers(t *testing.T) {
	h := newHarnessWithHR(t, api.InsecureDevHeaders{}, &fakeDispatcher{})
	a := h.tenant(t, "tenant-a")
	seedPerson(t, h, a)
	retire(t, h, a)

	// The person, or anyone else who is not an officer, cannot erase.
	for _, who := range []string{"person-a@example.invalid", "cat-2@example.invalid"} {
		if got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", erasureBody(uuid.New(), "x"), "X-Muistamo-Actor", who); got.status != http.StatusForbidden {
			t.Errorf("erasure by %s = %d, want 403", who, got.status)
		}
		if got := h.call(t, a, http.MethodGet, "/v1/privacy/erasures/"+uuid.NewString(), "", "X-Muistamo-Actor", who); got.status != http.StatusForbidden {
			t.Errorf("proof read by %s = %d, want 403", who, got.status)
		}
	}
	// An officer cannot erase themselves.
	self := strings.NewReplacer(subjectIdentity, "dev:"+officer, subjectEmail, officer).Replace(erasureBody(uuid.New(), "x"))
	if got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", self, asOfficer()...); got.status != http.StatusForbidden {
		t.Errorf("officer erasing themselves = %d, want 403", got.status)
	}
	// The stored reason must not name the person.
	if got := h.call(t, a, http.MethodPost, "/v1/privacy/erasures", erasureBody(uuid.New(), "request from "+subjectEmail), asOfficer()...); got.status != http.StatusUnprocessableEntity {
		t.Errorf("reason naming the person = %d, want 422", got.status)
	}
	if n := events(t, h, a, "privacy.erasure.completed"); n != 0 {
		t.Errorf("refused requests recorded %d erasures", n)
	}

	// Access: the person may export what is under their own identity, and nothing keyed by email.
	own := h.call(t, a, http.MethodPost, "/v1/privacy/access", `{"subject":{"identities":["`+subjectIdentity+`"],"email":"`+subjectEmail+`"}}`)
	if own.status != http.StatusOK {
		t.Fatalf("own export = %d: %s", own.status, own.raw)
	}
	sections := own.body["sections"].(map[string]any)
	if rows, _ := sections["agent_template_versions"].([]any); len(rows) != 2 {
		t.Errorf("own export template versions = %d, want 2", len(rows))
	}
	if rows, _ := sections["hr_events"].([]any); len(rows) != 0 {
		t.Errorf("self-service export returned email-keyed HR events: %d", len(rows))
	}
	// Someone else's data needs an officer.
	if got := h.call(t, a, http.MethodPost, "/v1/privacy/access", accessBody, "X-Muistamo-Actor", "cat-2@example.invalid"); got.status != http.StatusForbidden {
		t.Errorf("export of someone else = %d, want 403", got.status)
	}
	full := h.call(t, a, http.MethodPost, "/v1/privacy/access", accessBody, asOfficer()...)
	if full.status != http.StatusOK {
		t.Fatalf("officer export = %d: %s", full.status, full.raw)
	}
	fs := full.body["sections"].(map[string]any)
	for _, table := range []string{"hr_events", "agent_instances", "agent_template_versions", "catalogue_requests", "catalogue_approvals", "policy_documents", "evidence_events"} {
		if rows, _ := fs[table].([]any); len(rows) == 0 {
			t.Errorf("officer export has nothing in %s", table)
		}
	}
	// The access record names counts, never the person.
	var after string
	if err := pgx.BeginFunc(context.Background(), mustConn(t, h.db.OwnerURL), func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT after::text FROM evidence_events WHERE action = 'privacy.access.exported' ORDER BY seq DESC LIMIT 1`).Scan(&after)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after, subjectEmail) || strings.Contains(after, "A-PERSON") {
		t.Errorf("access evidence names the person: %s", after)
	}
	var v map[string]any
	if json.Unmarshal([]byte(after), &v) != nil || v["counts"] == nil {
		t.Errorf("access evidence = %s", after)
	}
}

func mustConn(t *testing.T, url string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

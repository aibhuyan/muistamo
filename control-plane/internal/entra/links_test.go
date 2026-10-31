package entra

// HUMAN REVIEW REQUIRED: the joiner's Entra user link, with the real registry and database.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.temporal.io/sdk/temporal"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

const officer = "dev:officer@example.invalid"

func linkFixture(t *testing.T) (adapterFixture, *lifecycle.EntraActivities, registry.Actor) {
	t.Helper()
	f := setupAdapter(t)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO privacy_officers (tenant_id, officer) VALUES ($1, $2)`, testTenant, officer)
	acts := &lifecycle.EntraActivities{Registry: f.svc, Identity: f.adapter, Revoker: &lifecycle.Simulated{}, Users: f.adapter}
	return f, acts, registry.Actor{Tenant: testTenant, Name: officer, RequestID: "officer-read"}
}

func evidenceCount(t *testing.T, f adapterFixture, action string) string {
	t.Helper()
	return testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM evidence_events WHERE action=$1`, action)
}

func TestJoinerLinksTheHRPersonToTheirEntraUser(t *testing.T) {
	f, acts, reader := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON"), user(userB, "HR-OTHER")}
	join := adapterLifecycleRef(t, f, "join")
	if err := acts.EntraLinkUser(context.Background(), join); err != nil {
		t.Fatal(err)
	}
	link, err := f.svc.GetEntraUserLink(context.Background(), reader, "HR-PERSON")
	if err != nil || link.Status != "matched" || link.EntraUserObjectId == nil || *link.EntraUserObjectId != userA || link.ReceiptId != join.ReceiptId {
		t.Fatalf("link = %+v, %v", link, err)
	}
	// A retried activity changes nothing and signs nothing more.
	if err := acts.EntraLinkUser(context.Background(), join); err != nil {
		t.Fatal(err)
	}
	if n := evidenceCount(t, f, "identity.user.linked"); n != "1" {
		t.Fatalf("linked evidence events = %s", n)
	}
	// The retained evidence never names the user: erasure deletes the link, not the evidence.
	after := testdb.Scalar(t, f.db.OwnerURL, `SELECT after::text FROM evidence_events WHERE action='identity.user.linked'`)
	if strings.Contains(after, userA.String()) || !strings.Contains(after, `"matched"`) || !strings.Contains(after, `"user"`) {
		t.Fatalf("link evidence = %s", after)
	}
}

func TestUnmatchedAndAmbiguousUsersAreRecordedWithoutAnObjectID(t *testing.T) {
	for status, users := range map[string][]map[string]any{
		"unmatched": {user(userB, "HR-OTHER")},
		"ambiguous": {user(userA, "HR-PERSON"), user(userB, "HR-PERSON")},
	} {
		t.Run(status, func(t *testing.T) {
			f, acts, reader := linkFixture(t)
			f.graph.users = users
			if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
				t.Fatal(err)
			}
			link, err := f.svc.GetEntraUserLink(context.Background(), reader, "HR-PERSON")
			if err != nil || string(link.Status) != status || link.EntraUserObjectId != nil {
				t.Fatalf("link = %+v, %v", link, err)
			}
			if n := evidenceCount(t, f, "identity.user.unmatched"); n != "1" {
				t.Fatalf("unmatched evidence events = %s", n)
			}
		})
	}
}

func seedLink(t *testing.T, f adapterFixture, person string, id uuid.UUID) {
	t.Helper()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO person_entra_links (tenant_id,person_id,status,binding_version,entra_tenant_id,entra_user_object_id,receipt_id)
		VALUES ($1,$2,'matched',$3,$4,$5,gen_random_uuid())`, testTenant, person, binding().BindingVersion, binding().EntraTenantId, id)
}

// An Entra user belongs to at most one person: a token can never resolve to two people. The
// earlier link is provably stale (the user's employeeId is now this person's), so it goes too.
func TestAUserAlreadyLinkedToAnotherPersonIsAConflictForBoth(t *testing.T) {
	f, acts, reader := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
	seedLink(t, f, "HR-ELSEWHERE", userA)
	join := adapterLifecycleRef(t, f, "join")
	if err := acts.EntraLinkUser(context.Background(), join); err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"HR-PERSON", "HR-ELSEWHERE"} {
		link, err := f.svc.GetEntraUserLink(context.Background(), reader, person)
		if err != nil || link.Status != "conflict" || link.EntraUserObjectId != nil {
			t.Fatalf("%s: link = %+v, %v", person, link, err)
		}
	}
	if n := evidenceCount(t, f, "identity.user.conflict"); n != "2" {
		t.Fatalf("conflict evidence events = %s, want one per person", n)
	}
	// A retried activity finds this receipt's outcome and does not relink the user.
	if err := acts.EntraLinkUser(context.Background(), join); err != nil {
		t.Fatal(err)
	}
	if n := testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM person_entra_links WHERE status='matched'`); n != "0" {
		t.Fatalf("matched links after a retried conflict = %s", n)
	}
	// The database refuses a second person for the same user even if the check were skipped.
	err := f.conn.InTenant(context.Background(), testTenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(context.Background(), `UPDATE person_entra_links SET status='matched', entra_user_object_id=$1 WHERE person_id='HR-ELSEWHERE'`, userA); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(context.Background(), `UPDATE person_entra_links SET status='matched', entra_user_object_id=$1 WHERE person_id='HR-PERSON'`, userA)
		return err
	})
	if err == nil {
		t.Fatal("two people were linked to one Entra user")
	}
}

func TestARefusedLookupIsEvidencedAndNotRetried(t *testing.T) {
	f, acts, reader := linkFixture(t)
	f.graph.usersStatus = 403
	err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join"))
	var app *temporal.ApplicationError
	if !errors.As(err, &app) || !app.NonRetryable() {
		t.Fatalf("refused lookup = %v, want a non-retryable error", err)
	}
	if n := evidenceCount(t, f, "identity.user.lookup-failed"); n != "1" {
		t.Fatalf("lookup-failed evidence events = %s", n)
	}
	if link, err := f.svc.GetEntraUserLink(context.Background(), reader, "HR-PERSON"); err != nil || link.Status != "unavailable" || link.EntraUserObjectId != nil {
		t.Fatalf("refused lookup recorded %+v, %v", link, err)
	}
	// The workflow's failure step after a refusal changes nothing more.
	if err := acts.EntraUnlinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
		t.Fatal(err)
	}
	if n := evidenceCount(t, f, "identity.user.lookup-failed"); n != "1" {
		t.Fatalf("lookup-failed evidence events after the failure step = %s", n)
	}
}

// A rehire that cannot confirm the person's user never keeps the earlier link.
func TestARehireThatCannotConfirmTheUserClearsTheLink(t *testing.T) {
	for name, rehire := range map[string]func(*testing.T, adapterFixture, *lifecycle.EntraActivities, muistamov1.EntraLifecycleRef){
		"refused": func(t *testing.T, f adapterFixture, acts *lifecycle.EntraActivities, ref muistamov1.EntraLifecycleRef) {
			f.graph.usersStatus = 403
			if err := acts.EntraLinkUser(context.Background(), ref); err == nil {
				t.Fatal("a refused lookup succeeded")
			}
		},
		"failing": func(t *testing.T, f adapterFixture, acts *lifecycle.EntraActivities, ref muistamov1.EntraLifecycleRef) {
			if err := acts.EntraUnlinkUser(context.Background(), ref); err != nil {
				t.Fatal(err)
			}
		},
		"unmatched": func(t *testing.T, f adapterFixture, acts *lifecycle.EntraActivities, ref muistamov1.EntraLifecycleRef) {
			f.graph.users = nil
			if err := acts.EntraLinkUser(context.Background(), ref); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, acts, reader := linkFixture(t)
			f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
			if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
				t.Fatal(err)
			}
			seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
			seedAdapterHR(t, f.conn, f.key, f.actor, "rehire", "joiner", 3)
			ref := adapterLifecycleRef(t, f, "rehire")
			rehire(t, f, acts, ref)
			link, err := f.svc.GetEntraUserLink(context.Background(), reader, "HR-PERSON")
			if err != nil || link.Status == "matched" || link.EntraUserObjectId != nil || link.ReceiptId != ref.ReceiptId {
				t.Fatalf("rehired link = %+v, %v", link, err)
			}
		})
	}
}

// A concurrent joiner that links the same user after this joiner's check makes the unique index
// refuse; both people still end as a conflict, as when the link was already there.
func TestAConcurrentLinkToTheSameUserIsAConflictForBoth(t *testing.T) {
	f, acts, reader := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
	ctx := context.Background()
	other, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close(ctx) }()
	held, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Exec(ctx, `INSERT INTO person_entra_links (tenant_id,person_id,status,binding_version,entra_tenant_id,entra_user_object_id,receipt_id)
		VALUES ($1,'HR-ELSEWHERE','matched',$2,$3,$4,gen_random_uuid())`, testTenant, binding().BindingVersion, binding().EntraTenantId, userA); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- acts.EntraLinkUser(ctx, adapterLifecycleRef(t, f, "join")) }()
	// Commit only once the joiner's insert waits on the uncommitted row.
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO person_entra_links%'`) != "0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the joiner never waited on the concurrent link")
		}
	}
	if err := held.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"HR-PERSON", "HR-ELSEWHERE"} {
		link, err := f.svc.GetEntraUserLink(ctx, reader, person)
		if err != nil || link.Status != "conflict" || link.EntraUserObjectId != nil {
			t.Fatalf("%s: link = %+v, %v", person, link, err)
		}
	}
}

// Another tenant bound to the same directory may hold the user where this tenant cannot see it:
// the database refuses the second link, and the joiner records a conflict instead of failing.
func TestAUserHeldByAnotherTenantIsAConflict(t *testing.T) {
	f, acts, reader := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
	other, version := uuid.New(), uuid.New()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO tenants (id, name) VALUES ($1, 'other-tenant')`, other)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO entra_bindings (tenant_id,binding_version,config_digest,entra_tenant_id,blueprint_app_id)
		VALUES ($1,$2,repeat('a',64),$3,gen_random_uuid())`, other, version, binding().EntraTenantId)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO person_entra_links (tenant_id,person_id,status,binding_version,entra_tenant_id,entra_user_object_id,receipt_id)
		VALUES ($1,'THEIRS','matched',$2,$3,$4,gen_random_uuid())`, other, version, binding().EntraTenantId, userA)
	if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
		t.Fatal(err)
	}
	if link, err := f.svc.GetEntraUserLink(context.Background(), reader, "HR-PERSON"); err != nil || link.Status != "conflict" || link.EntraUserObjectId != nil {
		t.Fatalf("link = %+v, %v", link, err)
	}
}

// Evidence before return: a link whose evidence cannot be signed is not written.
func TestALinkWithoutEvidenceIsNotWritten(t *testing.T) {
	f, _, _ := linkFixture(t)
	join := adapterLifecycleRef(t, f, "join")
	broken := registry.New(f.conn, failingSigner{})
	id := userA
	if _, err := broken.RecordEntraUserLink(context.Background(), f.actor, join.ReceiptId, "matched", &id); err == nil {
		t.Fatal("a link was recorded without evidence")
	}
	if n := testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM person_entra_links`); n != "0" {
		t.Fatalf("links written without evidence = %s", n)
	}
}

type failingSigner struct{}

func (failingSigner) KeyID() string               { return "failing" }
func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("signer unavailable") }

// Only the person's current joiner links them; a rehire with a new user replaces the link.
func TestOnlyTheCurrentJoinerLinksAndARehireRelinks(t *testing.T) {
	f, acts, reader := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
	join := adapterLifecycleRef(t, f, "join")
	if err := acts.EntraLinkUser(context.Background(), join); err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	if err := acts.EntraLinkUser(context.Background(), join); err == nil {
		t.Fatal("a superseded joiner relinked the person")
	}
	if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "leave")); err == nil {
		t.Fatal("a leaver linked the person")
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "rehire", "joiner", 3)
	f.graph.users = []map[string]any{user(userB, "HR-PERSON")}
	rehire := adapterLifecycleRef(t, f, "rehire")
	if err := acts.EntraLinkUser(context.Background(), rehire); err != nil {
		t.Fatal(err)
	}
	link, err := f.svc.GetEntraUserLink(context.Background(), reader, "HR-PERSON")
	if err != nil || link.EntraUserObjectId == nil || *link.EntraUserObjectId != userB || link.ReceiptId != rehire.ReceiptId {
		t.Fatalf("rehired link = %+v, %v", link, err)
	}
}

func TestOnlyPrivacyOfficersReadLinks(t *testing.T) {
	f, acts, _ := linkFixture(t)
	f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
	if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetEntraUserLink(context.Background(), registry.Actor{Tenant: testTenant, Name: officer, RequestID: "read"}, "HR-PERSON"); err != nil {
		t.Fatal(err)
	}
	if n := evidenceCount(t, f, "privacy.entra-link.read"); n != "1" {
		t.Fatalf("officer read evidence events = %s", n)
	}
	someone := registry.Actor{Tenant: testTenant, Name: "dev:person@example.invalid", RequestID: "self"}
	if _, err := f.svc.GetEntraUserLink(context.Background(), someone, "HR-PERSON"); !errors.Is(err, registry.ErrForbidden) {
		t.Fatalf("a non-officer read a link: %v", err)
	}
	other := registry.Actor{Tenant: uuid.New(), Name: officer, RequestID: "other-tenant"}
	if _, err := f.svc.GetEntraUserLink(context.Background(), other, "HR-PERSON"); err == nil {
		t.Fatal("another tenant read a link")
	}
}

// Erasure finds the link by either key alone: the HR id, or the entra:<object id> identity.
func TestErasureDeletesTheLink(t *testing.T) {
	person := "HR-PERSON"
	for name, subject := range map[string]muistamov1.PrivacySubject{
		"by HR id":          {Email: "person@example.invalid", HrPersonId: &person},
		"by Entra identity": {Email: "nobody@example.invalid", Identities: []string{"entra:" + userA.String()}},
	} {
		t.Run(name, func(t *testing.T) {
			f, acts, reader := linkFixture(t)
			f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
			if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
				t.Fatal(err)
			}
			testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET state = 'retired', document = jsonb_set(document, '{spec,state}', '"retired"')`)
			proof, _, err := f.svc.Erase(context.Background(), reader, muistamov1.ErasureRequest{Id: uuid.New(), Reason: "ticket 1", Subject: subject})
			if err != nil {
				t.Fatal(err)
			}
			if proof.Counts["person_entra_links"] != 1 {
				t.Fatalf("erasure counts = %v", proof.Counts)
			}
			if n := testdb.Scalar(t, f.db.OwnerURL, `SELECT count(*)::text FROM person_entra_links`); n != "0" {
				t.Fatalf("links after erasure = %s", n)
			}
		})
	}
}

// An access export finds the link by either key alone, as erasure does.
func TestAccessExportIncludesTheLink(t *testing.T) {
	person := "HR-PERSON"
	for name, subject := range map[string]muistamov1.PrivacySubject{
		"by HR id":          {Email: "person@example.invalid", HrPersonId: &person},
		"by Entra identity": {Email: "nobody@example.invalid", Identities: []string{"entra:" + userA.String()}},
	} {
		t.Run(name, func(t *testing.T) {
			f, acts, reader := linkFixture(t)
			f.graph.users = []map[string]any{user(userA, "HR-PERSON")}
			if err := acts.EntraLinkUser(context.Background(), adapterLifecycleRef(t, f, "join")); err != nil {
				t.Fatal(err)
			}
			out, err := f.svc.ExportPersonalData(context.Background(), reader, subject)
			if err != nil {
				t.Fatal(err)
			}
			if rows := out.Sections["person_entra_links"]; len(rows) != 1 || rows[0]["entra_user_object_id"] != userA.String() {
				t.Fatalf("exported links = %v", rows)
			}
		})
	}
}

// The lookup uses only a client whose configuration is the registered binding version's.
func TestLookupRefusesAClientThatIsNotTheRegisteredBinding(t *testing.T) {
	f, _, _ := linkFixture(t)
	changed := binding()
	changed.SponsorUserIds = []string{uuid.NewString()}
	c, err := New(changed, func(context.Context, string, string) (string, error) { return fakeSecret, nil })
	if err != nil {
		t.Fatal(err)
	}
	g := &adapterGraph{users: []map[string]any{user(userA, "HR-PERSON")}}
	c.http = &http.Client{Transport: g.transport(t)}
	a, err := NewAdapter(f.svc, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.LookupUser(context.Background(), f.actor, uuid.MustParse(changed.BindingVersion), "HR-PERSON"); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("lookup with a changed binding = %v", err)
	}
	if _, err := a.LookupUser(context.Background(), f.actor, uuid.New(), "HR-PERSON"); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("lookup with an unknown binding version = %v", err)
	}
	if len(g.calls) != 0 {
		t.Fatalf("Graph was called: %v", g.calls)
	}
	other := registry.Actor{Tenant: uuid.New(), Name: "worker", RequestID: "other-tenant"}
	if _, err := f.adapter.LookupUser(context.Background(), other, uuid.MustParse(binding().BindingVersion), "HR-PERSON"); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("lookup for another tenant = %v", err)
	}
	if len(f.graph.calls) != 0 {
		t.Fatalf("Graph was called for another tenant: %v", f.graph.calls)
	}
}

// The registry enforces the receipt rules itself, not only through the activity's checks.
func TestTheRegistryLinksOnlyForTheCurrentJoiner(t *testing.T) {
	f, _, _ := linkFixture(t)
	join := adapterLifecycleRef(t, f, "join")
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	leave := adapterLifecycleRef(t, f, "leave")
	id := userA
	for name, receipt := range map[string]uuid.UUID{"superseded joiner": join.ReceiptId, "leaver": leave.ReceiptId} {
		if _, err := f.svc.RecordEntraUserLink(context.Background(), f.actor, receipt, "matched", &id); err == nil {
			t.Errorf("%s: linked", name)
		}
	}
	for name, outcome := range map[string]struct {
		status string
		id     *uuid.UUID
	}{"matched without a user": {"matched", nil}, "unmatched with a user": {"unmatched", &id}, "unknown status": {"maybe", nil}} {
		if _, err := f.svc.RecordEntraUserLink(context.Background(), f.actor, join.ReceiptId, outcome.status, outcome.id); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

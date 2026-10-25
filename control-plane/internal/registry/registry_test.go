package registry_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

type fixture struct {
	db    testdb.DB
	conn  *store.DB
	key   evidence.LocalKey
	svc   *registry.Service
	actor registry.Actor
}

func setup(t *testing.T) fixture {
	t.Helper()
	db := testdb.New(t)
	ctx := context.Background()
	tenant, err := store.CreateTenant(ctx, db.OwnerURL, "acme")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	return fixture{db: db, conn: conn, key: key, svc: registry.New(conn, key),
		actor: registry.Actor{Tenant: tenant, Name: "dev:person-a@example.invalid", RequestID: "req-1"}}
}

func template(purpose string) muistamov1.AgentTemplate {
	var doc muistamov1.AgentTemplate
	doc.ApiVersion = muistamov1.AgentTemplateApiVersionMuistamoDevv1
	doc.Kind = muistamov1.AgentTemplateKindAgentTemplate
	doc.Metadata.Name = "analyst-intern"
	doc.Spec.Purpose = purpose
	doc.Spec.ModelAlias = "reasoning-default"
	return doc
}

func instance(state muistamov1.InstanceState) muistamov1.AgentInstance {
	var doc muistamov1.AgentInstance
	doc.ApiVersion = muistamov1.AgentInstanceApiVersionMuistamoDevv1
	doc.Kind = muistamov1.AgentInstanceKindAgentInstance
	doc.Metadata.Name = "analyst-intern-person-a"
	doc.Spec.TemplateRef.Name = "analyst-intern"
	doc.Spec.TemplateRef.Version = "1"
	doc.Spec.Binding.Type = muistamov1.AgentInstanceSpecBindingTypeUser
	doc.Spec.Binding.Ref = "person-a@example.invalid"
	doc.Spec.State = state
	return doc
}

func (f fixture) events(t *testing.T) int {
	return testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events`)
}

func TestTemplateVersionsAreImmutable(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	v1, created, err := f.svc.ApplyTemplate(ctx, f.actor, template("first"))
	if err != nil || !created || v1.Version != 1 {
		t.Fatalf("first apply = v%d created=%v err=%v, want v1 created", v1.Version, created, err)
	}
	again, created, err := f.svc.ApplyTemplate(ctx, f.actor, template("first"))
	if err != nil || created || again.Version != 1 {
		t.Fatalf("identical apply = v%d created=%v err=%v, want v1 unchanged", again.Version, created, err)
	}
	v2, created, err := f.svc.ApplyTemplate(ctx, f.actor, template("second"))
	if err != nil || !created || v2.Version != 2 {
		t.Fatalf("changed apply = v%d created=%v err=%v, want v2 created", v2.Version, created, err)
	}

	old, err := f.svc.GetTemplateVersion(ctx, f.actor, "analyst-intern", 1)
	if err != nil || old.Document.Spec.Purpose != "first" {
		t.Fatalf("version 1 = %q, %v; want purpose first", old.Document.Spec.Purpose, err)
	}
	latest, err := f.svc.GetTemplate(ctx, f.actor, "analyst-intern")
	if err != nil || latest.Version != 2 {
		t.Fatalf("latest = v%d, %v; want v2", latest.Version, err)
	}
	if n := f.events(t); n != 2 {
		t.Fatalf("evidence events = %d, want 2 (the no-op writes none)", n)
	}
}

func TestAppRoleCannotAlterTemplateVersions(t *testing.T) {
	f := setup(t)
	if _, _, err := f.svc.ApplyTemplate(context.Background(), f.actor, template("first")); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE agent_template_versions SET document = '{}'`,
		`DELETE FROM agent_template_versions`,
		`DELETE FROM evidence_events`,
		`UPDATE evidence_events SET actor = 'someone-else'`,
	} {
		err := execAsApp(f, stmt)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s as app role: err = %v, want permission denied", stmt, err)
		}
	}
}

func TestInstanceLifecycle(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("first")); err != nil {
		t.Fatal(err)
	}

	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, instance(muistamov1.InstanceStateActive), ""); !errors.Is(err, registry.ErrInvalid) {
		t.Fatalf("create in active: err = %v, want ErrInvalid", err)
	}
	missing := instance(muistamov1.InstanceStateRequested)
	missing.Spec.TemplateRef.Version = "9"
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, missing, ""); !errors.Is(err, registry.ErrInvalid) {
		t.Fatalf("create against missing template version: err = %v, want ErrInvalid", err)
	}

	rec, created, err := f.svc.ApplyInstance(ctx, f.actor, instance(muistamov1.InstanceStateRequested), "")
	if err != nil || !created || rec.Revision != 1 {
		t.Fatalf("create = r%d created=%v err=%v", rec.Revision, created, err)
	}
	name := rec.Document.Metadata.Name

	if _, err := f.svc.Transition(ctx, f.actor, name, muistamov1.InstanceStateActive, ""); !errors.Is(err, registry.ErrPreconditionRequired) {
		t.Fatalf("transition without If-Match: err = %v, want ErrPreconditionRequired", err)
	}
	if _, err := f.svc.Transition(ctx, f.actor, name, muistamov1.InstanceStateActive, registry.ETag(7)); !errors.Is(err, registry.ErrPrecondition) {
		t.Fatalf("transition with stale If-Match: err = %v, want ErrPrecondition", err)
	}

	for _, to := range []muistamov1.InstanceState{
		muistamov1.InstanceStateActive, muistamov1.InstanceStateSuspended, muistamov1.InstanceStateRetired,
	} {
		rec, err = f.svc.Transition(ctx, f.actor, name, to, registry.ETag(rec.Revision))
		if err != nil || rec.Document.Spec.State != to {
			t.Fatalf("transition to %s: state=%s err=%v", to, rec.Document.Spec.State, err)
		}
	}
	if _, err := f.svc.Transition(ctx, f.actor, name, muistamov1.InstanceStateActive, registry.ETag(rec.Revision)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("retired to active: err = %v, want ErrConflict", err)
	}

	update := rec.Document
	sponsor := "person-b@example.invalid"
	update.Spec.Sponsor = &sponsor
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, update, ""); !errors.Is(err, registry.ErrPreconditionRequired) {
		t.Fatalf("update without If-Match: err = %v, want ErrPreconditionRequired", err)
	}
	updated, _, err := f.svc.ApplyInstance(ctx, f.actor, update, registry.ETag(rec.Revision))
	if err != nil || *updated.Document.Spec.Sponsor != sponsor {
		t.Fatalf("update sponsor: %v", err)
	}
	rebind := updated.Document
	rebind.Spec.Binding.Ref = "person-c@example.invalid"
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, rebind, registry.ETag(updated.Revision)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("change binding: err = %v, want ErrConflict", err)
	}

	// template v1, instance created, three transitions, one sponsor update.
	if n := f.events(t); n != 6 {
		t.Fatalf("evidence events = %d, want 6", n)
	}
}

func TestWriteIsRefusedWhenEvidenceCannotBeRecorded(t *testing.T) {
	f := setup(t)
	testdb.Exec(t, f.db.OwnerURL, `
		CREATE FUNCTION refuse_evidence() RETURNS trigger LANGUAGE plpgsql AS
		$$ BEGIN RAISE EXCEPTION 'evidence store unavailable (test)'; END $$`)
	testdb.Exec(t, f.db.OwnerURL, `
		CREATE TRIGGER refuse_evidence BEFORE INSERT ON evidence_events
		FOR EACH ROW EXECUTE FUNCTION refuse_evidence()`)

	_, _, err := f.svc.ApplyTemplate(context.Background(), f.actor, template("first"))
	if !errors.Is(err, registry.ErrEvidence) {
		t.Fatalf("err = %v, want ErrEvidence", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM agent_template_versions`); n != 0 {
		t.Fatalf("template versions = %d, want 0: the write must roll back", n)
	}
}

type failingSigner struct{ evidence.LocalKey }

func (failingSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("signer unavailable (test)")
}

func TestWriteIsRefusedWhenSigningFails(t *testing.T) {
	f := setup(t)
	if _, _, err := f.svc.ApplyTemplate(context.Background(), f.actor, template("first")); err != nil {
		t.Fatal(err)
	}
	broken := registry.New(f.conn, failingSigner{f.key})

	_, _, err := broken.ApplyTemplate(context.Background(), f.actor, template("second"))
	if !errors.Is(err, registry.ErrEvidence) {
		t.Fatalf("err = %v, want ErrEvidence", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM agent_template_versions`); n != 1 {
		t.Fatalf("template versions = %d, want 1: the second write must roll back", n)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT seq FROM evidence_heads`); n != 1 {
		t.Fatalf("chain head seq = %d, want 1: a failed append must not move it", n)
	}
}

func TestUnknownTenantIsRefused(t *testing.T) {
	f := setup(t)
	stranger := f.actor
	stranger.Tenant = uuid.New()
	if _, err := f.svc.ListTemplates(context.Background(), stranger, "", 10); !errors.Is(err, store.ErrUnknownTenant) {
		t.Fatalf("err = %v, want ErrUnknownTenant", err)
	}
}

func execAsApp(f fixture, stmt string) error {
	return testdb.ExecErr(f.db.AppURL, f.actor.Tenant, stmt)
}

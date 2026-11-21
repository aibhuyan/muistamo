package registry_test

// HUMAN REVIEW REQUIRED (AGENTS.md): only the HR joiner labels an agent with a person, and only
// for its own recorded joiner event (docs/hr-person-label-plan.md). The leaver, privacy exports,
// erasure and the console find a person's agents by this label.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// hrEvent records an HR event as the webhook would. decision is legacy, accepted or ignored.
func hrEvent(t *testing.T, f fixture, tenant uuid.UUID, eventID, kind, person, decision string) {
	t.Helper()
	generation, dispatch := 0, "legacy"
	switch decision {
	case "accepted":
		generation, dispatch = testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM hr_events WHERE decision = 'accepted'`)+1, "dispatched"
	case "ignored":
		dispatch = "ignored"
	}
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO hr_events (tenant_id,event_id,type,person_id,received_at,occurred_at,workflow_id,payload,decision,dispatch_state,generation)
		VALUES ($1,$2,$3,$4,now(),now(),'wf','{}',$5,$6,$7)`, tenant, eventID, kind, person, decision, dispatch, generation)
}

func labelled(doc muistamov1.AgentInstance, person string) muistamov1.AgentInstance {
	labels := map[string]string{registry.PersonLabel: person}
	doc.Metadata.Labels = &labels
	return doc
}

// A leaver recorded while the joiner is creating the agent is never missed: the joiner waits for
// the person's lock, as HR intake holds it, then sees the leaver and creates nothing.
func TestTheJoinerWaitsForALeaverBeingRecorded(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("research")); err != nil {
		t.Fatal(err)
	}
	hrEvent(t, f, f.actor.Tenant, "join-p7", "joiner", "P7", "accepted")
	intake, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = intake.Close(ctx) }()
	tx, err := intake.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, f.actor.Tenant.String()+"/P7"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO hr_events (tenant_id,event_id,type,person_id,received_at,occurred_at,workflow_id,payload,decision,dispatch_state,generation)
		VALUES ($1,'leave-p7','leaver','P7',now(),now(),'wf','{}','accepted','dispatched',2)`, f.actor.Tenant); err != nil {
		t.Fatal(err)
	}
	worker := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:wf", RequestID: "hr-event:join-p7"}
	done := make(chan error, 1)
	go func() {
		_, _, err := f.svc.CreateHRInstance(ctx, worker, instance("requested"), "P7", "join-p7")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the joiner did not wait for the person's lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, registry.ErrConflict) {
		t.Errorf("the joiner after the leaver = %v, want ErrConflict", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM agent_instances`); n != 0 {
		t.Errorf("%d agents were created after the leaver", n)
	}
}

func TestOnlyTheHRJoinerLabelsAnAgentWithAPerson(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("research")); err != nil {
		t.Fatal(err)
	}
	hrEvent(t, f, f.actor.Tenant, "join-accepted", "joiner", "P1", "accepted")
	hrEvent(t, f, f.actor.Tenant, "join-legacy", "joiner", "P2", "legacy")
	hrEvent(t, f, f.actor.Tenant, "join-ignored", "joiner", "P3", "ignored")
	hrEvent(t, f, f.actor.Tenant, "leave-p5", "leaver", "P5", "accepted")
	// P6's joiner was overtaken by P6's leaver: the leaver may already have run, so the joiner
	// must create nothing it would never suspend.
	hrEvent(t, f, f.actor.Tenant, "join-p6", "joiner", "P6", "accepted")
	hrEvent(t, f, f.actor.Tenant, "leave-p6", "leaver", "P6", "accepted")
	// Another tenant's joiner for P1 proves nothing in this tenant.
	other, err := store.CreateTenant(ctx, f.db.OwnerURL, "other")
	if err != nil {
		t.Fatal(err)
	}
	hrEvent(t, f, other, "join-elsewhere", "joiner", "P1", "accepted")
	worker := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:wf", RequestID: "hr-event:x"}

	// By hand, a label is refused whether or not the person has an HR joiner; nothing is created.
	for _, person := range []string{"P1", "NOBODY"} {
		if _, _, err := f.svc.ApplyInstance(ctx, f.actor, labelled(instance("requested"), person), ""); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("apply labelled %s by hand = %v, want ErrInvalid", person, err)
		}
	}
	// So is a label smuggled in through the worker's own name: the rule is the method, not the actor.
	if _, _, err := f.svc.ApplyInstance(ctx, worker, labelled(instance("requested"), "P1"), ""); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("apply labelled as the worker = %v, want ErrInvalid", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM agent_instances`); n != 0 {
		t.Fatalf("%d agents were created", n)
	}

	refused := map[string]struct{ person, event string }{
		"an unknown event":         {"P1", "no-such-event"},
		"another person's joiner":  {"P9", "join-accepted"},
		"a leaver":                 {"P5", "leave-p5"},
		"a superseded joiner":      {"P6", "join-p6"},
		"an ignored joiner":        {"P3", "join-ignored"},
		"another tenant's joiner":  {"P1", "join-elsewhere"},
		"a label for someone else": {"P1", "join-accepted"},
	}
	for name, c := range refused {
		doc := instance("requested")
		if name == "a label for someone else" {
			doc = labelled(doc, "P9")
		}
		if _, _, err := f.svc.CreateHRInstance(ctx, worker, doc, c.person, c.event); !errors.Is(err, registry.ErrConflict) {
			t.Errorf("%s = %v, want ErrConflict", name, err)
		}
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM agent_instances`); n != 0 {
		t.Fatalf("%d agents were created by refused joiners", n)
	}

	// An accepted joiner labels the agent itself, records its creation, and asked again returns it.
	rec, created, err := f.svc.CreateHRInstance(ctx, worker, instance("requested"), "P1", "join-accepted")
	if err != nil || !created || rec.Document.Metadata.Labels == nil || (*rec.Document.Metadata.Labels)[registry.PersonLabel] != "P1" {
		t.Fatalf("accepted joiner = %+v, %v, %v", rec.Document.Metadata, created, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action = 'instance.created' AND subject_name = $1`, rec.Document.Metadata.Name); n != 1 {
		t.Errorf("instance.created events = %d, want 1", n)
	}
	again, created, err := f.svc.CreateHRInstance(ctx, worker, instance("requested"), "P1", "join-accepted")
	if err != nil || created || again.Revision != rec.Revision {
		t.Errorf("asked again = %v, %v; want the same agent unchanged", created, err)
	}
	// The name now belongs to P1's agent: P2's joiner cannot take it over, and P1's own joiner
	// cannot replace it with a different document (another binding) under the same label.
	if _, _, err := f.svc.CreateHRInstance(ctx, worker, instance("requested"), "P2", "join-legacy"); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("another person's joiner on P1's agent = %v, want ErrConflict", err)
	}
	rebound := instance("requested")
	rebound.Spec.Binding.Ref = "someone-else@example.invalid"
	if _, _, err := f.svc.CreateHRInstance(ctx, worker, rebound, "P1", "join-accepted"); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("a different document on P1's agent = %v, want ErrConflict", err)
	}
	// Labels stay immutable: an update cannot remove or move the label.
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, instance("requested"), `"1"`); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("removing the label by update = %v, want ErrConflict", err)
	}
	// A legacy joiner (a workflow started before decisions were recorded) still creates its agent.
	doc := instance("requested")
	doc.Metadata.Name = "analyst-intern-p2"
	if _, created, err := f.svc.CreateHRInstance(ctx, worker, doc, "P2", "join-legacy"); err != nil || !created {
		t.Errorf("legacy joiner = %v, %v", created, err)
	}
	// A hand-made agent, which now cannot carry the label, is never one of P1's agents: the leaver,
	// the privacy export and erasure find P1's by the label (InstancesForPerson, rowsForHRPerson).
	hand := instance("requested")
	hand.Metadata.Name = "hand-made"
	hand.Spec.Binding.Ref = "someone-else@example.invalid"
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, hand, ""); err != nil {
		t.Fatal(err)
	}
	mine, err := f.svc.InstancesForPerson(ctx, worker, "P1")
	if err != nil || len(mine) != 1 || mine[0].Document.Metadata.Name != rec.Document.Metadata.Name {
		t.Errorf("P1's agents = %v, %v; want only the joiner's", len(mine), err)
	}
	// Nor can an update add the label to it later.
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, labelled(hand, "P1"), `"1"`); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("adding the label by update = %v, want ErrConflict", err)
	}
	// P1's privacy access export holds P1's agent and not the hand-made one, and once P1's agent is
	// retired, the hand-made agent does not block P1's erasure.
	officer := registry.Actor{Tenant: f.actor.Tenant, Name: "operator:dpo", RequestID: "privacy"}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.actor.Tenant, []string{officer.Name}); err != nil {
		t.Fatal(err)
	}
	p1 := "P1"
	subject := muistamov1.PrivacySubject{Email: "p1-not-bound@example.invalid", HrPersonId: &p1}
	export, err := f.svc.ExportPersonalData(ctx, officer, subject)
	if err != nil {
		t.Fatal(err)
	}
	var exported []string
	for _, row := range export.Sections["agent_instances"] {
		exported = append(exported, row["name"].(string))
	}
	if len(exported) != 1 || exported[0] != rec.Document.Metadata.Name {
		t.Errorf("P1's export lists agents %v, want only %s", exported, rec.Document.Metadata.Name)
	}
	for _, to := range []muistamov1.InstanceState{muistamov1.InstanceStateSuspended, muistamov1.InstanceStateRetired} {
		if _, err := f.svc.TransitionTo(ctx, worker, rec.Document.Metadata.Name, to); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.svc.Erase(ctx, officer, muistamov1.ErasureRequest{Id: uuid.New(), Subject: subject, Reason: "test"}); err != nil {
		t.Errorf("P1's erasure with only a hand-made agent active = %v", err)
	}
}

// Invariant 5: a joiner retried after the person was erased never recreates their agent; a rehire
// after the erasure is a new event and does.
func TestAnErasedPersonsJoinerCreatesNothing(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("research")); err != nil {
		t.Fatal(err)
	}
	// An accepted joiner whose handoff was never attempted does not hold the erasure back (a legacy
	// one does, privacy.go), yet its workflow can still run afterwards and reach EnsureInstance.
	hrEvent(t, f, f.actor.Tenant, "join-p8", "joiner", "P8", "accepted")
	officer := registry.Actor{Tenant: f.actor.Tenant, Name: "operator:dpo", RequestID: "privacy"}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.actor.Tenant, []string{officer.Name}); err != nil {
		t.Fatal(err)
	}
	p8 := "P8"
	if _, _, err := f.svc.Erase(ctx, officer, muistamov1.ErasureRequest{Id: uuid.New(), Subject: muistamov1.PrivacySubject{Email: "p8@example.invalid", HrPersonId: &p8}, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	worker := registry.Actor{Tenant: f.actor.Tenant, Name: "workflow:wf", RequestID: "hr-event:join-p8"}
	if _, _, err := f.svc.CreateHRInstance(ctx, worker, instance("requested"), "P8", "join-p8"); !errors.Is(err, registry.ErrConflict) {
		t.Errorf("the erased person's joiner, retried = %v, want ErrConflict", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM agent_instances`); n != 0 {
		t.Fatalf("%d agents were created for an erased person", n)
	}
	hrEvent(t, f, f.actor.Tenant, "rehire-p8", "joiner", "P8", "accepted")
	if _, created, err := f.svc.CreateHRInstance(ctx, worker, instance("requested"), "P8", "rehire-p8"); err != nil || !created {
		t.Errorf("a rehire after the erasure = %v, %v; want the agent created", created, err)
	}
}

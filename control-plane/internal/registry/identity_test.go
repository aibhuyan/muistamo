package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func identityBinding(tenant uuid.UUID) muistamov1.EntraIdentityBinding {
	return muistamov1.EntraIdentityBinding{TenantId: tenant.String(), BindingVersion: uuid.NewString(), EntraTenantId: uuid.NewString(), BlueprintAppId: uuid.NewString(), BlueprintObjectId: uuid.NewString(), BlueprintPrincipalId: uuid.NewString(), SponsorUserIds: []string{uuid.NewString()}, CredentialRef: "test-vault-reference", CredentialVersion: "test-v1"}
}

func identityHR(t *testing.T, f fixture, id, kind string, generation int64) {
	t.Helper()
	var event muistamov1.HREvent
	event.Id = id
	event.Type = muistamov1.HREventType(kind)
	event.OccurredAt = time.Date(2026, 10, 27, 9, 0, int(generation), 0, time.UTC)
	event.Person.Id = "HR-PERSON"
	event.Person.Email = "person-a@example.invalid"
	event.Person.JobCode = "INTERN"
	in := lifecycle.Intake{DB: f.conn, Signer: f.key}
	if _, err := in.Accept(context.Background(), f.actor.Tenant, "hris:test", id, event); !errors.Is(err, lifecycle.ErrDispatch) {
		t.Fatalf("seed accepted HR decision: %v", err)
	}
}

func liveIdentity(t *testing.T) (fixture, muistamov1.EntraIdentityBinding, muistamov1.AgentInstanceRecord) {
	t.Helper()
	f := setup(t)
	ctx := context.Background()
	b := identityBinding(f.actor.Tenant)
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.EnrollIdentityTenant(ctx, f.actor, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("identity test")); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "join", "joiner", 1)
	r, created, err := f.svc.CreateEntraInstance(ctx, f.actor, instance(muistamov1.InstanceStateRequested), "join", 1, uuid.MustParse(b.BindingVersion))
	if err != nil || !created {
		t.Fatalf("create trusted instance: %+v %v", r, err)
	}
	return f, b, r
}

func TestIdentityBindingVersionIsImmutableAndTenantScoped(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	b := identityBinding(f.actor.Tenant)
	r, created, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b)
	if err != nil || !created || r.ConfigDigest == "" {
		t.Fatalf("register: %+v %v", r, err)
	}
	if _, created, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); err != nil || created {
		t.Fatalf("duplicate binding changed: %v %v", created, err)
	}
	b.CredentialVersion = "test-v2"
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("binding version retargeted: %v", err)
	}
	b.TenantId = uuid.NewString()
	b.BindingVersion = uuid.NewString()
	if _, _, err := f.svc.RegisterIdentityBinding(ctx, f.actor, b); !errors.Is(err, registry.ErrInvalid) {
		t.Fatalf("foreign binding accepted: %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM entra_bindings WHERE to_jsonb(entra_bindings)::text LIKE '%test-vault-reference%'`); n != 0 {
		t.Fatal("binding persisted credential reference")
	}
}

func TestIdentityCreateExclusionSpansHRGenerations(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	op, created, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil || !created {
		t.Fatalf("reserve create: %+v %v", op, err)
	}
	again, created, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil || created || again.Id != op.Id || again.CreationId != op.CreationId {
		t.Fatalf("duplicate create changed original marker: %+v %v", again, err)
	}
	if err := f.svc.MarkIdentityIndeterminate(ctx, f.actor, op.Id, "uncertain"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "rehire", "joiner", 2)
	if _, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "rehire", 2, "create"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("new generation authorised a second blind create: %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM identity_operations WHERE action='create'`); n != 1 {
		t.Fatalf("create intents=%d", n)
	}
}

func TestIdentityActivationRequiresMatchingResultAndCurrentHR(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "active"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("unprovisioned live instance activated: %v", err)
	}
	if _, err := f.svc.SetIdentityRef(ctx, f.actor, name, "entra:"+uuid.NewString()); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("legacy setter forged live ownership: %v", err)
	}
	create, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	provider := uuid.New()
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, create.CreationId, provider, "enabled"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("enabled creation was accepted: %v", err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, uuid.New(), provider, "disabled"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("foreign create marker bound: %v", err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "active"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("disabled identity activated: %v", err)
	}
	enable, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "enable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, enable.Id, create.CreationId, provider, "enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "active"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "active"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("same-state activation bypassed newer leaver: %v", err)
	}
	if _, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "enable"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("old enable was replayed after leaver: %v", err)
	}
}

func TestIdentityPendingDeleteBlocksRehireAndPrematureRetirement(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	provider := uuid.New()
	create, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "retired"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("retirement preceded provider cleanup: %v", err)
	}
	del, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "leave", 2, "delete")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.MarkIdentityIndeterminate(ctx, f.actor, del.Id, "uncertain"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "rehire", "joiner", 3)
	if _, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "rehire", 3, "enable"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("rehire enabled during uncertain deletion: %v", err)
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "active"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("rehire activated during uncertain deletion: %v", err)
	}
}

func TestIdentityIntentRollsBackWhenEvidenceFails(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	broken := registry.New(f.conn, identityBrokenSigner{f.key})
	if _, _, err := broken.ReserveIdentityOperation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create"); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned identity intent committed: %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM identity_operations`); n != 0 {
		t.Fatalf("unsigned journal rows=%d", n)
	}
}

func TestIdentityStateCannotBeRetargetedByApplicationRole(t *testing.T) {
	f, _, r := liveIdentity(t)
	for _, statement := range []string{
		`UPDATE instance_identities SET provider_mode='simulated',binding_version=NULL,entra_tenant_id=NULL,assignment_receipt_id=NULL,observed_state='simulated'`,
		`UPDATE instance_identities SET binding_version='11111111-1111-4111-8111-111111111111'`,
		`UPDATE instance_identities SET assignment_receipt_id=NULL`,
	} {
		if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, statement); err == nil {
			t.Fatalf("trusted identity metadata was editable: %s", statement)
		}
	}
	state, err := f.svc.IdentityStatus(context.Background(), f.actor, r.Document.Metadata.Name)
	if err != nil || state.ProviderMode != "entra" {
		t.Fatalf("mode changed: %+v %v", state, err)
	}
}

func TestIdentityRetirementRequiresSignedDeleteProof(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	provider := uuid.New()
	create, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "suspended"); err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `UPDATE instance_identities SET observed_state='deleted' WHERE tenant_id=$1`, f.actor.Tenant)
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "retired"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("unproved deletion allowed retirement: %v", err)
	}
}

func TestIdentityLegacyActivitiesNeverTouchLiveInstance(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	sim := &lifecycle.Simulated{}
	a := lifecycle.Activities{Registry: f.svc, Provisioner: sim, Revoker: sim}
	scope := lifecycle.Scope{Tenant: f.actor.Tenant, WorkflowID: "legacy", EventID: "join"}
	name := r.Document.Metadata.Name
	for _, call := range []func() error{
		func() error {
			return a.ProvisionIdentity(ctx, scope, name, lifecycle.Person{Email: "person-a@example.invalid"})
		},
		func() error { return a.SetIdentityEnabled(ctx, scope, name, true) },
		func() error { return a.RevokeCredentials(ctx, scope, name) },
		func() error { return a.SetState(ctx, scope, name, "suspended") },
	} {
		if err := call(); !errors.Is(err, registry.ErrConflict) {
			t.Fatalf("legacy activity accepted live ownership: %v", err)
		}
	}
	if len(sim.Recorded()) != 0 {
		t.Fatalf("legacy provider ran for live instance: %v", sim.Recorded())
	}
}

func TestIdentityPrivacyInventoryFollowsOpaqueReceipts(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	if _, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, r.Document.Metadata.Name, "join", 1, "create"); err != nil {
		t.Fatal(err)
	}
	officer := registry.Actor{Tenant: f.actor.Tenant, Name: "operator:dpo", RequestID: "export"}
	if err := store.SetPrivacyOfficers(ctx, f.db.OwnerURL, f.actor.Tenant, []string{officer.Name}); err != nil {
		t.Fatal(err)
	}
	hr := "HR-PERSON"
	subject := muistamov1.PrivacySubject{Email: "person-a@example.invalid", Identities: []string{f.actor.Name}, HrPersonId: &hr}
	data, err := f.svc.ExportPersonalData(ctx, officer, subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"entra_bindings", "instance_identities", "identity_operations"} {
		if len(data.Sections[table]) != 1 {
			t.Fatalf("opaque identity metadata absent from privacy inventory: %s %+v", table, data.Sections[table])
		}
	}
	other := f.actor
	other.Tenant, err = store.CreateTenant(ctx, f.db.OwnerURL, "other")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IdentityStatus(ctx, other, r.Document.Metadata.Name); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("foreign ownership exposed: %v", err)
	}
}

func TestIdentityResultFailureRetainsPendingIntent(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	op, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	broken := registry.New(f.conn, identityBrokenSigner{f.key})
	if err := broken.CommitIdentityResult(ctx, f.actor, op.Id, op.CreationId, uuid.New(), "disabled"); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned result accepted: %v", err)
	}
	status, err := f.svc.IdentityStatus(ctx, f.actor, name)
	if err != nil {
		t.Fatal(err)
	}
	if status.ProviderId != nil || status.ObservedState != "unprovisioned" {
		t.Fatalf("uncommitted provider result escaped: %+v", status)
	}
	stored, err := f.svc.IdentityOperation(ctx, f.actor, op.Id)
	if err != nil || stored.State != "pending" || stored.ResultEvidenceSeq != nil {
		t.Fatalf("uncertain result was not left pending: %+v %v", stored, err)
	}
}

func TestIdentityUnsignedHRDecisionCannotCreateLiveInstance(t *testing.T) {
	f, b, r := liveIdentity(t)
	ctx := context.Background()
	var e muistamov1.HREvent
	e.Id = "unsigned"
	e.Type = "joiner"
	e.OccurredAt = time.Now()
	e.Person.Id = "HR-PERSON"
	e.Person.Email = "person-a@example.invalid"
	e.Person.JobCode = "INTERN"
	payload, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO hr_events(tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version) VALUES($1,'unsigned','joiner','HR-PERSON','',$2,now(),2,'accepted','pending','entra',$3)`, f.actor.Tenant, payload, uuid.MustParse(b.BindingVersion))
	doc := instance("requested")
	doc.Metadata.Name = r.Document.Metadata.Name + "-unsigned"
	if _, _, err := f.svc.CreateEntraInstance(ctx, f.actor, doc, "unsigned", 2, uuid.MustParse(b.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("unsigned HR row authorised live materialisation: %v", err)
	}
}

func TestIdentityProviderOwnershipCannotBeShared(t *testing.T) {
	f, b, r := liveIdentity(t)
	ctx := context.Background()
	provider := uuid.New()
	name := r.Document.Metadata.Name
	first, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, first.Id, first.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	doc := instance("requested")
	doc.Metadata.Name = name + "-two"
	if _, _, err := f.svc.CreateEntraInstance(ctx, f.actor, doc, "join", 1, uuid.MustParse(b.BindingVersion)); err != nil {
		t.Fatal(err)
	}
	second, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, doc.Metadata.Name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, second.Id, second.CreationId, provider, "disabled"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("provider identity bound to two instances: %v", err)
	}
}

func TestIdentityCorrectiveDisableAfterLateEnable(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	provider := uuid.New()
	create, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	enable, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "enable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.MarkIdentityIndeterminate(ctx, f.actor, enable.Id, "uncertain"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "suspended"); err != nil {
		t.Fatal(err)
	}
	disable, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "leave", 2, "disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, disable.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	// The ORIGINAL enable later returns a verified terminal result. Its physical request
	// may have outlasted the first disable, so the current leaver needs a new signed attempt.
	if err := f.svc.CommitIdentityResult(ctx, f.actor, enable.Id, create.CreationId, provider, "enabled"); err != nil {
		t.Fatal(err)
	}
	corrective, permitted, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "leave", 2, "disable")
	if err != nil || !permitted || corrective.Id == disable.Id {
		t.Fatalf("late enable cannot get a fresh corrective disable: %+v %v permitted=%v", corrective, err, permitted)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, corrective.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	owned, err := f.svc.IdentityStatus(ctx, f.actor, name)
	if err != nil || owned.ObservedState != "disabled" {
		t.Fatalf("corrective disable failed: %+v %v", owned, err)
	}
}

func TestIdentityFactoryReuseRequiresSameClone(t *testing.T) {
	f, b, r := liveIdentity(t)
	doc := r.Document
	doc.Spec.IdentityRef = nil
	other := "missing-clone"
	doc.Spec.CloneRef = &other
	if _, _, err := f.svc.CreateEntraInstance(context.Background(), f.actor, doc, "join", 1, uuid.MustParse(b.BindingVersion)); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("factory reuse bypassed clone association: %v", err)
	}
}

func TestIdentityDatabaseCreateExclusionSpansAttempts(t *testing.T) {
	f, _, r := liveIdentity(t)
	op, _, err := f.svc.ReserveIdentityOperation(context.Background(), f.actor, r.Document.Metadata.Name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	err = testdb.ExecErr(f.db.AppURL, f.actor.Tenant, `INSERT INTO identity_operations(tenant_id,id,instance_identity_id,binding_version,hr_receipt_id,hr_generation,action,attempt,creation_id) SELECT tenant_id,gen_random_uuid(),instance_identity_id,binding_version,hr_receipt_id,hr_generation,action,2,creation_id FROM identity_operations WHERE id=$1`, op.Id)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23505" || pg.ConstraintName != "identity_single_create" {
		t.Fatalf("database admitted another create or failed for unrelated reason: %v", err)
	}
}

func TestIdentityJournalEvidenceChainVerifies(t *testing.T) {
	f, _, r := liveIdentity(t)
	ctx := context.Background()
	name := r.Document.Metadata.Name
	provider := uuid.New()
	create, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "create")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, create.Id, create.CreationId, provider, "disabled"); err != nil {
		t.Fatal(err)
	}
	enable, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "join", 1, "enable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CommitIdentityResult(ctx, f.actor, enable.Id, create.CreationId, provider, "enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "active"); err != nil {
		t.Fatal(err)
	}
	identityHR(t, f, "leave", "leaver", 2)
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "suspended"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		action muistamov1.IdentityOperationStatusAction
		state  muistamov1.InstanceIdentityStatusObservedState
	}{{"disable", "disabled"}, {"delete", "deleted"}} {
		op, _, err := f.svc.ReserveIdentityOperation(ctx, f.actor, name, "leave", 2, step.action)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.svc.CommitIdentityResult(ctx, f.actor, op.Id, create.CreationId, provider, step.state); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.svc.TransitionTo(ctx, f.actor, name, "retired"); err != nil {
		t.Fatal(err)
	}
	events := f.chain(t, f.actor)
	if err := evidencechain.Verify(events, f.keys()); err != nil {
		t.Fatalf("journal evidence chain failed: %v", err)
	}
	intents, results := 0, 0
	for _, event := range events {
		if event.Action == "identity.operation.intent" {
			intents++
		}
		if event.Action == "identity.operation.succeeded" {
			results++
		}
	}
	if intents != 4 || results != 4 {
		t.Fatalf("journal evidence incomplete: intents=%d results=%d", intents, results)
	}
	t.Logf("verified %d signed journal lifecycle events; provider observations were artificial", len(events))
}

type identityBrokenSigner struct{ evidence.LocalKey }

func (identityBrokenSigner) Sign([]byte) ([]byte, error) {
	return nil, errors.New("fake signer failure")
}

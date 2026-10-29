package lifecycle_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

type fixture struct {
	db        testdb.DB
	key       evidence.LocalKey
	svc       *registry.Service
	simulated *lifecycle.Simulated
	acts      *lifecycle.Activities
	scope     lifecycle.Scope
}

func setup(t *testing.T) fixture {
	t.Helper()
	db := testdb.New(t)
	ctx := context.Background()
	tenant, err := store.CreateTenant(ctx, db.OwnerURL, "acme")
	if err != nil {
		t.Fatal(err)
	}
	testdb.ApprovedModelAlias(t, db.OwnerURL, tenant, "reasoning-default")
	conn, err := store.Open(ctx, db.AppURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	key := testdb.SigningKey(t, db)
	svc := registry.New(conn, key)
	sim := &lifecycle.Simulated{}
	return fixture{
		db: db, key: key, svc: svc, simulated: sim,
		acts:  &lifecycle.Activities{Registry: svc, Provisioner: sim, Revoker: sim},
		scope: lifecycle.Scope{Tenant: tenant, WorkflowID: "wf-test", EventID: "ev-1"},
	}
}

func (f fixture) template(t *testing.T, name string, jobCodes ...string) {
	t.Helper()
	var doc muistamov1.AgentTemplate
	doc.ApiVersion = muistamov1.AgentTemplateApiVersionMuistamoDevv1
	doc.Kind = muistamov1.AgentTemplateKindAgentTemplate
	doc.Metadata.Name = name
	doc.Spec.Purpose = "test"
	doc.Spec.ModelAlias = "reasoning-default"
	if len(jobCodes) > 0 {
		doc.Spec.Assignment = &struct {
			HrJobCodes *[]string `json:"hrJobCodes,omitempty"`
		}{HrJobCodes: &jobCodes}
	}
	low := muistamov1.AgentTemplateSpecRiskTierLow
	doc.Spec.RiskTier = &low
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:admin@example.invalid", RequestID: "seed"}
	rec, _, err := f.svc.ApplyTemplate(context.Background(), actor, doc)
	if err != nil {
		t.Fatal(err)
	}
	// Low risk publishes to the catalogue on request; only published versions are assignable.
	if req, err := f.svc.RequestPublication(context.Background(), actor, name, rec.Version); err != nil || req.State != "published" {
		t.Fatalf("publish %s: state %v, %v", name, req.State, err)
	}
}

// templateUnpublished applies a template without publishing it to the catalogue.
func (f fixture) templateUnpublished(t *testing.T, name string, jobCodes ...string) {
	t.Helper()
	var doc muistamov1.AgentTemplate
	doc.ApiVersion = muistamov1.AgentTemplateApiVersionMuistamoDevv1
	doc.Kind = muistamov1.AgentTemplateKindAgentTemplate
	doc.Metadata.Name = name
	doc.Spec.Purpose = "test"
	doc.Spec.ModelAlias = "reasoning-default"
	doc.Spec.Assignment = &struct {
		HrJobCodes *[]string `json:"hrJobCodes,omitempty"`
	}{HrJobCodes: &jobCodes}
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:admin@example.invalid", RequestID: "seed"}
	if _, _, err := f.svc.ApplyTemplate(context.Background(), actor, doc); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyCataloguePublishedTemplatesMatchJoiners(t *testing.T) {
	f := setup(t)
	f.template(t, "published", "ANALYST_INTERN")
	f.templateUnpublished(t, "applied-only", "ANALYST_INTERN")
	matched, err := f.acts.MatchTemplates(context.Background(), f.scope, "ANALYST_INTERN")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 || matched[0].Name != "published" {
		t.Fatalf("matched = %+v, want only the published template", matched)
	}
}

var person = lifecycle.Person{ID: "E-1001", Email: "person-a@example.invalid", JobCode: "ANALYST_INTERN"}

func TestJoinerAndLeaverActivitiesAgainstTheRegistry(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.template(t, "analyst-intern", "ANALYST_INTERN", "SUMMER_INTERN")
	f.template(t, "research-assistant", "ANALYST_INTERN")
	f.template(t, "sales-coach", "SALES")
	f.template(t, "unassigned")

	matched, err := f.acts.MatchTemplates(ctx, f.scope, "ANALYST_INTERN")
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 2 || matched[0].Name != "analyst-intern" || matched[1].Name != "research-assistant" {
		t.Fatalf("matched = %+v, want analyst-intern and research-assistant", matched)
	}

	name, err := f.acts.EnsureInstance(ctx, f.scope, matched[0], person)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.acts.EnsureInstance(ctx, f.scope, matched[0], person)
	if err != nil || again != name {
		t.Fatalf("second EnsureInstance = %q, %v; want the same instance %q", again, err, name)
	}
	for range 2 { // provisioning twice must be harmless
		if err := f.acts.ProvisionIdentity(ctx, f.scope, name, person); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.acts.SetState(ctx, f.scope, name, muistamov1.InstanceStateActive); err != nil {
		t.Fatal(err)
	}

	instances, err := f.acts.PersonInstances(ctx, f.scope, person.ID)
	if err != nil || !slices.Equal(instances, []string{name}) {
		t.Fatalf("person instances = %v, %v", instances, err)
	}
	if err := f.acts.SetState(ctx, f.scope, name, muistamov1.InstanceStateSuspended); err != nil {
		t.Fatal(err)
	}
	if err := f.acts.RevokeCredentials(ctx, f.scope, name); err != nil {
		t.Fatal(err)
	}
	if err := f.acts.RecordPersonalLayerDecision(ctx, f.scope, name); err != nil {
		t.Fatal(err)
	}
	if err := f.acts.SetState(ctx, f.scope, name, muistamov1.InstanceStateRetired); err != nil {
		t.Fatal(err)
	}
	if err := f.acts.SetIdentityEnabled(ctx, f.scope, name, false); err != nil {
		t.Fatal(err)
	}

	rec, err := f.svc.GetInstance(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "x", RequestID: "x"}, name)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Document.Spec.State != muistamov1.InstanceStateRetired || rec.Document.Spec.IdentityRef == nil {
		t.Fatalf("instance = %+v, want retired with an identity", rec.Document.Spec)
	}
	if calls := f.simulated.Recorded(); len(calls) != 4 { // provision x2 (idempotent), revoke, disable
		t.Fatalf("simulated calls = %v", calls)
	}

	// A rehire after retirement gets a fresh instance; the retired one is never reused.
	fresh, err := f.acts.EnsureInstance(ctx, f.scope, matched[0], person)
	if err != nil || fresh == name {
		t.Fatalf("instance after retirement = %q, %v; want a new name", fresh, err)
	}

	events, err := f.svc.ListEvents(ctx, registry.Actor{Tenant: f.scope.Tenant, Name: "x", RequestID: "x"}, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range events {
		if e.Actor == "workflow:wf-test" {
			actions = append(actions, e.Action)
		}
		if e.Action == "credentials.revoked" {
			var after map[string]any
			if err := json.Unmarshal(e.After, &after); err != nil || after["simulated"] != true {
				t.Fatalf("simulated revocation evidence does not say it was simulated: %s", e.After)
			}
		}
	}
	want := []string{
		"instance.created", "identity.provisioned", "instance.transitioned", "instance.transitioned",
		"credentials.revoked", "personal-layer.decision", "instance.transitioned", "identity.disabled",
		"instance.created",
	}
	if !slices.Equal(actions, want) {
		t.Fatalf("workflow evidence:\n %v\nwant\n %v", actions, want)
	}
	if err := evidencechain.Verify(events, map[string]ed25519.PublicKey{f.key.KeyID(): f.key.Public()}); err != nil {
		t.Fatalf("chain: %v", err)
	}
}

func TestLeaverBeforeActivationSuspends(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.template(t, "analyst-intern", "ANALYST_INTERN")
	name, err := f.acts.EnsureInstance(ctx, f.scope, registry.TemplateVersionRef{Name: "analyst-intern", Version: 1}, person)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.acts.SetState(ctx, f.scope, name, muistamov1.InstanceStateSuspended); err != nil {
		t.Fatalf("requested -> suspended: %v", err)
	}
}

// A leaver's credentials step really revokes the instance's gateway keys, and its evidence says
// so and how many (docs/agentgateway-plan.md, step 4). HUMAN REVIEW REQUIRED.
func TestLeaverRevokesTheInstancesVirtualKeys(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.acts.Revoker = lifecycle.KeyRevoker{Registry: f.svc}
	f.template(t, "analyst-intern", "ANALYST_INTERN")
	name, err := f.acts.EnsureInstance(ctx, f.scope, registry.TemplateVersionRef{Name: "analyst-intern", Version: 1}, person)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.acts.ProvisionIdentity(ctx, f.scope, name, person); err != nil {
		t.Fatal(err)
	}
	if err := f.acts.SetState(ctx, f.scope, name, muistamov1.InstanceStateActive); err != nil {
		t.Fatal(err)
	}
	admin := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:gw-admin@example.invalid", RequestID: "test"}
	if err := registry.ConfigureGatewayAdmins(ctx, f.db.OwnerURL, admin, []string{admin.Name}, f.key); err != nil {
		t.Fatal(err)
	}
	issued, err := f.svc.IssueKey(ctx, admin, muistamov1.VirtualKeyRequest{Instance: name, Aliases: []string{"reasoning-default"},
		MonthlyBudget: muistamov1.Money{Amount: "5", Currency: "EUR"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.acts.SetState(ctx, f.scope, name, muistamov1.InstanceStateSuspended); err != nil {
		t.Fatal(err)
	}
	for range 2 { // a retried activity is harmless
		if err := f.acts.RevokeCredentials(ctx, f.scope, name); err != nil {
			t.Fatal(err)
		}
	}
	key, err := f.svc.GetKey(ctx, admin, issued.Key.Id)
	if err != nil || key.Status != muistamov1.VirtualKeyStatusRevoked || *key.RevokeReason != "leaver" {
		t.Fatalf("key after leaver = %+v, %v", key, err)
	}
	events, err := f.svc.ListEvents(ctx, admin, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var counts []any
	for _, e := range events {
		if e.Action != "credentials.revoked" {
			continue
		}
		var after map[string]any
		if err := json.Unmarshal(e.After, &after); err != nil {
			t.Fatal(err)
		}
		if after["simulated"] != false || after["revoker"] != "gateway-virtual-keys" {
			t.Fatalf("credentials.revoked evidence = %v, want real gateway revocation", after)
		}
		if !strings.Contains(fmt.Sprint(after["scope"]), "in-flight responses not terminated") {
			t.Fatalf("real revocation evidence overstates its scope: %v", after)
		}
		counts = append(counts, after["keysRevoked"])
	}
	// A retry reports the same key the first attempt revoked, never zero.
	if !slices.Equal(counts, []any{float64(1), float64(1)}) {
		t.Fatalf("revoked counts per attempt = %v, want [1 1]", counts)
	}
}

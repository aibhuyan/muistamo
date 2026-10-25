package lifecycle_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func (f fixture) clone(t *testing.T, name, sync string, jobCodes ...string) {
	t.Helper()
	codes, _ := json.Marshal(jobCodes)
	var doc muistamov1.AgentClone
	if err := json.Unmarshal([]byte(`{"apiVersion":"muistamo.dev/v1","kind":"AgentClone","metadata":{"name":"`+name+`"},
		"spec":{"template":"analyst","sync":"`+sync+`","overlay":{"assignment":{"hrJobCodes":`+string(codes)+`}}}}`), &doc); err != nil {
		t.Fatal(err)
	}
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:admin@example.invalid", RequestID: "seed"}
	if _, _, err := f.svc.ApplyClone(context.Background(), actor, doc); err != nil {
		t.Fatalf("clone %s: %v", name, err)
	}
}

func (f fixture) match(t *testing.T, jobCode string) []registry.TemplateVersionRef {
	t.Helper()
	refs, err := f.acts.MatchTemplates(context.Background(), f.scope, jobCode)
	if err != nil {
		t.Fatal(err)
	}
	return refs
}

func TestJoinersGetTheMatchingClone(t *testing.T) {
	f := setup(t)
	f.template(t, "analyst", "ANALYST")
	f.clone(t, "analyst-fi", "follow", "ANALYST_FI")
	f.clone(t, "analyst-se", "follow", "ANALYST_SE")

	if refs := f.match(t, "ANALYST_FI"); len(refs) != 1 || refs[0].Clone != "analyst-fi" || refs[0].Name != "analyst" || refs[0].Version != 1 {
		t.Errorf("ANALYST_FI = %+v, want the Finnish clone", refs)
	}
	if refs := f.match(t, "ANALYST"); len(refs) != 1 || refs[0].Clone != "" {
		t.Errorf("ANALYST = %+v, want the plain template", refs)
	}
	if refs := f.match(t, "NOBODY"); len(refs) != 0 {
		t.Errorf("NOBODY = %+v", refs)
	}

	// The instance is named after the clone and belongs to it.
	name, err := f.acts.EnsureInstance(context.Background(), f.scope, f.match(t, "ANALYST_FI")[0],
		lifecycle.Person{ID: "P-1", Email: "p1@example.invalid", JobCode: "ANALYST_FI"})
	if err != nil {
		t.Fatal(err)
	}
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:admin@example.invalid", RequestID: "check"}
	rec, err := f.svc.GetInstance(context.Background(), actor, name)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(name, "analyst-fi-") || rec.Document.Spec.CloneRef == nil || *rec.Document.Spec.CloneRef != "analyst-fi" {
		t.Errorf("instance %s cloneRef %v, want one of analyst-fi", name, rec.Document.Spec.CloneRef)
	}
}

func TestAmbiguousClonesAssignNothing(t *testing.T) {
	f := setup(t)
	f.template(t, "analyst", "ANALYST")
	f.clone(t, "analyst-fi", "follow", "ANALYST_FI")
	f.clone(t, "analyst-fi-b", "follow", "ANALYST_FI")

	if refs := f.match(t, "ANALYST_FI"); len(refs) != 0 {
		t.Errorf("two clones listing the job code: %+v, want none", refs)
	}
	raw := testdb.Scalar(t, f.db.OwnerURL, `SELECT after::text FROM evidence_events WHERE action = 'assignment.ambiguous'`)
	if !strings.Contains(raw, "analyst-fi") || !strings.Contains(raw, "analyst-fi-b") {
		t.Errorf("ambiguity evidence = %s", raw)
	}
	// The plain template's own job code is unaffected.
	if refs := f.match(t, "ANALYST"); len(refs) != 1 {
		t.Errorf("ANALYST = %+v", refs)
	}
}

func TestUnassignableClonesNeverMatch(t *testing.T) {
	f := setup(t)
	f.template(t, "analyst", "ANALYST")
	f.clone(t, "analyst-manual", "manual", "ANALYST_M")
	// A new published version leaves the manual clone behind, so joiners cannot get it.
	f.template(t, "analyst", "ANALYST", "ANALYST_V2")
	if refs := f.match(t, "ANALYST_M"); len(refs) != 0 {
		t.Errorf("a manual clone behind upstream matched: %+v", refs)
	}
	actor := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:admin@example.invalid", RequestID: "sync"}
	if _, err := f.svc.SyncClone(context.Background(), actor, "analyst-manual"); err != nil {
		t.Fatal(err)
	}
	if refs := f.match(t, "ANALYST_M"); len(refs) != 1 || refs[0].Version != 2 || refs[0].Clone != "analyst-manual" {
		t.Errorf("after sync: %+v", refs)
	}
}

func TestJoinersStopGettingTemplatesOnARevokedModel(t *testing.T) {
	f := setup(t)
	f.template(t, "analyst", "ANALYST")
	f.clone(t, "analyst-fi", "follow", "ANALYST_FI")
	if len(f.match(t, "ANALYST")) != 1 || len(f.match(t, "ANALYST_FI")) != 1 {
		t.Fatal("setup: the template and clone should match before revocation")
	}
	if err := store.SetPrivacyOfficers(context.Background(), f.db.OwnerURL, f.scope.Tenant, []string{"dev:dpo@example.invalid"}); err != nil {
		t.Fatal(err)
	}
	dpo := registry.Actor{Tenant: f.scope.Tenant, Name: "dev:dpo@example.invalid", RequestID: "revoke"}
	if _, err := f.svc.DecideModel(context.Background(), dpo, "reasoning-default-model",
		muistamov1.ModelApprovalDecisionDecisionRevoke, "provider terms changed"); err != nil {
		t.Fatal(err)
	}
	// Still published, but no new agents run on a revoked model: not the template, not its clone.
	if refs := f.match(t, "ANALYST"); len(refs) != 0 {
		t.Errorf("template after revocation: %+v", refs)
	}
	if refs := f.match(t, "ANALYST_FI"); len(refs) != 0 {
		t.Errorf("clone after revocation: %+v", refs)
	}
}

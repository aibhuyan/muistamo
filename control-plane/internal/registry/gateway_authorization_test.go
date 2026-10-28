package registry_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func modelCall() (muistamov1.GatewayAuthorizationRequest, muistamov1.GatewayModelRoute) {
	alias := "reasoning-default"
	return muistamov1.GatewayAuthorizationRequest{Kind: "model", Method: "POST", Path: "/v1/chat/completions", MetadataValid: true, Alias: &alias},
		muistamov1.GatewayModelRoute{Alias: alias, AliasRevision: 1, CatalogueName: alias + "-model", ModelRevision: 1, Provider: "test", Model: "test-model", Region: "eu-test", BaseUrl: "http://fake.invalid/v1"}
}

func TestGatewayAuthorizationUsesCanonicalDevelopmentPrincipal(t *testing.T) {
	f, req := gatewayFixture(t)
	key, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, key.Secret, call, &route)
	if err != nil || !d.Allowed {
		t.Fatalf("authorization = %+v %v", d, err)
	}
	export, err := f.svc.ExportPersonalData(t.Context(), f.actor, muistamov1.PrivacySubject{Identities: []string{f.actor.Name}, Email: "person-a@example.invalid"})
	if err != nil || len(export.Sections["gateway_calls"]) != 1 {
		t.Fatalf("self access lost the acting principal's calls: %+v %v", export.Sections["gateway_calls"], err)
	}
	if got := testdb.Scalar(t, f.db.OwnerURL, `SELECT person FROM gateway_calls WHERE request_id=$1`, d.RequestId); got != f.actor.Name {
		t.Fatalf("call principal = %q, want %q", got, f.actor.Name)
	}
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "retired"); err != nil {
		t.Fatal(err)
	}
	officer := registry.Actor{Tenant: f.actor.Tenant, Name: "dev:officer@example.invalid", RequestID: uuid.NewString()}
	if err := store.SetPrivacyOfficers(t.Context(), f.db.OwnerURL, f.actor.Tenant, []string{officer.Name}); err != nil {
		t.Fatal(err)
	}
	_, _, err = f.svc.Erase(t.Context(), officer, muistamov1.ErasureRequest{Id: uuid.New(), Subject: muistamov1.PrivacySubject{Identities: []string{f.actor.Name}, Email: "person-a@example.invalid"}, Reason: "test cleanup"})
	if err != nil {
		t.Fatal(err)
	}
	if got := testdb.Scalar(t, f.db.OwnerURL, `SELECT person FROM gateway_calls WHERE request_id=$1`, d.RequestId); !strings.HasPrefix(got, "erased:") {
		t.Fatalf("erasure missed the canonical call principal: %s", got)
	}
}

func TestGatewayAuthorizationRejectsUnsafeStoredIdentityBeforeLedger(t *testing.T) {
	f, req := gatewayFixture(t)
	key, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	poison := "fake-cc\r\nInjected: SECRET-POISON"
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,costCentre}',to_jsonb($1::text))`, poison)
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, key.Secret, call, &route)
	if err != nil || d.Allowed {
		t.Fatalf("unsafe identity authorized before adapter refusal: %+v %v", d, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM gateway_calls`); n != 0 {
		t.Fatal("unsafe identity got an authorized ledger entry")
	}
	if raw := testdb.Scalar(t, f.db.OwnerURL, `SELECT coalesce(string_agg(to_jsonb(e)::text,''),'') FROM evidence_events e WHERE action LIKE 'gateway.call.%'`); strings.Contains(raw, "SECRET-POISON") {
		t.Fatal("denial copied unsafe stored header content")
	}
}

func TestGatewayAuthenticatedDenialCarriesOnlyTrustedAttribution(t *testing.T) {
	f, req := gatewayFixture(t)
	key, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.RevokeKey(t.Context(), f.actor, key.Key.Id, "operator"); err != nil {
		t.Fatal(err)
	}
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, key.Secret, call, &route)
	if err != nil || d.Allowed || d.Person != nil {
		t.Fatalf("denial = %+v %v", d, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='gateway.call.denied' AND after->>'keyId'=$1 AND after->>'instance'=$2 AND after->>'person'=$3`, key.Key.Id.String(), req.Instance, f.actor.Name); n != 1 {
		t.Fatal("authenticated refusal lost trusted key/person attribution")
	}
}

func TestGatewayAuthorizationRechecksExpiryAfterKeyLockWait(t *testing.T) {
	f, req := gatewayFixture(t)
	key, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	gateConn, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gateConn.Close(context.Background()) }()
	gate, err := gateConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(context.Background()) }()
	if _, err := gate.Exec(ctx, `SELECT id FROM virtual_keys WHERE id=$1 FOR UPDATE`, key.Key.Id); err != nil {
		t.Fatal(err)
	}
	// Set expiry in a separate committed transaction before taking the gate: owner-only
	// fixture timestamp edits are safe here; the gate itself never changes the row.
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `UPDATE virtual_keys SET expires_at=clock_timestamp()+interval '400 milliseconds' WHERE id=$1`, key.Key.Id)
	gate, err = gateConn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Exec(ctx, `SELECT id FROM virtual_keys WHERE id=$1 FOR UPDATE`, key.Key.Id); err != nil {
		t.Fatal(err)
	}
	observer, err := pgx.Connect(ctx, f.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = observer.Close(context.Background()) }()
	call, route := modelCall()
	done := make(chan muistamov1.GatewayAuthorizationDecision, 1)
	errs := make(chan error, 1)
	go func() {
		d, err := f.svc.AuthorizeGateway(ctx, f.actor.Tenant, key.Secret, call, &route)
		done <- d
		errs <- err
	}()
	waitForGatewayLock(t, ctx, observer, `query LIKE '%FROM virtual_keys%FOR UPDATE%' AND wait_event_type='Lock'`)
	time.Sleep(450 * time.Millisecond)
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	d := <-done
	if err := <-errs; err != nil || d.Allowed || d.Reason != "inactive-key" {
		t.Fatalf("expired key escaped lock-wait recheck: %+v %v", d, err)
	}
}

func TestGatewayAuthorizationCommitsExactPriceAndEvidenceBeforeAllow(t *testing.T) {
	f, req := gatewayFixture(t)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately more precision than the generated float32 price type can preserve.
	testdb.Exec(t, f.db.OwnerURL, `UPDATE model_catalogue SET document=jsonb_set(jsonb_set(document,
		'{spec,priceSheet,inputPerMTok}','1.234567890123'::jsonb),'{spec,priceSheet,outputPerMTok}','9.876543210987'::jsonb)`)
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, &route)
	if err != nil || !d.Allowed || d.RequestId.Version() != 7 || d.Person == nil || *d.Person != f.actor.Name || d.Policy == nil || bool(d.Policy.Enforced) {
		t.Fatalf("authorization = %+v, %v", d, err)
	}
	if got := testdb.Scalar(t, f.db.OwnerURL, `SELECT input_per_mtok::text||'/'||output_per_mtok::text FROM gateway_calls WHERE request_id=$1`, d.RequestId); got != "1.234567890123/9.876543210987" {
		t.Fatalf("price snapshot lost decimal precision: %s", got)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='gateway.call.authorized' AND request_id=$1`, d.RequestId.String()); n != 1 {
		t.Fatalf("allow returned without persisted evidence: %d", n)
	}
	broken := registry.New(f.conn, failingSigner{f.key})
	failed, err := broken.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, &route)
	if !errors.Is(err, registry.ErrEvidence) || failed.Allowed || failed.Person != nil {
		t.Fatalf("unsigned allow escaped: %+v %v", failed, err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM gateway_calls`); n != 1 {
		t.Fatalf("failed evidence left an authorized call: %d", n)
	}
}

func TestGatewayAuthorizationDenialsAreSignedAndNeverStoreUntrustedContent(t *testing.T) {
	f, req := gatewayFixture(t)
	issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
	if err != nil {
		t.Fatal(err)
	}
	call, route := modelCall()
	for _, token := range []string{"", "not-a-key-secret-marker", issued.Secret[:len(issued.Secret)-43] + strings.Repeat("A", 43)} {
		d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, token, call, &route)
		if err != nil || d.Allowed || d.Reason != "invalid-key" || d.Person != nil {
			t.Fatalf("invalid credential = %+v %v", d, err)
		}
	}
	poison := "SECRET-UNTRUSTED-METADATA@example.invalid"
	bad := call
	bad.Path, bad.Alias = "/bad?secret="+poison, &poison
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, bad, &route)
	if err != nil || d.Allowed || d.Reason != "invalid-request" {
		t.Fatalf("bad route = %+v %v", d, err)
	}
	raw := testdb.Scalar(t, f.db.OwnerURL, `SELECT coalesce(string_agg(to_jsonb(e)::text,''),'') FROM evidence_events e WHERE action LIKE 'gateway.call.%'`)
	if strings.Contains(raw, poison) || strings.Contains(raw, issued.Secret) || strings.Contains(raw, "not-a-key-secret-marker") {
		t.Fatal("denial evidence retained bearer or untrusted content")
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE action='gateway.call.denied'`); n != 4 {
		t.Fatalf("denial evidence count = %d", n)
	}
}

func TestGatewayAuthorizationChecksCurrentScopeAndRoute(t *testing.T) {
	for _, scenario := range []string{"suspended", "revoked", "expired", "key-alias", "effective-alias", "approval", "alias-revision", "model-revision", "catalogue-name", "provider", "model", "region", "zero-budget", "budget-spent", "mcp", "missing-metadata", "wrong-path", "wrong-method", "no-route", "service-binding", "whitespace-binding", "oversized-binding"} {
		t.Run(scenario, func(t *testing.T) {
			f, req := gatewayFixture(t)
			if scenario == "zero-budget" {
				req.MonthlyBudget.Amount = "0"
			}
			issued, err := f.svc.IssueKey(t.Context(), f.actor, req)
			if err != nil {
				t.Fatal(err)
			}
			call, route := modelCall()
			pin := &route
			switch scenario {
			case "suspended":
				_, err = f.svc.TransitionTo(t.Context(), f.actor, req.Instance, "suspended")
			case "revoked":
				_, err = f.svc.RevokeKey(t.Context(), f.actor, issued.Key.Id, "operator")
			case "expired":
				testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE virtual_keys DISABLE TRIGGER virtual_keys_stamp`)
				testdb.Exec(t, f.db.OwnerURL, `UPDATE virtual_keys SET created_at=now()-interval '2 days',expires_at=now()-interval '1 day'`)
			case "key-alias":
				testdb.Exec(t, f.db.OwnerURL, `UPDATE virtual_keys SET aliases=ARRAY['other']`)
			case "effective-alias":
				testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_template_versions SET document=jsonb_set(document,'{spec,modelAlias}','"other"')`)
			case "approval":
				testdb.Exec(t, f.db.OwnerURL, `UPDATE model_catalogue SET approval_status='revoked',decided_by='seed:dpo',decision_reason='test',decided_at=now()`)
			case "alias-revision":
				route.AliasRevision++
			case "model-revision":
				route.ModelRevision++
			case "catalogue-name":
				route.CatalogueName = "other"
			case "provider":
				route.Provider = "other"
			case "model":
				route.Model = "other"
			case "region":
				route.Region = "other"
			case "budget-spent":
				// Prices remain SQL numerics. A synthetic recorded call consumes this key's cap.
				id := uuid.New()
				testdb.Exec(t, f.db.OwnerURL, `INSERT INTO gateway_calls(tenant_id,request_id,key_id,instance,person,kind,alias,provider,model,price_currency,input_per_mtok,output_per_mtok) VALUES($1,$2,$3,$4,'person-a@example.invalid','model','reasoning-default','test','test-model','EUR',1000000,0)`, f.actor.Tenant, id, issued.Key.Id, req.Instance)
				testdb.Exec(t, f.db.OwnerURL, `INSERT INTO usage_records(tenant_id,request_id,input_tokens,output_tokens,cost_amount,cost_currency) VALUES($1,$2,26,0,26,'EUR')`, f.actor.Tenant, id)
			case "mcp":
				call.Kind, call.Path = "mcp", "/mcp"
			case "missing-metadata":
				call.MetadataValid = false
			case "wrong-path":
				call.Path = "/v1/chat/completions?model=other"
			case "wrong-method":
				call.Method = "GET"
			case "no-route":
				pin = nil
			case "service-binding":
				testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,binding,type}','"service"')`)
			case "whitespace-binding":
				testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,binding,ref}','" person-a@example.invalid "')`)
			case "oversized-binding":
				testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,binding,ref}',to_jsonb($1::text))`, strings.Repeat("x",317))
			}
			if err != nil {
				t.Fatal(err)
			}
			d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, issued.Secret, call, pin)
			if err != nil || d.Allowed {
				t.Fatalf("%s was allowed: %+v, %v", scenario, d, err)
			}
			encoded, _ := json.Marshal(d)
			if strings.Contains(string(encoded), "person-a") {
				t.Fatal("denial response exposed identity")
			}
		})
	}
}

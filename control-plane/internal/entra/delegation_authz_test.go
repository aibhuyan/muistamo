//go:build authz

package entra

// Adversarial delegation checks (invariants 1-3). Never skip or weaken (AGENTS.md).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// Another linked person can never borrow HR-PERSON's agent by naming it.
func TestAuthzDelegationServesOnlyTheTokensOwnPerson(t *testing.T) {
	f := setupDelegation(t)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO hr_events (tenant_id,event_id,type,person_id,workflow_id,payload,occurred_at,generation,decision,dispatch_state,identity_mode,identity_binding_version)
		VALUES ($1,'other-join','joiner','HR-OTHER','','{}',now(),1,'accepted','pending','entra',$2)`, testTenant, binding().BindingVersion)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO person_entra_links (tenant_id,person_id,status,binding_version,entra_tenant_id,entra_user_object_id,receipt_id)
		SELECT $1,'HR-OTHER','matched',$2,$3,$4,receipt_id FROM hr_events WHERE event_id='other-join'`, testTenant, binding().BindingVersion, binding().EntraTenantId, userB)
	_, err := f.delegate(t, f.dir.token(userClaims(userB)), &f.name)
	refusedWith(t, err, "no-active-agent")
	_, err = f.delegate(t, f.dir.token(userClaims(userB)), nil)
	refusedWith(t, err, "no-active-agent")
	if f.dir.exchanges != 0 {
		t.Fatal("another person's token reached the exchange for HR-PERSON's agent")
	}
}

// A tenant's knowledge service never reaches another tenant's people, links or nonces.
func TestAuthzDelegationIsTenantScoped(t *testing.T) {
	f := setupDelegation(t)
	other := uuid.New()
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO tenants (id, name) VALUES ($1, 'globex')`, other)
	actor := registry.Actor{Tenant: other, Name: "knowledge:" + other.String(), RequestID: uuid.NewString()}
	exchanged := false
	_, err := f.svc.Delegate(context.Background(), actor, registry.DelegationRequest{BindingVersion: uuid.MustParse(binding().BindingVersion), EntraTenant: uuid.MustParse(binding().EntraTenantId), User: userA},
		func(context.Context, uuid.UUID) (string, time.Time, error) {
			exchanged = true
			return "obviously-fake", time.Now().Add(time.Hour), nil
		})
	refusedWith(t, err, "user-unlinked")
	if exchanged {
		t.Fatal("another tenant's request reached the exchange")
	}
	nonce := "0123456789abcdef0123456789abcdef"
	if err := f.svc.UseDelegationNonce(context.Background(), testTenant, nonce); err != nil {
		t.Fatal(err)
	}
	if n := testdb.CountIn(t, f.db.AppURL, other, `SELECT count(*) FROM delegation_nonces`); n != 0 {
		t.Fatalf("another tenant sees %d nonces", n)
	}
	if err := testdb.ExecErr(f.db.AppURL, other, `INSERT INTO delegation_nonces (tenant_id, nonce) VALUES ($1, 'ffffffffffffffffffffffffffffffff')`, testTenant); err == nil {
		t.Fatal("another tenant planted a nonce")
	}
	testdb.ExecIn(t, f.db.AppURL, other, `DELETE FROM delegation_nonces`)
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM delegation_nonces`); n != 1 {
		t.Fatalf("another tenant deleted nonces: %d left", n)
	}
}

// An app-only token never acts for a person, and a leaver's agent gets nothing at the next call.
func TestAuthzDelegationRefusesAppTokensAndLeavers(t *testing.T) {
	f := setupDelegation(t)
	app := userClaims(userA)
	delete(app, "scp")
	app["roles"], app["idtyp"] = []string{KnowledgeScope}, "app"
	_, err := f.delegate(t, f.dir.token(app), nil)
	refusedWith(t, err, "token-invalid")
	token := f.dir.token(userClaims(userA))
	if _, err := f.delegate(t, token, nil); err != nil {
		t.Fatal(err)
	}
	seedAdapterHR(t, f.conn, f.key, f.actor, "leave", "leaver", 2)
	// The cached exchange for this very token is not reused: the decision is made again.
	_, err = f.delegate(t, token, nil)
	refusedWith(t, err, "user-unlinked")
}

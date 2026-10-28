package registry_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestGatewayAuthorizationPinsCloneAndPublicationScope(t *testing.T) {
	for _, mode := range []muistamov1.AgentCloneSpecSync{"manual", "follow"} {
		t.Run(string(mode), func(t *testing.T) {
			f, req := gatewayFixture(t)
			testdb.CatalogueApprover(t, f.db.OwnerURL, f.actor.Tenant, f.actor.Name)
			publication, err := f.svc.RequestPublication(t.Context(), f.actor, "analyst-intern", 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"dev:approver-one@example.invalid", "dev:approver-two@example.invalid"} {
				testdb.CatalogueApprover(t, f.db.OwnerURL, f.actor.Tenant, name)
				approver := f.actor
				approver.Name = name
				if _, err := f.svc.DecideCatalogueRequest(t.Context(), approver, publication.Id, "approve", "fake fixture approval"); err != nil {
					t.Fatal(err)
				}
			}
			clone := muistamov1.AgentClone{ApiVersion: "muistamo.dev/v1", Kind: "AgentClone"}
			clone.Metadata.Name = "scope-clone"
			clone.Spec.Template, clone.Spec.Sync = "analyst-intern", mode
			if _, _, err := f.svc.ApplyClone(t.Context(), f.actor, clone); err != nil {
				t.Fatal(err)
			}
			doc := instance("requested")
			doc.Metadata.Name = "scope-clone-person"
			doc.Spec.CloneRef = &clone.Metadata.Name
			if _, _, err := f.svc.ApplyInstance(t.Context(), f.actor, doc, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.TransitionTo(t.Context(), f.actor, doc.Metadata.Name, "active"); err != nil {
				t.Fatal(err)
			}
			req.Instance = doc.Metadata.Name
			key, err := f.svc.IssueKey(t.Context(), f.actor, req)
			if err != nil {
				t.Fatal(err)
			}
			testdb.ApprovedModelAlias(t, f.db.OwnerURL, f.actor.Tenant, "other")
			next := template("new scope")
			next.Spec.ModelAlias = "other"
			if _, _, err := f.svc.ApplyTemplate(t.Context(), f.actor, next); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			conn, err := pgx.Connect(ctx, f.db.OwnerURL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close(context.Background()) }()
			gate, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = gate.Rollback(context.Background()) }()
			if _, err := gate.Exec(ctx, `LOCK TABLE model_catalogue IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			observer, err := pgx.Connect(ctx, f.db.OwnerURL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = observer.Close(context.Background()) }()
			call, route := modelCall()
			auth := make(chan error, 1)
			go func() {
				d, err := f.svc.AuthorizeGateway(ctx, f.actor.Tenant, key.Secret, call, &route)
				if err == nil && !d.Allowed {
					err = errors.New("authorization unexpectedly denied")
				}
				auth <- err
			}()
			waitForGatewayLock(t, ctx, observer, `query LIKE '%model_catalogue%' AND wait_event_type='Lock'`)
			updated := make(chan error, 1)
			query := `UPDATE agent_clones SET synced_version=2 WHERE name='scope-clone'`
			predicate := `query LIKE 'UPDATE agent_clones SET synced_version%' AND wait_event_type='Lock'`
			if mode == "follow" {
				query = `UPDATE catalogue_published SET version=2 WHERE template='analyst-intern'`
				predicate = `query LIKE 'UPDATE catalogue_published SET version%' AND wait_event_type='Lock'`
			}
			go func() {
				updated <- f.conn.InTenant(ctx, f.actor.Tenant, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query); return err })
			}()
			waited := gatewayLockObserved(ctx, observer, predicate)
			if err := gate.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-auth; err != nil {
				t.Fatal(err)
			}
			if err := <-updated; err != nil {
				t.Fatal(err)
			}
			if !waited {
				t.Error("effective scope changed before authorization ledger insertion")
			}
			if d, err := f.svc.AuthorizeGateway(ctx, f.actor.Tenant, key.Secret, call, &route); err != nil || d.Allowed || d.Reason != "alias-not-allowed" {
				t.Fatalf("old key scope survived clone change: %+v %v", d, err)
			}
		})
	}
}

func TestGatewayFollowCloneWithoutLockedPublicationIsRefused(t *testing.T) {
	f, req := gatewayFixture(t)
	// Owner fixture creates a valid clone without a publication; this covers a withdrawal
	// before the locked selection and never permits a later second read to supply scope.
	clone := muistamov1.AgentClone{ApiVersion: "muistamo.dev/v1", Kind: "AgentClone"}
	clone.Metadata.Name = "withdrawn-clone"
	clone.Spec.Template, clone.Spec.Sync = "analyst-intern", "follow"
	testdb.CatalogueApprover(t, f.db.OwnerURL, f.actor.Tenant, f.actor.Name)
	if _, _, err := f.svc.ApplyClone(t.Context(), f.actor, clone); err != nil {
		t.Fatal(err)
	}
	testdb.Exec(t, f.db.OwnerURL, `UPDATE agent_instances SET document=jsonb_set(document,'{spec,cloneRef}','"withdrawn-clone"')`)
	// Seed an existing key, as it would predate the catalogue withdrawal.
	keyID := uuid.New()
	secret := make([]byte, 32)
	sum := sha256.Sum256(secret)
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO virtual_keys(tenant_id,id,instance,aliases,budget_amount,budget_currency,secret_sha256,created_by) VALUES($1,$2,$3,ARRAY['reasoning-default'],25,'EUR',$4,$5)`, f.actor.Tenant, keyID, req.Instance, sum[:], f.actor.Name)
	call, route := modelCall()
	d, err := f.svc.AuthorizeGateway(t.Context(), f.actor.Tenant, "mvk_"+keyID.String()+"_"+base64.RawURLEncoding.EncodeToString(secret), call, &route)
	if err != nil || d.Allowed || d.Reason != "alias-not-allowed" {
		t.Fatalf("follow clone without locked publication was not a signed refusal: %+v %v", d, err)
	}
}

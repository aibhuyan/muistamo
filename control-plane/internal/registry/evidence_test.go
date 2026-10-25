package registry_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func (f fixture) chain(t *testing.T, actor registry.Actor) []evidencechain.Event {
	t.Helper()
	events, err := f.svc.ListEvents(context.Background(), actor, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func (f fixture) keys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{f.key.KeyID(): f.key.Public()}
}

func TestEvidenceChainVerifies(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("first")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("second")); err != nil {
		t.Fatal(err)
	}
	rec, _, err := f.svc.ApplyInstance(ctx, f.actor, instance(muistamov1.InstanceStateRequested), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Transition(ctx, f.actor, rec.Document.Metadata.Name, muistamov1.InstanceStateActive, registry.ETag(1)); err != nil {
		t.Fatal(err)
	}

	events := f.chain(t, f.actor)
	if len(events) != 4 {
		t.Fatalf("events = %d, want 4", len(events))
	}
	if err := evidencechain.Verify(events, f.keys()); err != nil {
		t.Fatalf("chain read back from the database does not verify: %v", err)
	}
	if events[3].Action != "instance.transitioned" || events[3].Actor != f.actor.Name || events[3].RequestID != f.actor.RequestID {
		t.Fatalf("last event = %+v", events[3])
	}
}

func TestConcurrentWritesKeepTheChainGapFree(t *testing.T) {
	f := setup(t)
	const writers = 20
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doc := template("concurrent")
			doc.Metadata.Name = fmt.Sprintf("template-%02d", i)
			if _, _, err := f.svc.ApplyTemplate(context.Background(), f.actor, doc); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	events := f.chain(t, f.actor)
	if len(events) != writers {
		t.Fatalf("events = %d, want %d", len(events), writers)
	}
	if err := evidencechain.Verify(events, f.keys()); err != nil {
		t.Fatalf("chain after concurrent writes: %v", err)
	}
}

func TestEachTenantHasItsOwnChain(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	other, err := store.CreateTenant(ctx, f.db.OwnerURL, "globex")
	if err != nil {
		t.Fatal(err)
	}
	b := f.actor
	b.Tenant = other

	for _, actor := range []registry.Actor{f.actor, b, f.actor} {
		if _, _, err := f.svc.ApplyTemplate(ctx, actor, template("purpose of "+actor.Tenant.String())); err != nil {
			t.Fatal(err)
		}
	}
	a, bEvents := f.chain(t, f.actor), f.chain(t, b)
	if len(a) != 1 || len(bEvents) != 1 || bEvents[0].Seq != 1 || bEvents[0].PrevHash != evidencechain.GenesisHash {
		t.Fatalf("chains: A has %d events, B has %d (B seq %d); want one each, both starting at seq 1",
			len(a), len(bEvents), bEvents[0].Seq)
	}
	for _, chain := range [][]evidencechain.Event{a, bEvents} {
		if err := evidencechain.Verify(chain, f.keys()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEvidenceIsAppendOnlyEvenForTheOwner(t *testing.T) {
	f := setup(t)
	if _, _, err := f.svc.ApplyTemplate(context.Background(), f.actor, template("first")); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`UPDATE evidence_events SET actor = 'someone-else'`,
		`DELETE FROM evidence_events`,
		`TRUNCATE evidence_events`,
	} {
		err := testdb.ExecErr(f.db.OwnerURL, f.actor.Tenant, stmt)
		if err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s as owner: err = %v, want the append-only trigger to refuse", stmt, err)
		}
	}
}

func TestTamperingIsDetected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, purpose := range []string{"first", "second", "third"} {
		if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template(purpose)); err != nil {
			t.Fatal(err)
		}
	}
	// An owner who disables the guard can still change history; verification must notice.
	testdb.Exec(t, f.db.OwnerURL, `ALTER TABLE evidence_events DISABLE TRIGGER evidence_events_append_only`)
	testdb.Exec(t, f.db.OwnerURL, `UPDATE evidence_events SET after = jsonb_set(after, '{createdBy}', '"dev:someone-else"') WHERE seq = 2`)

	err := evidencechain.Verify(f.chain(t, f.actor), f.keys())
	var verr *evidencechain.VerifyError
	if !errors.As(err, &verr) || verr.Seq != 2 {
		t.Fatalf("err = %v, want verification to fail at seq 2", err)
	}
}

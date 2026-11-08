package registry_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

func TestNeededApprovalsFailClosed(t *testing.T) {
	for tier, want := range map[string]int{"low": 0, "medium": 1, "high": 2, "": 2, "unknown": 2} {
		if got := registry.NeededApprovals(tier); got != want {
			t.Errorf("NeededApprovals(%q) = %d, want %d", tier, got, want)
		}
	}
}

type catalogueFixture struct {
	fixture
	requester, approver1, approver2, outsider registry.Actor
}

func setupCatalogue(t *testing.T) catalogueFixture {
	t.Helper()
	f := setup(t)
	as := func(name string) registry.Actor {
		a := f.actor
		a.Name = "dev:" + name
		return a
	}
	c := catalogueFixture{fixture: f, requester: as("owner@example.invalid"), approver1: as("cat-1@example.invalid"),
		approver2: as("cat-2@example.invalid"), outsider: as("someone@example.invalid")}
	if err := store.SetCatalogueApprovers(context.Background(), f.db.OwnerURL, f.actor.Tenant,
		[]string{c.approver1.Name, c.approver2.Name, c.requester.Name}); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c catalogueFixture) apply(t *testing.T, tier string, purpose string) int {
	t.Helper()
	doc := template(purpose)
	if tier != "" {
		rt := muistamov1.AgentTemplateSpecRiskTier(tier)
		doc.Spec.RiskTier = &rt
	}
	rec, _, err := c.svc.ApplyTemplate(context.Background(), c.requester, doc)
	if err != nil {
		t.Fatal(err)
	}
	return rec.Version
}

func (c catalogueFixture) published(t *testing.T) map[string]int {
	t.Helper()
	entries, err := c.svc.ListCatalogue(context.Background(), c.requester)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, e := range entries {
		out[e.Template] = e.Version
	}
	return out
}

func TestApprovalByRiskTier(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		tier   string
		needed int
	}{{"low", 0}, {"medium", 1}, {"high", 2}, {"", 2}} {
		t.Run("tier="+tc.tier, func(t *testing.T) {
			c := setupCatalogue(t)
			v := c.apply(t, tc.tier, "purpose")
			req, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v)
			if err != nil {
				t.Fatal(err)
			}
			if req.NeededApprovals != tc.needed {
				t.Fatalf("needed = %d, want %d", req.NeededApprovals, tc.needed)
			}
			approvers := []registry.Actor{c.approver1, c.approver2}
			for i := 0; i < tc.needed; i++ {
				if req.State != muistamov1.CatalogueRequestStatePending {
					t.Fatalf("after %d approvals state = %s, want pending", i, req.State)
				}
				if _, ok := c.published(t)["analyst-intern"]; ok {
					t.Fatalf("published after only %d of %d approvals", i, tc.needed)
				}
				if req, err = c.svc.DecideCatalogueRequest(ctx, approvers[i], req.Id, "approve", "ok"); err != nil {
					t.Fatal(err)
				}
			}
			if req.State != muistamov1.CatalogueRequestStatePublished || c.published(t)["analyst-intern"] != v {
				t.Fatalf("state = %s, catalogue = %v; want published v%d", req.State, c.published(t), v)
			}
		})
	}
}

func TestApprovalRulesCannotBeBent(t *testing.T) {
	c := setupCatalogue(t)
	ctx := context.Background()
	v := c.apply(t, "high", "purpose")
	req, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.DecideCatalogueRequest(ctx, c.requester, req.Id, "approve", "mine"); !errors.Is(err, registry.ErrForbidden) {
		t.Fatalf("requester approving own request: err = %v, want ErrForbidden (even though they are an approver)", err)
	}
	if _, err := c.svc.DecideCatalogueRequest(ctx, c.outsider, req.Id, "approve", "x"); !errors.Is(err, registry.ErrForbidden) {
		t.Fatalf("non-approver: err = %v, want ErrForbidden", err)
	}
	if _, err := c.svc.DecideCatalogueRequest(ctx, c.approver1, req.Id, "approve", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.svc.DecideCatalogueRequest(ctx, c.approver1, req.Id, "approve", "again"); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("same approver twice: err = %v, want ErrConflict", err)
	}
	if _, ok := c.published(t)["analyst-intern"]; ok {
		t.Fatal("a high-risk template was published with one distinct approver")
	}
	if _, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v); !errors.Is(err, registry.ErrConflict) {
		t.Fatalf("second pending request for the same version: err = %v, want ErrConflict", err)
	}

	rejected, err := c.svc.DecideCatalogueRequest(ctx, c.approver2, req.Id, "reject", "too broad")
	if err != nil || rejected.State != muistamov1.CatalogueRequestStateRejected {
		t.Fatalf("reject: state %v, %v", rejected.State, err)
	}
	if _, ok := c.published(t)["analyst-intern"]; ok {
		t.Fatal("rejected request was published")
	}
}

func TestNewerVersionReplacesAndWithdrawalStopsMatching(t *testing.T) {
	c := setupCatalogue(t)
	ctx := context.Background()
	v1 := c.apply(t, "low", "first")
	first, _ := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v1)
	v2 := c.apply(t, "low", "second")
	if _, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v2); err != nil {
		t.Fatal(err)
	}
	if got := c.published(t)["analyst-intern"]; got != v2 {
		t.Fatalf("catalogue version = %d, want %d", got, v2)
	}
	superseded, _ := c.svc.ListCatalogueRequests(ctx, c.requester, "superseded")
	if len(superseded) != 1 || superseded[0].Id != first.Id {
		t.Fatalf("superseded = %+v, want the first request", superseded)
	}

	if err := c.svc.Withdraw(ctx, c.outsider, "analyst-intern"); !errors.Is(err, registry.ErrForbidden) {
		t.Fatalf("non-approver withdraw: err = %v", err)
	}
	if err := c.svc.Withdraw(ctx, c.approver1, "analyst-intern"); err != nil {
		t.Fatal(err)
	}
	if len(c.published(t)) != 0 {
		t.Fatalf("catalogue after withdrawal = %v", c.published(t))
	}
}

func TestConcurrentApprovalsPublishOnce(t *testing.T) {
	c := setupCatalogue(t)
	ctx := context.Background()
	v := c.apply(t, "medium", "purpose")
	req, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, a := range []registry.Actor{c.approver1, c.approver2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = c.svc.DecideCatalogueRequest(ctx, a, req.Id, "approve", "ok")
		}()
	}
	wg.Wait()
	ok, conflicts := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, registry.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || conflicts != 1 {
		t.Fatalf("ok=%d conflicts=%d, want exactly one approval to count and one to find the request closed", ok, conflicts)
	}
	events, _ := c.svc.ListEvents(ctx, c.requester, 0, 1000)
	published := 0
	for _, e := range events {
		if e.Action == "catalogue.published" {
			published++
		}
	}
	if published != 1 {
		t.Fatalf("catalogue.published events = %d, want 1", published)
	}
	if err := evidencechain.Verify(events, map[string]ed25519.PublicKey{c.key.KeyID(): c.key.Public()}); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownRequestIsNotFound(t *testing.T) {
	c := setupCatalogue(t)
	if _, err := c.svc.DecideCatalogueRequest(context.Background(), c.approver1, uuid.New(), "approve", "x"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// Who reads the catalogue inbox (maintainer decision, 2026-11-08): approvers every request, anyone
// else only the requests they filed.
func TestTheCatalogueInboxIsForApproversAndEachRequesterOwn(t *testing.T) {
	ctx := context.Background()
	c := setupCatalogue(t)
	v := c.apply(t, "medium", "purpose")
	if _, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v); err != nil {
		t.Fatal(err)
	}
	// The requester is no longer an approver: they still see their own request.
	if err := store.SetCatalogueApprovers(ctx, c.db.OwnerURL, c.actor.Tenant, []string{c.approver1.Name}); err != nil {
		t.Fatal(err)
	}
	for who, want := range map[registry.Actor]int{c.approver1: 1, c.requester: 1, c.outsider: 0, c.approver2: 0} {
		got, err := c.svc.ListCatalogueRequests(ctx, who, "")
		if err != nil || len(got) != want {
			t.Errorf("%s sees %d requests (%v), want %d", who.Name, len(got), err, want)
		}
	}
}

// A console caller's decision is evidenced with the console app (the event body only).
func TestAConsoleDecisionNamesTheConsoleApp(t *testing.T) {
	ctx := context.Background()
	c := setupCatalogue(t)
	v := c.apply(t, "medium", "purpose")
	req, err := c.svc.RequestPublication(ctx, c.requester, "analyst-intern", v)
	if err != nil {
		t.Fatal(err)
	}
	console := c.approver1
	console.ClientApp = uuid.MustParse("c0c0c0c0-0000-4000-8000-0000000c0501")
	if _, err := c.svc.DecideCatalogueRequest(ctx, console, req.Id, "approve", "fit"); err != nil {
		t.Fatal(err)
	}
	app := testdb.Scalar(t, c.db.OwnerURL, `SELECT after->'client'->>'app' FROM evidence_events WHERE action = 'catalogue.request.approved'`)
	kind := testdb.Scalar(t, c.db.OwnerURL, `SELECT after->'client'->>'kind' FROM evidence_events WHERE action = 'catalogue.request.approved'`)
	if app != "c0c0c0c0-0000-4000-8000-0000000c0501" || kind != "console" {
		t.Fatalf("evidence client = %q %q", app, kind)
	}
	// Only the console caller's events name it (its decision, and the publication it caused);
	// the development requester's never do.
	if n := testdb.Scalar(t, c.db.OwnerURL, `SELECT count(*) FROM evidence_events WHERE actor <> $1 AND after ? 'client'`, console.Name); n != "0" {
		t.Fatalf("a request without a client named one: %s", n)
	}
}

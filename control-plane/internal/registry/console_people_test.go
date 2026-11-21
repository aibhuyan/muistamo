package registry_test

// HUMAN REVIEW REQUIRED (AGENTS.md): who may read people and HR events through the console, and
// what of them (docs/console-management-plan.md, slice 3; D70).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

// seedReceipts records n legacy HR events for person, one second apart from base, ev-<person>-<i>,
// each with a payload naming the person's email.
func seedReceipts(t *testing.T, f fixture, person string, n int, base time.Time) {
	t.Helper()
	for i := range n {
		testdb.Exec(t, f.db.OwnerURL, `INSERT INTO hr_events (tenant_id,event_id,type,person_id,received_at,occurred_at,workflow_id,payload)
			VALUES ($1,$2,'joiner',$3,$4,$4,'wf',jsonb_build_object('person',jsonb_build_object('id',$3::text,'email','secret-'||$3||'@example.invalid')))`,
			f.actor.Tenant, fmt.Sprintf("ev-%s-%03d", person, i), person, base.Add(time.Duration(i)*time.Second))
	}
}

func TestHRFeedPagesNewestFirstWithoutThePayload(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	base := time.Date(2026, 11, 1, 9, 0, 0, 123456000, time.UTC)
	seedReceipts(t, f, "P1", 5, base)
	// Two events received at the same instant are ordered by id and neither is lost at a page edge.
	testdb.Exec(t, f.db.OwnerURL, `INSERT INTO hr_events (tenant_id,event_id,type,person_id,received_at,occurred_at,workflow_id,payload)
		VALUES ($1,'ev-tie-a','leaver','P2',$2,$2,'wf','{}'), ($1,'ev-tie-b','leaver','P2',$2,$2,'wf','{}')`, f.actor.Tenant, base.Add(2*time.Second))

	var seen []string
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging does not end")
		}
		page, err := f.svc.ListHrReceipts(ctx, f.actor, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(page)
		if strings.Contains(string(raw), "@example") {
			t.Fatalf("the feed carries the payload: %s", raw)
		}
		for _, r := range page.Items {
			seen = append(seen, r.EventId)
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	want := []string{"ev-P1-004", "ev-P1-003", "ev-tie-b", "ev-tie-a", "ev-P1-002", "ev-P1-001", "ev-P1-000"}
	if strings.Join(seen, ",") != strings.Join(want, ",") {
		t.Errorf("feed = %v, want %v", seen, want)
	}
	if _, err := f.svc.ListHrReceipts(ctx, f.actor, "not-a-cursor", 2); !errors.Is(err, registry.ErrInvalid) {
		t.Errorf("a bad cursor = %v, want ErrInvalid", err)
	}
}

func TestPersonPageListsTheirEventsAndAgentsOnly(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	seedReceipts(t, f, "P1", 101, time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC))
	seedReceipts(t, f, "P2", 1, time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC))
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("research")); err != nil {
		t.Fatal(err)
	}
	// An agent labelled with P3's id, made by hand: P3 has no HR event and is still found.
	doc := instance("requested")
	labels := map[string]string{registry.PersonLabel: "P3"}
	doc.Metadata.Labels = &labels
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, doc, ""); err != nil {
		t.Fatal(err)
	}

	p1, err := f.svc.GetPerson(ctx, f.actor, "P1")
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Receipts) != 100 || !p1.ReceiptsTruncated || p1.Receipts[0].EventId != "ev-P1-100" || len(p1.Agents) != 0 {
		t.Errorf("P1: %d events (truncated %v, first %s), %d agents", len(p1.Receipts), p1.ReceiptsTruncated, p1.Receipts[0].EventId, len(p1.Agents))
	}
	for _, r := range p1.Receipts {
		if r.PersonId != "P1" {
			t.Fatalf("P1's page lists %s's event", r.PersonId)
		}
	}
	p2, err := f.svc.GetPerson(ctx, f.actor, "P2")
	if err != nil || len(p2.Receipts) != 1 || p2.ReceiptsTruncated {
		t.Errorf("P2 = %+v, %v", p2, err)
	}
	p3, err := f.svc.GetPerson(ctx, f.actor, "P3")
	if err != nil || len(p3.Receipts) != 0 || len(p3.Agents) != 1 {
		t.Fatalf("P3 = %+v, %v", p3, err)
	}
	a := p3.Agents[0]
	if a.Name != "analyst-intern-person-a" || a.TemplateName != "analyst-intern" || a.TemplateVersion != "1" || a.CloneName != nil || a.State != "requested" {
		t.Errorf("P3's agent = %+v", a)
	}
	raw, _ := json.Marshal([]any{p1, p2, p3})
	if strings.Contains(string(raw), "@example") {
		t.Errorf("a person's page carries an email: %s", raw)
	}
	if _, err := f.svc.GetPerson(ctx, f.actor, "NOBODY"); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("an unknown person = %v, want ErrNotFound", err)
	}
}

func TestConsoleCallersNeedTheAdministratorRoleToReadPeople(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	seedReceipts(t, f, "P1", 1, time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC))
	const admin, auditor, nobody = "entra:aaaaaaaa-0000-4000-8000-000000000001", "entra:aaaaaaaa-0000-4000-8000-000000000002", "entra:aaaaaaaa-0000-4000-8000-000000000003"
	setRole(t, f, f.actor.Tenant, "administrator", admin)
	setRole(t, f, f.actor.Tenant, "auditor", auditor)
	for who, want := range map[string]error{admin: nil, auditor: registry.ErrForbidden, nobody: registry.ErrForbidden} {
		_, listErr := f.svc.ListHrReceipts(ctx, throughConsole(f.actor, who), "", 50)
		_, getErr := f.svc.GetPerson(ctx, throughConsole(f.actor, who), "P1")
		// A malformed cursor says nothing to a caller without the role.
		_, cursorErr := f.svc.ListHrReceipts(ctx, throughConsole(f.actor, who), "not-a-cursor", 50)
		if want != nil && !errors.Is(cursorErr, want) {
			t.Errorf("%s with a bad cursor = %v, want %v", who, cursorErr, want)
		}
		for name, err := range map[string]error{"feed": listErr, "person": getErr} {
			if (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
				t.Errorf("%s %s = %v, want %v", who, name, err, want)
			}
		}
	}
	// A development caller needs no role.
	if _, err := f.svc.GetPerson(ctx, f.actor, "P1"); err != nil {
		t.Errorf("development caller = %v", err)
	}
}

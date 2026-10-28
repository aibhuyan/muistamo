package api_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// noPersonalData lists the tenant tables that hold no person's identifier, with the reason.
// Every tenant table must be here or in registry.PersonalDataTables: erasure and access exports
// reach only the inventory, so a table missing from both would silently escape them (invariant 5).
var noPersonalData = map[string]string{
	"agent_templates":           "template name and latest version number only",
	"catalogue_published":       "template, version and request id; the requester is in catalogue_requests",
	"evidence_heads":            "the chain's sequence number and hash",
	"hr_webhook_secrets":        "the tenant's HMAC secret",
	"identity_enrollments":      "the tenant's Entra binding version",
	"knowledge_service_secrets": "the tenant's service-call secret",
	"usage_records":             "token counts and cost per request id; the person is in gateway_calls",
}

func TestEveryTenantTableIsClassifiedForPrivacy(t *testing.T) {
	h := newHarness(t, api.InsecureDevHeaders{})
	conn, err := pgx.Connect(t.Context(), h.db.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(t.Context()) }()
	rows, err := conn.Query(t.Context(), `SELECT DISTINCT table_name FROM information_schema.columns
		WHERE table_schema = 'public' AND column_name = 'tenant_id' ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var unclassified []string
	for _, table := range tables {
		_, exempt := noPersonalData[table]
		if !exempt && !slices.Contains(registry.PersonalDataTables, table) {
			unclassified = append(unclassified, table)
		}
	}
	if len(unclassified) > 0 {
		t.Errorf("tenant tables in neither registry.PersonalDataTables nor noPersonalData: %s", strings.Join(unclassified, ", "))
	}
	for table := range noPersonalData {
		if slices.Contains(registry.PersonalDataTables, table) {
			t.Errorf("%s is both personal data and exempt", table)
		}
	}
}

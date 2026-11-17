package registry_test

// HUMAN REVIEW REQUIRED (AGENTS.md): who may read agents and templates through the console
// (docs/console-management-plan.md, D70).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
	"muistamo.dev/muistamo/control-plane/internal/testdb"
)

var consoleApp = uuid.MustParse("c0c0c0c0-0000-4000-8000-0000000c0501")

// throughConsole is the same person as actor, signed in through the console.
func throughConsole(actor registry.Actor, name string) registry.Actor {
	actor.Name, actor.ClientApp, actor.RequestID = name, consoleApp, uuid.NewString()
	return actor
}

func operator(tenant uuid.UUID) registry.Actor {
	return registry.Actor{Tenant: tenant, Name: "operator:test", RequestID: uuid.NewString()}
}

func setRole(t *testing.T, f fixture, tenant uuid.UUID, role string, people ...string) {
	t.Helper()
	if err := registry.ConfigureConsoleRole(t.Context(), f.db.OwnerURL, operator(tenant), role, people, f.key); err != nil {
		t.Fatalf("set %s: %v", role, err)
	}
}

// seedAgent gives the fixture's tenant one template and one instance, written by a
// development caller as the CLI would.
func seedAgent(t *testing.T, f fixture) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.svc.ApplyTemplate(ctx, f.actor, template("research")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.ApplyInstance(ctx, f.actor, instance("requested"), ""); err != nil {
		t.Fatal(err)
	}
}

// reads runs the four reads the console's agent and template pages make.
func reads(f fixture, who registry.Actor) map[string]error {
	ctx := context.Background()
	_, listInstances := f.svc.ListInstances(ctx, who, "", 50)
	_, getInstance := f.svc.GetInstance(ctx, who, "analyst-intern-person-a")
	_, listTemplates := f.svc.ListTemplates(ctx, who, "", 50)
	_, getTemplate := f.svc.GetTemplate(ctx, who, "analyst-intern")
	return map[string]error{"list instances": listInstances, "get instance": getInstance, "list templates": listTemplates, "get template": getTemplate}
}

func TestConsoleCallersNeedTheAdministratorRoleToReadAgentsAndTemplates(t *testing.T) {
	f := setup(t)
	seedAgent(t, f)
	const admin, auditor, nobody = "entra:aaaaaaaa-0000-4000-8000-000000000001", "entra:aaaaaaaa-0000-4000-8000-000000000002", "entra:aaaaaaaa-0000-4000-8000-000000000003"
	setRole(t, f, f.actor.Tenant, "administrator", admin)
	setRole(t, f, f.actor.Tenant, "auditor", auditor)

	for name, err := range reads(f, throughConsole(f.actor, admin)) {
		if err != nil {
			t.Errorf("administrator, %s: %v", name, err)
		}
	}
	// An auditor reads the evidence log, not agents; someone with no role reads neither.
	for _, who := range []string{auditor, nobody} {
		for name, err := range reads(f, throughConsole(f.actor, who)) {
			if !errors.Is(err, registry.ErrForbidden) {
				t.Errorf("%s, %s = %v, want forbidden", who, name, err)
			}
		}
	}
	// A refusal comes before the lookup: a missing name does not tell a non-administrator
	// whether the agent or template exists.
	if _, err := f.svc.GetInstance(t.Context(), throughConsole(f.actor, nobody), "no-such-agent"); !errors.Is(err, registry.ErrForbidden) {
		t.Errorf("missing instance for a non-administrator = %v, want forbidden", err)
	}
	if _, err := f.svc.GetTemplate(t.Context(), throughConsole(f.actor, nobody), "no-such-template"); !errors.Is(err, registry.ErrForbidden) {
		t.Errorf("missing template for a non-administrator = %v, want forbidden", err)
	}
	// Development callers (the CLI, Terraform, workflows) carry no console app and are unchanged.
	for name, err := range reads(f, f.actor) {
		if err != nil {
			t.Errorf("development caller, %s: %v", name, err)
		}
	}
	// The role is read at the time of the call: once removed, the next read is refused.
	setRole(t, f, f.actor.Tenant, "administrator")
	for name, err := range reads(f, throughConsole(f.actor, admin)) {
		if !errors.Is(err, registry.ErrForbidden) {
			t.Errorf("former administrator, %s = %v, want forbidden", name, err)
		}
	}
}

func TestConsoleAccessReportsTheCallersOwnRoles(t *testing.T) {
	f := setup(t)
	const admin, auditor = "entra:aaaaaaaa-0000-4000-8000-000000000001", "entra:aaaaaaaa-0000-4000-8000-000000000002"
	setRole(t, f, f.actor.Tenant, "administrator", admin)
	setRole(t, f, f.actor.Tenant, "auditor", auditor)
	if err := registry.ConfigureGatewayAdmins(t.Context(), f.db.OwnerURL, operator(f.actor.Tenant), []string{auditor}, f.key); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCatalogueApprovers(t.Context(), f.db.OwnerURL, f.actor.Tenant, []string{admin}); err != nil {
		t.Fatal(err)
	}
	for who, want := range map[string][4]bool{
		admin:        {true, false, true, false},
		auditor:      {false, true, false, true},
		"entra:none": {false, false, false, false},
	} {
		got, err := f.svc.ConsoleAccess(t.Context(), throughConsole(f.actor, who))
		if err != nil {
			t.Fatal(err)
		}
		if is := [4]bool{got.Administrator, got.Auditor, got.CatalogueApprover, got.GatewayAdministrator}; is != want {
			t.Errorf("%s: administrator, auditor, approver, gateway administrator = %v, want %v", who, is, want)
		}
	}
}

func TestConsoleRolesAreSetByAnOperatorWithSignedEvidence(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	const a, b = "entra:aaaaaaaa-0000-4000-8000-000000000001", "entra:aaaaaaaa-0000-4000-8000-000000000002"
	op := operator(f.actor.Tenant)

	// Evidence before return: a list whose evidence cannot be signed is not written.
	if err := registry.ConfigureConsoleRole(ctx, f.db.OwnerURL, op, "administrator", []string{a}, identityBrokenSigner{f.key}); !errors.Is(err, evidence.ErrNotRecorded) {
		t.Fatalf("unsigned role change = %v", err)
	}
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM console_roles`); n != 0 {
		t.Fatalf("an unsigned role change wrote %d rows", n)
	}
	for name, bad := range map[string]struct {
		role   string
		people []string
	}{
		"unknown role":    {"owner", []string{a}},
		"duplicate":       {"administrator", []string{a, a}},
		"blank":           {"administrator", []string{"  "}},
		"padded":          {"administrator", []string{" " + a}},
		"erased identity": {"administrator", []string{"erased:" + uuid.NewString()}},
		"an email":        {"administrator", []string{"person-a@example.invalid"}},
		"upper case":      {"administrator", []string{"entra:AAAAAAAA-0000-4000-8000-000000000001"}},
		"not an object":   {"administrator", []string{"entra:someone"}},
		"nil object":      {"administrator", []string{"entra:" + uuid.Nil.String()}},
		"empty dev":       {"administrator", []string{"dev:"}},
	} {
		if err := registry.ConfigureConsoleRole(ctx, f.db.OwnerURL, op, bad.role, bad.people, f.key); !errors.Is(err, registry.ErrInvalid) {
			t.Errorf("%s = %v, want invalid", name, err)
		}
	}
	if err := registry.ConfigureConsoleRole(ctx, f.db.OwnerURL, registry.Actor{Tenant: uuid.New(), Name: "operator:test", RequestID: uuid.NewString()}, "administrator", []string{a}, f.key); !errors.Is(err, store.ErrUnknownTenant) {
		t.Errorf("unknown tenant = %v", err)
	}

	setRole(t, f, f.actor.Tenant, "administrator", a, b)
	setRole(t, f, f.actor.Tenant, "auditor", b)
	// Setting one role replaces that role's list and leaves the other alone.
	setRole(t, f, f.actor.Tenant, "administrator", b)
	got := testdb.Scalar(t, f.db.OwnerURL, `SELECT string_agg(role || '=' || person, ',' ORDER BY role, person) FROM console_roles WHERE tenant_id=$1`, f.actor.Tenant)
	if want := "administrator=" + b + ",auditor=" + b; got != want {
		t.Fatalf("roles = %s, want %s", got, want)
	}
	last := testdb.ScalarIn(t, f.db.AppURL, f.actor.Tenant, `SELECT (before->>'role') || ' ' || (before->'people')::text || ' -> ' || (after->'people')::text || ' by ' || actor
		FROM evidence_events WHERE action = 'console.roles.configured' ORDER BY seq DESC LIMIT 1`)
	if want := fmt.Sprintf(`administrator ["%s", "%s"] -> ["%s"] by operator:test`, a, b, b); last != want {
		t.Fatalf("evidence = %s, want %s", last, want)
	}
	if n := testdb.CountIn(t, f.db.AppURL, f.actor.Tenant, `SELECT count(*) FROM evidence_events WHERE action = 'console.roles.configured'`); n != 3 {
		t.Fatalf("role changes in evidence = %d, want 3", n)
	}
	setRole(t, f, f.actor.Tenant, "auditor")
	if n := testdb.Count(t, f.db.OwnerURL, `SELECT count(*) FROM console_roles WHERE role='auditor'`); n != 0 {
		t.Fatalf("cleared auditors left %d rows", n)
	}
}

// The server reads the lists and never changes them, whatever its code does.
func TestTheServerRoleCannotChangeConsoleRoles(t *testing.T) {
	f := setup(t)
	const a = "entra:aaaaaaaa-0000-4000-8000-000000000001"
	setRole(t, f, f.actor.Tenant, "administrator", a)
	for name, sql := range map[string]string{
		"insert": fmt.Sprintf("INSERT INTO console_roles(tenant_id,role,person) VALUES('%s','administrator','entra:self')", f.actor.Tenant),
		"update": "UPDATE console_roles SET person='entra:self'",
		"delete": "DELETE FROM console_roles",
	} {
		if err := testdb.ExecErr(f.db.AppURL, f.actor.Tenant, sql); sqlState(err) != "42501" {
			t.Errorf("%s as the server role = %v, want insufficient privilege", name, err)
		}
	}
	if err := testdb.ExecErr(f.db.OwnerURL, uuid.Nil, fmt.Sprintf("INSERT INTO console_roles(tenant_id,role,person) VALUES('%s','owner','entra:x')", f.actor.Tenant)); err == nil {
		t.Error("the database accepted a role that does not exist")
	}
}

// The evidence log is the auditor's (D70): through the console, only a console auditor reads it.
func TestConsoleCallersNeedTheAuditorRoleToReadEvidence(t *testing.T) {
	f := setup(t)
	seedAgent(t, f)
	const admin, auditor, nobody = "entra:aaaaaaaa-0000-4000-8000-000000000001", "entra:aaaaaaaa-0000-4000-8000-000000000002", "entra:aaaaaaaa-0000-4000-8000-000000000003"
	setRole(t, f, f.actor.Tenant, "administrator", admin)
	setRole(t, f, f.actor.Tenant, "auditor", auditor)

	events, err := f.svc.ListEvents(t.Context(), throughConsole(f.actor, auditor), 0, 50)
	if err != nil || len(events) == 0 {
		t.Fatalf("auditor reads %d events, %v", len(events), err)
	}
	for _, who := range []string{admin, nobody} {
		if _, err := f.svc.ListEvents(t.Context(), throughConsole(f.actor, who), 0, 50); !errors.Is(err, registry.ErrForbidden) {
			t.Errorf("%s reads the evidence log: %v", who, err)
		}
	}
	// mst and other development callers are unchanged.
	if dev, err := f.svc.ListEvents(t.Context(), f.actor, 0, 50); err != nil || len(dev) != len(events) {
		t.Errorf("development caller reads %d events, %v", len(dev), err)
	}
	setRole(t, f, f.actor.Tenant, "auditor")
	if _, err := f.svc.ListEvents(t.Context(), throughConsole(f.actor, auditor), 0, 50); !errors.Is(err, registry.ErrForbidden) {
		t.Errorf("a former auditor reads the evidence log: %v", err)
	}
}

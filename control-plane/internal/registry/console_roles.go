package registry

// HUMAN REVIEW REQUIRED (AGENTS.md): authorisation. Who may read the console's management
// screens (docs/console-management-plan.md, D70).

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// The console roles (D70). Administrators read agents and templates; auditors read the evidence
// log.
const (
	ConsoleAdministrator = "administrator"
	ConsoleAuditor       = "auditor"
)

// ConfigureConsoleRole replaces the tenant's list of people in one console role. Only an operator
// calls it, with the table owner's credentials: the server role can read the lists and never
// change them. The change and its signed evidence commit together, under the exclusive erasure
// fence, as for gateway administrators.
func ConfigureConsoleRole(ctx context.Context, ownerURL string, actor Actor, role string, people []string, signer evidence.Signer) error {
	if actor.Tenant == uuid.Nil || strings.TrimSpace(actor.Name) == "" || actor.RequestID == "" {
		return fmt.Errorf("tenant, operator and request id are required: %w", ErrInvalid)
	}
	if role != ConsoleAdministrator && role != ConsoleAuditor {
		return fmt.Errorf("the role is %s or %s: %w", ConsoleAdministrator, ConsoleAuditor, ErrInvalid)
	}
	if signer == nil {
		return ErrEvidence
	}
	names := slices.Clone(people)
	slices.Sort(names)
	for i, name := range names {
		if !consoleCallerName(name) || (i > 0 && names[i-1] == name) {
			return fmt.Errorf("people in a role must be distinct, each entra:<object id> or dev:<identity>: %w", ErrInvalid)
		}
	}
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		return fmt.Errorf("connect console administration: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, actor.Tenant).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return store.ErrUnknownTenant
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('muistamo.tenant_id',$1,true)`, actor.Tenant.String()); err != nil {
			return err
		}
		// Exclusive: serialize configuration with other changes and with erasure.
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, true); err != nil {
			return err
		}
		for _, name := range names {
			keys := []string{store.HRFenceKey(actor.Tenant, "identifier", name), store.HRFenceKey(actor.Tenant, "identifier", strings.TrimPrefix(name, "dev:"))}
			at, err := store.HRFenceTime(ctx, tx, keys)
			if err != nil {
				return err
			}
			if at != nil {
				return fmt.Errorf("an erased identity cannot hold a console role: %w", ErrConflict)
			}
		}
		before := []string{}
		// Owner connections bypass row-level security, so every operator query also scopes explicitly.
		rows, err := tx.Query(ctx, `SELECT person FROM console_roles WHERE tenant_id=$1 AND role=$2 ORDER BY person`, actor.Tenant, role)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			before = append(before, name)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM console_roles WHERE tenant_id=$1 AND role=$2`, actor.Tenant, role); err != nil {
			return fmt.Errorf("replace console role: %w", err)
		}
		for _, name := range names {
			if _, err := tx.Exec(ctx, `INSERT INTO console_roles(tenant_id,role,person) VALUES($1,$2,$3)`, actor.Tenant, role, name); err != nil {
				return fmt.Errorf("store console role: %w", err)
			}
		}
		return recordEvidence(ctx, tx, signer, actor, "console.roles.configured", "ConsoleRoleSet", actor.Tenant.String()+"/"+role,
			map[string]any{"role": role, "people": before}, map[string]any{"role": role, "people": names})
	})
}

// consoleCallerName reports whether name is one a console caller can resolve to: entra:<object id>
// in canonical form (entra.ConsoleResolver), or dev:<identity> under development sign-in. Any
// other name would be stored and never match anyone.
func consoleCallerName(name string) bool {
	if oid, ok := strings.CutPrefix(name, "entra:"); ok {
		id, err := uuid.Parse(oid)
		return err == nil && id != uuid.Nil && id.String() == oid
	}
	if who, ok := strings.CutPrefix(name, "dev:"); ok {
		return len(who) >= 1 && strings.TrimSpace(who) == who && !strings.ContainsAny(who, " \t\r\n")
	}
	return false
}

func hasConsoleRole(ctx context.Context, tx pgx.Tx, role, name string) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM console_roles WHERE role = $1 AND person = $2)`, role, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("check console role: %w", err)
	}
	return ok, nil
}

// requireConsoleRole refuses a person signed in through the console who does not hold role. It
// runs in the transaction of the read it guards, so the role is the one held at the moment of the
// call. A caller with no console app (the CLI, Terraform and workflows, which reach the control
// plane only in development or from inside it) is not a console caller and is unchanged; whether
// such callers need a role too is an open decision for CLI sign-in. A person signed in with Entra
// (entra:<object id>) needs the role whatever app they came through, so a future resolver that
// does not name the console app cannot open these reads (security review, 2026-11-21).
func requireConsoleRole(ctx context.Context, tx pgx.Tx, actor Actor, role, what string) error {
	if actor.ClientApp == uuid.Nil && !strings.HasPrefix(actor.Name, "entra:") {
		return nil
	}
	ok, err := hasConsoleRole(ctx, tx, role, actor.Name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("only console %ss can read %s: %w", role, what, ErrForbidden)
	}
	return nil
}

// requireConsoleAdministrator guards the Workforce reads: agents and templates.
func requireConsoleAdministrator(ctx context.Context, tx pgx.Tx, actor Actor, what string) error {
	return requireConsoleRole(ctx, tx, actor, ConsoleAdministrator, what)
}

// ConsoleAccess reports which roles the caller holds, for the console to choose its navigation
// links. It authorises nothing: every route decides for itself at the time of the call.
func (s *Service) ConsoleAccess(ctx context.Context, actor Actor) (muistamov1.ConsoleAccess, error) {
	var out muistamov1.ConsoleAccess
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		if out.Administrator, err = hasConsoleRole(ctx, tx, ConsoleAdministrator, actor.Name); err != nil {
			return err
		}
		if out.Auditor, err = hasConsoleRole(ctx, tx, ConsoleAuditor, actor.Name); err != nil {
			return err
		}
		if out.CatalogueApprover, err = isApprover(ctx, tx, actor.Name); err != nil {
			return err
		}
		out.GatewayAdministrator, err = isGatewayAdmin(ctx, tx, actor.Name)
		return err
	})
	return out, err
}

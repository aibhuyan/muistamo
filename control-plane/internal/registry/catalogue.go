package registry

// HUMAN REVIEW REQUIRED (CLAUDE.md): the catalogue's approval rules.
//
// A template version is assignable to joiners only while it is published to the catalogue
// (FR-102, E1.2). Publication needs approval by risk tier: low none, medium one approver, high
// two distinct approvers. A version without a risk tier counts as high. Approvers come from the
// tenant's catalogue approver list; the requester never approves their own request and nobody
// counts twice. Decisions lock the request row, so concurrent approvals cannot both publish.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// ErrForbidden means the actor may not take this catalogue action.
var ErrForbidden = errors.New("forbidden")

// NeededApprovals is the number of distinct approvers a risk tier requires.
func NeededApprovals(tier string) int {
	switch tier {
	case "low":
		return 0
	case "medium":
		return 1
	default: // high, or no tier at all: fail closed to the strictest rule
		return 2
	}
}

func tierOf(doc muistamov1.AgentTemplate) string {
	if doc.Spec.RiskTier == nil {
		return "high"
	}
	switch tier := string(*doc.Spec.RiskTier); tier {
	case "low", "medium":
		return tier
	default:
		return "high"
	}
}

// RequestPublication asks for a template version to be published. Low risk publishes at once.
func (s *Service) RequestPublication(ctx context.Context, actor Actor, template string, version int) (muistamov1.CatalogueRequest, error) {
	var out muistamov1.CatalogueRequest
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rec, _, err := templateVersion(ctx, tx, template, version)
		if err != nil {
			return err
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM catalogue_requests WHERE template = $1 AND version = $2 AND state = 'pending'`,
			template, version).Scan(&open); err != nil {
			return fmt.Errorf("check open requests: %w", err)
		}
		if open > 0 {
			return fmt.Errorf("template %q version %d already has a pending request: %w", template, version, ErrConflict)
		}
		tier := tierOf(rec.Document)
		id := uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO catalogue_requests (tenant_id, id, template, version, requested_by, risk_tier, needed_approvals, state)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')`,
			actor.Tenant, id, template, version, actor.Name, tier, NeededApprovals(tier)); err != nil {
			return fmt.Errorf("create catalogue request: %w", err)
		}
		if err := recordEvidence(ctx, tx, s.signer, actor, "catalogue.publication.requested", "AgentTemplate", template, nil,
			map[string]any{"request": id, "version": version, "riskTier": tier, "neededApprovals": NeededApprovals(tier)}); err != nil {
			return err
		}
		if NeededApprovals(tier) == 0 {
			if err := publish(ctx, tx, s, actor, id, template, version); err != nil {
				return err
			}
		}
		out, err = catalogueRequest(ctx, tx, id)
		return err
	})
	return out, err
}

// DecideCatalogueRequest records an approver's decision and publishes once enough distinct
// approvers have approved.
func (s *Service) DecideCatalogueRequest(ctx context.Context, actor Actor, id uuid.UUID, decision, reason string) (muistamov1.CatalogueRequest, error) {
	var out muistamov1.CatalogueRequest
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var template, requestedBy, state string
		var version, needed int
		err := tx.QueryRow(ctx, `
			SELECT template, version, requested_by, state, needed_approvals FROM catalogue_requests
			WHERE id = $1 FOR UPDATE`, id).Scan(&template, &version, &requestedBy, &state, &needed)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("catalogue request %s: %w", id, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("lock catalogue request: %w", err)
		}
		approver, err := isApprover(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		switch {
		case !approver:
			return fmt.Errorf("only catalogue approvers can decide requests: %w", ErrForbidden)
		case actor.Name == requestedBy:
			return fmt.Errorf("the requester cannot decide their own request: %w", ErrForbidden)
		case state != "pending":
			return fmt.Errorf("request is %s, not pending: %w", state, ErrConflict)
		}
		var already bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM catalogue_approvals WHERE request_id = $1 AND approver = $2)`,
			id, actor.Name).Scan(&already); err != nil {
			return fmt.Errorf("check previous decision: %w", err)
		}
		if already {
			return fmt.Errorf("%s has already decided this request: %w", actor.Name, ErrConflict)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO catalogue_approvals (tenant_id, request_id, approver, decision, reason) VALUES ($1, $2, $3, $4, $5)`,
			actor.Tenant, id, actor.Name, decision, reason); err != nil {
			return fmt.Errorf("record decision: %w", err)
		}
		if err := recordEvidence(ctx, tx, s.signer, actor, "catalogue.request."+decision+"d", "AgentTemplate", template, nil,
			map[string]any{"request": id, "version": version, "reason": reason}); err != nil {
			return err
		}
		if decision == "reject" {
			if _, err := tx.Exec(ctx, `UPDATE catalogue_requests SET state = 'rejected', closed_at = now() WHERE id = $1`, id); err != nil {
				return fmt.Errorf("close request: %w", err)
			}
		} else {
			var approvals int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM catalogue_approvals WHERE request_id = $1 AND decision = 'approve'`, id).Scan(&approvals); err != nil {
				return fmt.Errorf("count approvals: %w", err)
			}
			if approvals >= needed {
				if err := publish(ctx, tx, s, actor, id, template, version); err != nil {
					return err
				}
			}
		}
		out, err = catalogueRequest(ctx, tx, id)
		return err
	})
	return out, err
}

// Withdraw removes a template from the catalogue. Existing instances are untouched.
func (s *Service) Withdraw(ctx context.Context, actor Actor, template string) error {
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		approver, err := isApprover(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		if !approver {
			return fmt.Errorf("only catalogue approvers can withdraw templates: %w", ErrForbidden)
		}
		var requestID uuid.UUID
		var version int
		err = tx.QueryRow(ctx, `DELETE FROM catalogue_published WHERE template = $1 RETURNING request_id, version`, template).Scan(&requestID, &version)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("template %q is not in the catalogue: %w", template, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("withdraw: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE catalogue_requests SET state = 'withdrawn', closed_at = now() WHERE id = $1`, requestID); err != nil {
			return fmt.Errorf("close request: %w", err)
		}
		following, err := followClones(ctx, tx, template)
		if err != nil {
			return err
		}
		// Follow clones resolve to nothing now, so joiners stop getting them too.
		return recordEvidence(ctx, tx, s.signer, actor, "catalogue.withdrawn", "AgentTemplate", template,
			map[string]any{"version": version}, map[string]any{"unassignableClones": following})
	})
}

// ListCatalogue returns the published template versions.
func (s *Service) ListCatalogue(ctx context.Context, actor Actor) ([]muistamov1.CatalogueEntry, error) {
	entries := []muistamov1.CatalogueEntry{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT template, version, request_id, published_at FROM catalogue_published ORDER BY template`)
		if err != nil {
			return fmt.Errorf("list catalogue: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var e muistamov1.CatalogueEntry
			var request uuid.UUID
			if err := rows.Scan(&e.Template, &e.Version, &request, &e.PublishedAt); err != nil {
				return fmt.Errorf("scan catalogue: %w", err)
			}
			e.RequestId = request
			entries = append(entries, e)
		}
		return rows.Err()
	})
	return entries, err
}

// ListCatalogueRequests returns requests, newest first, optionally in one state.
func (s *Service) ListCatalogueRequests(ctx context.Context, actor Actor, state string) ([]muistamov1.CatalogueRequest, error) {
	out := []muistamov1.CatalogueRequest{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM catalogue_requests WHERE $1 = '' OR state = $1 ORDER BY created_at DESC`, state)
		if err != nil {
			return fmt.Errorf("list catalogue requests: %w", err)
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return fmt.Errorf("scan request: %w", err)
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			r, err := catalogueRequest(ctx, tx, id)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

func publish(ctx context.Context, tx pgx.Tx, s *Service, actor Actor, id uuid.UUID, template string, version int) error {
	var previous uuid.UUID
	var previousVersion int
	err := tx.QueryRow(ctx, `SELECT request_id, version FROM catalogue_published WHERE template = $1 FOR UPDATE`, template).Scan(&previous, &previousVersion)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx, `INSERT INTO catalogue_published (tenant_id, template, version, request_id) VALUES ($1, $2, $3, $4)`,
			actor.Tenant, template, version, id); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
	case err != nil:
		return fmt.Errorf("read catalogue entry: %w", err)
	default:
		if _, err := tx.Exec(ctx, `UPDATE catalogue_published SET version = $2, request_id = $3, published_at = now() WHERE template = $1`,
			template, version, id); err != nil {
			return fmt.Errorf("publish: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE catalogue_requests SET state = 'superseded', closed_at = now() WHERE id = $1`, previous); err != nil {
			return fmt.Errorf("supersede previous request: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE catalogue_requests SET state = 'published', closed_at = now() WHERE id = $1`, id); err != nil {
		return fmt.Errorf("close request: %w", err)
	}
	var before any
	if previousVersion != 0 {
		before = map[string]any{"version": previousVersion}
	}
	following, err := followClones(ctx, tx, template)
	if err != nil {
		return err
	}
	return recordEvidence(ctx, tx, s.signer, actor, "catalogue.published", "AgentTemplate", template, before,
		map[string]any{"version": version, "request": id, "followClones": following})
}

// followClones names the clones that follow template's published version: a publication or a
// withdrawal moves them.
func followClones(ctx context.Context, tx pgx.Tx, template string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT name FROM agent_clones WHERE template = $1 AND sync = 'follow' ORDER BY name`, template)
	if err != nil {
		return nil, fmt.Errorf("list follow clones of %q: %w", template, err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func isApprover(ctx context.Context, tx pgx.Tx, name string) (bool, error) {
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM catalogue_approvers WHERE approver = $1)`, name).Scan(&ok); err != nil {
		return false, fmt.Errorf("check approver: %w", err)
	}
	return ok, nil
}

func catalogueRequest(ctx context.Context, tx pgx.Tx, id uuid.UUID) (muistamov1.CatalogueRequest, error) {
	var r muistamov1.CatalogueRequest
	var tier, state string
	var closed *time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, template, version, requested_by, risk_tier, needed_approvals, state, created_at, closed_at
		FROM catalogue_requests WHERE id = $1`, id).Scan(
		&r.Id, &r.Template, &r.Version, &r.RequestedBy, &tier, &r.NeededApprovals, &state, &r.CreatedAt, &closed)
	if err != nil {
		return r, fmt.Errorf("read catalogue request: %w", err)
	}
	r.RiskTier = muistamov1.CatalogueRequestRiskTier(tier)
	r.State = muistamov1.CatalogueRequestState(state)
	r.ClosedAt = closed
	rows, err := tx.Query(ctx, `SELECT approver, decision, reason, decided_at FROM catalogue_approvals WHERE request_id = $1 ORDER BY decided_at`, id)
	if err != nil {
		return r, fmt.Errorf("read approvals: %w", err)
	}
	defer rows.Close()
	r.Approvals = []muistamov1.CatalogueApproval{}
	for rows.Next() {
		var a muistamov1.CatalogueApproval
		var decision string
		if err := rows.Scan(&a.Approver, &decision, &a.Reason, &a.DecidedAt); err != nil {
			return r, fmt.Errorf("scan approval: %w", err)
		}
		a.Decision = muistamov1.CatalogueApprovalDecision(decision)
		r.Approvals = append(r.Approvals, a)
	}
	return r, rows.Err()
}

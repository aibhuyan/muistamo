package registry

// HUMAN REVIEW REQUIRED: who a live leaver's personal-layer review names (docs/live-review-plan.md).
// The knowledge service knows people only as entra:<object id>, so the review names the leaver by
// the Entra user their joiner linked, and the decider by the manager's own standing link. Nothing
// here is returned to a workflow: object ids stay in the activity that sends the signed call.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// LiveReviewParties is what a live leaver's review is opened with.
type LiveReviewParties struct {
	Person     string // the HR person id
	Generation int64  // the leaver's HR generation, which orders the review in the knowledge service
	// Superseded: a later HR event for the person exists (they were rehired), so no review opens.
	Superseded bool
	// User is the leaver's Entra user, linked by the joiner before this leaver; nil when the
	// person was never linked, or their link is not from an earlier joiner.
	User *uuid.UUID
	// Manager is the manager's Entra user: the one HR person with the leaver's managerEmail whose
	// own link still stands (their latest HR event is the joiner that linked them). Nil when there
	// is none, or more than one, or it is the leaver: then the privacy officers decide.
	Manager *uuid.UUID
}

// LiveReviewParties reads, under the person's lock, who the live leaver receipt's review names.
func (s *Service) LiveReviewParties(ctx context.Context, actor Actor, receipt uuid.UUID) (LiveReviewParties, error) {
	var out LiveReviewParties
	_, _, _, err := s.withEntraReceipt(ctx, actor, receipt, false, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, route muistamov1.HRIdentityRoute, generation int64) error {
		if event.Type != "leaver" {
			return fmt.Errorf("only a leaver opens a personal-layer review: %w", ErrConflict)
		}
		out.Person, out.Generation = event.Person.Id, generation
		latest, latestGeneration, _, err := latestIdentityHR(ctx, tx, event.Person.Id)
		if err != nil {
			return err
		}
		if latest != event.Id || latestGeneration != generation {
			out.Superseded = true
			return nil
		}
		binding, err := identityBindingRow(ctx, tx, *route.BindingVersion)
		if err != nil {
			return err
		}
		// The leaver's link, written by a joiner of theirs before this leaver.
		var user uuid.UUID
		err = tx.QueryRow(ctx, `SELECT l.entra_user_object_id FROM person_entra_links l
			JOIN hr_events j ON j.tenant_id = l.tenant_id AND j.receipt_id = l.receipt_id
			WHERE l.person_id = $1 AND l.status = 'matched' AND l.entra_tenant_id = $2
			  AND j.person_id = l.person_id AND j.type = 'joiner' AND j.generation < $3`,
			event.Person.Id, binding.EntraTenantId, generation).Scan(&user)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("read the leaver's Entra user link: %w", err)
		default:
			out.User = &user
		}
		if event.Person.ManagerEmail == nil || strings.TrimSpace(*event.Person.ManagerEmail) == "" {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT l.entra_user_object_id FROM person_entra_links l
			JOIN LATERAL (SELECT receipt_id, type, payload FROM hr_events h WHERE h.person_id = l.person_id AND h.decision IN ('accepted','legacy')
				ORDER BY generation DESC, occurred_at DESC, (type='leaver') DESC, event_id DESC LIMIT 1) latest ON true
			WHERE l.status = 'matched' AND l.entra_tenant_id = $1 AND l.person_id <> $2
			  AND latest.type = 'joiner' AND latest.receipt_id = l.receipt_id
			  AND lower(latest.payload -> 'person' ->> 'email') = lower($3)
			LIMIT 2`, binding.EntraTenantId, event.Person.Id, strings.TrimSpace(*event.Person.ManagerEmail))
		if err != nil {
			return fmt.Errorf("find the leaver's manager: %w", err)
		}
		managers, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return fmt.Errorf("find the leaver's manager: %w", err)
		}
		if len(managers) == 1 && (out.User == nil || managers[0] != *out.User) {
			out.Manager = &managers[0]
		}
		return nil
	})
	return out, err
}

// FenceUser returns the Entra user a live joiner's person was linked as before this joiner, which
// is the user any earlier live review of theirs was opened under, with the joiner's generation.
// Nil when the person has no matched link: no live review of theirs can have been opened.
func (s *Service) FenceUser(ctx context.Context, actor Actor, receipt uuid.UUID) (string, *uuid.UUID, int64, error) {
	var person string
	var user *uuid.UUID
	_, _, generation, err := s.withEntraReceipt(ctx, actor, receipt, false, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, _ muistamov1.HRIdentityRoute, _ int64) error {
		if event.Type != "joiner" {
			return fmt.Errorf("only a joiner fences earlier reviews: %w", ErrConflict)
		}
		person = event.Person.Id
		link, err := entraUserLinkRow(ctx, tx, person, false)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if link.Status == "matched" && link.EntraUserObjectId != nil {
			user = link.EntraUserObjectId
		}
		return nil
	})
	return person, user, generation, err
}

package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// The people screens (docs/console-management-plan.md, slice 3; D70) name a person by HR id only.
// These reads select named columns and never the HR payload, which holds the person's email, job
// code and manager; and never an agent's binding, which names the person by email.

const receiptColumns = `SELECT event_id, type, person_id, occurred_at, received_at, generation, decision,
	dispatch_state, setup_completed_at IS NOT NULL, identity_mode FROM hr_events`

// personReceiptLimit is how many of one person's HR events their page lists.
const personReceiptLimit = 100

// receiptCursor is a position in the HR feed: after the event received at R with id E.
type receiptCursor struct {
	R time.Time `json:"r"`
	E string    `json:"e"`
}

func scanReceipt(row rowScanner) (muistamov1.HrReceipt, error) {
	var r muistamov1.HrReceipt
	var typ, decision, dispatch, mode string
	err := row.Scan(&r.EventId, &typ, &r.PersonId, &r.OccurredAt, &r.ReceivedAt, &r.Generation, &decision,
		&dispatch, &r.SetupCompleted, &mode)
	if err != nil {
		return r, fmt.Errorf("read HR event: %w", err)
	}
	r.Type = muistamov1.HrReceiptType(typ)
	r.Decision = muistamov1.HrReceiptDecision(decision)
	r.DispatchState = muistamov1.HrReceiptDispatchState(dispatch)
	r.IdentityMode = muistamov1.HrReceiptIdentityMode(mode)
	return r, nil
}

// ListHrReceipts lists the tenant's HR events, the most recently received first. A console
// caller must be a console administrator.
func (s *Service) ListHrReceipts(ctx context.Context, actor Actor, cursor string, limit int) (muistamov1.HrReceiptPage, error) {
	page := muistamov1.HrReceiptPage{Items: []muistamov1.HrReceipt{}}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := requireConsoleAdministrator(ctx, tx, actor, "people and HR events"); err != nil {
			return err
		}
		// The cursor is read after the role check: a caller without the role learns nothing,
		// not even that their cursor is malformed.
		var after *receiptCursor
		if cursor != "" {
			raw, err := base64.RawURLEncoding.DecodeString(cursor)
			var c receiptCursor
			if err != nil || json.Unmarshal(raw, &c) != nil || c.E == "" || c.R.IsZero() {
				return fmt.Errorf("cursor: %w", ErrInvalid)
			}
			after = &c
		}
		var rows pgx.Rows
		var err error
		if after == nil {
			rows, err = tx.Query(ctx, receiptColumns+` ORDER BY received_at DESC, event_id DESC LIMIT $1`, limit+1)
		} else {
			rows, err = tx.Query(ctx, receiptColumns+` WHERE (received_at, event_id) < ($1, $2)
				ORDER BY received_at DESC, event_id DESC LIMIT $3`, after.R, after.E, limit+1)
		}
		if err != nil {
			return fmt.Errorf("list HR events: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanReceipt(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, r)
		}
		return rows.Err()
	})
	if err != nil {
		return muistamov1.HrReceiptPage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		last := page.Items[limit-1]
		raw, err := json.Marshal(receiptCursor{R: last.ReceivedAt, E: last.EventId})
		if err != nil {
			return muistamov1.HrReceiptPage{}, fmt.Errorf("encode cursor: %w", err)
		}
		next := base64.RawURLEncoding.EncodeToString(raw)
		page.NextCursor = &next
	}
	return page, nil
}

// GetPerson returns one person's HR events and the agents labelled with their HR id (a label only
// the HR joiner sets; agents labelled by hand before that rule exist in development databases
// only, docs/hr-person-label-plan.md). A console caller must be a console administrator. An id
// with neither is ErrNotFound.
func (s *Service) GetPerson(ctx context.Context, actor Actor, personID string) (muistamov1.PersonSummary, error) {
	p := muistamov1.PersonSummary{PersonId: personID, Receipts: []muistamov1.HrReceipt{}, Agents: []muistamov1.PersonAgent{}}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := requireConsoleAdministrator(ctx, tx, actor, "people and HR events"); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, receiptColumns+` WHERE person_id = $1 ORDER BY received_at DESC, event_id DESC LIMIT $2`,
			personID, personReceiptLimit+1)
		if err != nil {
			return fmt.Errorf("person's HR events: %w", err)
		}
		for rows.Next() {
			r, err := scanReceipt(rows)
			if err != nil {
				rows.Close()
				return err
			}
			p.Receipts = append(p.Receipts, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("person's HR events: %w", err)
		}
		if len(p.Receipts) > personReceiptLimit {
			p.Receipts = p.Receipts[:personReceiptLimit]
			p.ReceiptsTruncated = true
		}
		// The fields shown, and nothing else: never the binding, which holds the person's email.
		rows, err = tx.Query(ctx, `SELECT name, document->'spec'->'templateRef'->>'name',
			document->'spec'->'templateRef'->>'version', document->'spec'->>'cloneRef',
			document->'spec'->>'state', updated_at
			FROM agent_instances WHERE document->'metadata'->'labels'->>$1 = $2 ORDER BY name`, PersonLabel, personID)
		if err != nil {
			return fmt.Errorf("person's agents: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a muistamov1.PersonAgent
			var state string
			if err := rows.Scan(&a.Name, &a.TemplateName, &a.TemplateVersion, &a.CloneName, &state, &a.UpdatedAt); err != nil {
				return fmt.Errorf("read person's agent: %w", err)
			}
			a.State = muistamov1.InstanceState(state)
			p.Agents = append(p.Agents, a)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("person's agents: %w", err)
		}
		if len(p.Receipts) == 0 && len(p.Agents) == 0 {
			return fmt.Errorf("person %q: %w", personID, ErrNotFound)
		}
		return nil
	})
	if err != nil {
		return muistamov1.PersonSummary{}, err
	}
	return p, nil
}

package registry

// HUMAN REVIEW REQUIRED: which Entra user an HR person is (docs/obo-retrieval-plan.md, PR A).
// A request made with an Entra token is matched to a person only through a matched link, so a
// link is written only by the person's current accepted live joiner, under the same HR privacy
// fence and person lock as the rest of the live lifecycle, with signed evidence in the same
// transaction. Evidence names the user only by a digest: the evidence is kept after erasure, the
// link row is not.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// IdentityBinding returns a registered binding version's stored status (its config digest).
func (s *Service) IdentityBinding(ctx context.Context, actor Actor, version uuid.UUID) (muistamov1.IdentityBindingStatus, error) {
	var out muistamov1.IdentityBindingStatus
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		out, err = identityBindingRow(ctx, tx, version)
		return err
	})
	return out, err
}

// RecordEntraUserLink records the outcome of the person's Entra user lookup for the joiner
// receipt: matched (objectID set), unmatched or ambiguous. A matched user that is already another
// person's makes both people a conflict: the other person's link is provably stale (the user's
// employeeId is now this person's) or the directory is wrong, and either way neither token may
// resolve to a person until a later joiner finds them unambiguously.
func (s *Service) RecordEntraUserLink(ctx context.Context, actor Actor, receipt uuid.UUID, status string, objectID *uuid.UUID) (muistamov1.EntraUserLink, error) {
	if (status == "matched") != (objectID != nil) || (status != "matched" && status != "unmatched" && status != "ambiguous") {
		return muistamov1.EntraUserLink{}, fmt.Errorf("invalid Entra user link outcome: %w", ErrInvalid)
	}
	return s.recordEntraUserOutcome(ctx, actor, receipt, status, objectID, "")
}

// RecordEntraUserLookupFailure records that the person's Entra user could not be looked up for
// this joiner receipt (a provider refusal, or a lookup that kept failing). Any earlier link is
// replaced: the person stays unlinked, and knowledge retrieval refuses until a later joiner
// links them.
func (s *Service) RecordEntraUserLookupFailure(ctx context.Context, actor Actor, receipt uuid.UUID, code string) error {
	_, err := s.recordEntraUserOutcome(ctx, actor, receipt, "unavailable", nil, code)
	return err
}

// recordEntraUserOutcome writes one outcome per joiner receipt. The first outcome recorded for a
// receipt stands: a retried activity, or the failure step after a refusal, changes nothing.
func (s *Service) recordEntraUserOutcome(ctx context.Context, actor Actor, receipt uuid.UUID, status string, objectID *uuid.UUID, code string) (muistamov1.EntraUserLink, error) {
	var out muistamov1.EntraUserLink
	if s.signer == nil {
		return out, ErrEvidence
	}
	_, _, _, err := s.withEntraReceipt(ctx, actor, receipt, true, func(ctx context.Context, tx pgx.Tx, event muistamov1.HREvent, route muistamov1.HRIdentityRoute, _ int64) error {
		if event.Type != "joiner" {
			return fmt.Errorf("only a joiner links an Entra user: %w", ErrConflict)
		}
		binding, err := identityBindingRow(ctx, tx, *route.BindingVersion)
		if err != nil {
			return err
		}
		person := event.Person.Id
		prior, err := entraUserLinkRow(ctx, tx, person, true)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		existed := err == nil
		if existed && prior.ReceiptId == receipt {
			out = prior
			return nil
		}
		var user string // the digest of the user this outcome concerns, if any
		// demoteHolder makes the person in this tenant who holds the matched user a conflict, and
		// reports whether there was one.
		demoteHolder := func() (bool, error) {
			var other string
			var otherReceipt uuid.UUID
			err := tx.QueryRow(ctx, `SELECT person_id,receipt_id FROM person_entra_links WHERE entra_tenant_id=$1 AND entra_user_object_id=$2 AND person_id<>$3 FOR UPDATE`,
				binding.EntraTenantId, *objectID, person).Scan(&other, &otherReceipt)
			if errors.Is(err, pgx.ErrNoRows) {
				return false, nil
			}
			if err != nil {
				return false, fmt.Errorf("check Entra user link conflict: %w", err)
			}
			if _, err := tx.Exec(ctx, `UPDATE person_entra_links SET status='conflict',entra_user_object_id=NULL,matched_at=now() WHERE person_id=$1`, other); err != nil {
				return false, fmt.Errorf("record Entra user link conflict: %w", err)
			}
			return true, recordEvidence(ctx, tx, s.signer, actor, "identity.user.conflict", "HRPerson", other,
				map[string]any{"status": "matched", "receiptId": otherReceipt, "user": user},
				map[string]any{"status": "conflict", "receiptId": otherReceipt, "user": user, "foundByReceiptId": receipt})
		}
		if objectID != nil {
			user = entraUserDigest(actor.Tenant, binding.EntraTenantId, *objectID)
			held, err := demoteHolder()
			if err != nil {
				return err
			}
			if held {
				status, objectID = "conflict", nil
			}
		}
		write := func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO person_entra_links (tenant_id,person_id,status,binding_version,entra_tenant_id,entra_user_object_id,receipt_id,matched_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,now())
				ON CONFLICT (tenant_id,person_id) DO UPDATE SET status=EXCLUDED.status,binding_version=EXCLUDED.binding_version,
				  entra_tenant_id=EXCLUDED.entra_tenant_id,entra_user_object_id=EXCLUDED.entra_user_object_id,
				  receipt_id=EXCLUDED.receipt_id,matched_at=EXCLUDED.matched_at`,
				actor.Tenant, person, status, *route.BindingVersion, binding.EntraTenantId, objectID, receipt)
			return err
		}
		// The user can also be held by a concurrent joiner that committed after the check above, or
		// where this tenant cannot see it (another tenant bound to the same directory): the unique
		// index refuses, and that is a conflict. A holder in this tenant is visible to a new
		// statement now, so it is demoted as above; another tenant's link cannot be reached here.
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return fmt.Errorf("record Entra user link: %w", err)
		}
		if err := write(savepoint); err != nil {
			_ = savepoint.Rollback(ctx)
			if objectID == nil || !isUniqueViolation(err) {
				return fmt.Errorf("record Entra user link: %w", err)
			}
			if _, err := demoteHolder(); err != nil {
				return err
			}
			status, objectID = "conflict", nil
			if err := write(tx); err != nil {
				return fmt.Errorf("record Entra user link: %w", err)
			}
		} else if err := savepoint.Commit(ctx); err != nil {
			return fmt.Errorf("record Entra user link: %w", err)
		}
		if out, err = entraUserLinkRow(ctx, tx, person, false); err != nil {
			return err
		}
		action := map[string]string{"matched": "identity.user.linked", "conflict": "identity.user.conflict", "unavailable": "identity.user.lookup-failed"}[status]
		if action == "" {
			action = "identity.user.unmatched"
		}
		after := map[string]any{"status": status, "receiptId": receipt, "entraTenantId": binding.EntraTenantId, "bindingVersion": *route.BindingVersion}
		if user != "" {
			after["user"] = user
		}
		if code != "" {
			after["code"] = code
		}
		var before any
		if existed {
			was := map[string]any{"status": prior.Status, "receiptId": prior.ReceiptId}
			if prior.EntraUserObjectId != nil {
				was["user"] = entraUserDigest(actor.Tenant, prior.EntraTenantId, *prior.EntraUserObjectId)
			}
			before = was
		}
		return recordEvidence(ctx, tx, s.signer, actor, action, "HRPerson", person, before, after)
	})
	return out, err
}

// entraUserDigest names an Entra user in retained evidence without the object id: an auditor
// holding the id can confirm which person a token spoke for, and no one can recover the id.
func entraUserDigest(tenant, entraTenant, objectID uuid.UUID) string {
	sum := sha256.Sum256([]byte("muistamo/v1 entra-user\n" + tenant.String() + "\n" + entraTenant.String() + "\n" + objectID.String()))
	return hex.EncodeToString(sum[:])
}

// GetEntraUserLink returns a person's link. Privacy officers only: it maps an HR id to a user,
// so each read is evidenced, as an access export is.
func (s *Service) GetEntraUserLink(ctx context.Context, actor Actor, person string) (muistamov1.EntraUserLink, error) {
	var out muistamov1.EntraUserLink
	if s.signer == nil {
		return out, ErrEvidence
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		officer, err := isPrivacyOfficer(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		if !officer {
			return fmt.Errorf("only privacy officers can read Entra user links: %w", ErrForbidden)
		}
		if out, err = entraUserLinkRow(ctx, tx, person, false); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "privacy.entra-link.read", "HRPerson", person, nil, map[string]any{"status": out.Status})
	})
	return out, err
}

func entraUserLinkRow(ctx context.Context, tx pgx.Tx, person string, lock bool) (muistamov1.EntraUserLink, error) {
	var out muistamov1.EntraUserLink
	var status string
	var at time.Time
	q := `SELECT person_id,status,entra_tenant_id,entra_user_object_id,receipt_id,matched_at FROM person_entra_links WHERE person_id=$1`
	if lock {
		q += ` FOR UPDATE`
	}
	err := tx.QueryRow(ctx, q, person).Scan(&out.PersonId, &status, &out.EntraTenantId, &out.EntraUserObjectId, &out.ReceiptId, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, fmt.Errorf("no Entra user link for this person: %w", ErrNotFound)
	}
	if err != nil {
		return out, fmt.Errorf("read Entra user link: %w", err)
	}
	out.Status, out.MatchedAt = muistamov1.EntraUserLinkStatus(status), at.UTC()
	return out, nil
}

// entraObjectIDs returns the Entra user object ids named by entra:<object id> identities.
func entraObjectIDs(values []string) []string {
	var ids []string
	for _, v := range values {
		if id, ok := strings.CutPrefix(v, "entra:"); ok {
			if parsed, err := uuid.Parse(id); err == nil && parsed.String() == id {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// entraLinkRowsByIdentity finds the links of the users named by entra:<object id> identities;
// the row stores the bare object id, so a whole-value search would miss it.
func entraLinkRowsByIdentity(ctx context.Context, tx pgx.Tx, values []string) ([]map[string]any, error) {
	ids := entraObjectIDs(values)
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT to_jsonb(t) FROM person_entra_links t WHERE t.tenant_id = current_setting('muistamo.tenant_id', true)::uuid AND entra_user_object_id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, fmt.Errorf("search Entra user links by identity: %w", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var row map[string]any
		if err := rows.Scan(&row); err != nil {
			return nil, fmt.Errorf("scan Entra user link: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// EntraUserMatch is the outcome of one Entra user lookup, as RecordEntraUserLink takes it.
type EntraUserMatch struct {
	Status   string
	ObjectID *uuid.UUID
}

// ProviderRefusal is a definite refusal by the identity provider (for example a missing
// permission): retrying the same request cannot succeed.
type ProviderRefusal struct{ Code string }

func (r *ProviderRefusal) Error() string { return "identity provider refused the request: " + r.Code }

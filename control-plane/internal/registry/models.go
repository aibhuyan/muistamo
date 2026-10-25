package registry

// The model catalogue, aliases and rollouts (FR-601, FR-602, E5.1, E5.4).
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): these rules decide which models agents may run on.
//
// A catalogue model is usable only once a privacy officer approves it, never the person who
// last changed it; any change to it resets approval (fail closed). An alias targets one approved
// model and changes target only through a rollout. Until the gateway exists (D28) no evaluation
// can run (FR-603), so a rollout requires an explicit acknowledgement and records evaluation as
// not run. A template version can be published only while its alias is compliant (exists and
// targets an approved model), and joiners get only templates whose alias is compliant now.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

const evaluationNotRun = "the evaluation gate (FR-603) needs the gateway, which is not decided (D28); this switch was made without an evaluation report"

const modelColumns = `SELECT revision, created_at, updated_at, updated_by, digest, document,
	approval_status, decided_by, decision_reason, decided_at FROM model_catalogue`

func scanModel(row rowScanner, name string) (muistamov1.ModelCatalogueItemRecord, string, error) {
	var rec muistamov1.ModelCatalogueItemRecord
	var digest, status string
	var body []byte
	err := row.Scan(&rec.Revision, &rec.CreatedAt, &rec.UpdatedAt, &rec.UpdatedBy, &digest, &body,
		&status, &rec.Approval.DecidedBy, &rec.Approval.Reason, &rec.Approval.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, "", fmt.Errorf("model %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return rec, "", fmt.Errorf("read model %q: %w", name, err)
	}
	rec.Approval.Status = muistamov1.ModelApprovalStatus(status)
	return rec, digest, json.Unmarshal(body, &rec.Document)
}

// ApplyModel adds or changes a catalogue model. A change resets its approval to pending.
func (s *Service) ApplyModel(ctx context.Context, actor Actor, doc muistamov1.ModelCatalogueItem) (muistamov1.ModelCatalogueItemRecord, bool, error) {
	if doc.Kind != muistamov1.ModelCatalogueItemKindModelCatalogueItem {
		return muistamov1.ModelCatalogueItemRecord{}, false, fmt.Errorf("kind %q is not ModelCatalogueItem: %w", doc.Kind, ErrInvalid)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return muistamov1.ModelCatalogueItemRecord{}, false, err
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	name := doc.Metadata.Name

	var rec muistamov1.ModelCatalogueItemRecord
	var created bool
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		current, currentDigest, err := scanModel(tx.QueryRow(ctx, modelColumns+` WHERE name = $1 FOR UPDATE`, name), name)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if exists && currentDigest == digest {
			rec = current
			return nil
		}
		if exists {
			_, err = tx.Exec(ctx, `UPDATE model_catalogue SET revision = revision + 1, digest = $2, document = $3,
				approval_status = 'pending', decided_by = NULL, decision_reason = NULL, decided_at = NULL,
				updated_at = now(), updated_by = $4 WHERE name = $1`, name, digest, body, actor.Name)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO model_catalogue (tenant_id, name, revision, digest, document, approval_status, updated_by)
				VALUES ($1, $2, 1, $3, $4, 'pending', $5)`, actor.Tenant, name, digest, body, actor.Name)
			created = true
		}
		if err != nil {
			return fmt.Errorf("store model %q: %w", name, err)
		}
		rec, _, err = scanModel(tx.QueryRow(ctx, modelColumns+` WHERE name = $1`, name), name)
		if err != nil {
			return err
		}
		var before any
		if exists {
			before = map[string]any{"revision": current.Revision, "document": current.Document, "approval": current.Approval.Status}
		}
		return recordEvidence(ctx, tx, s.signer, actor, "model.applied", "ModelCatalogueItem", name, before,
			map[string]any{"revision": rec.Revision, "document": doc, "approval": rec.Approval.Status})
	})
	return rec, created, err
}

// GetModel returns a catalogue model and its approval.
func (s *Service) GetModel(ctx context.Context, actor Actor, name string) (muistamov1.ModelCatalogueItemRecord, error) {
	var rec muistamov1.ModelCatalogueItemRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		rec, _, err = scanModel(tx.QueryRow(ctx, modelColumns+` WHERE name = $1`, name), name)
		return err
	})
	return rec, err
}

// ListModels returns the catalogue, by name.
func (s *Service) ListModels(ctx context.Context, actor Actor) ([]muistamov1.ModelCatalogueItemRecord, error) {
	out := []muistamov1.ModelCatalogueItemRecord{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, modelColumns+` ORDER BY name`)
		if err != nil {
			return fmt.Errorf("list models: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			rec, _, err := scanModel(rows, "")
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

// DecideModel records a privacy officer's approval, rejection or revocation of a model.
func (s *Service) DecideModel(ctx context.Context, actor Actor, name string, decision muistamov1.ModelApprovalDecisionDecision, reason string) (muistamov1.ModelCatalogueItemRecord, error) {
	var rec muistamov1.ModelCatalogueItemRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		officer, err := isPrivacyOfficer(ctx, tx, actor.Name)
		if err != nil {
			return err
		}
		if !officer {
			return fmt.Errorf("only privacy officers can approve, reject or revoke models: %w", ErrForbidden)
		}
		current, _, err := scanModel(tx.QueryRow(ctx, modelColumns+` WHERE name = $1 FOR UPDATE`, name), name)
		if err != nil {
			return err
		}
		if current.UpdatedBy == actor.Name {
			return fmt.Errorf("you last changed this model, so another privacy officer must decide it: %w", ErrForbidden)
		}
		status := current.Approval.Status
		var next muistamov1.ModelApprovalStatus
		switch {
		case decision == muistamov1.ModelApprovalDecisionDecisionApprove && status == muistamov1.ModelApprovalStatusPending:
			next = muistamov1.ModelApprovalStatusApproved
		case decision == muistamov1.ModelApprovalDecisionDecisionReject && status == muistamov1.ModelApprovalStatusPending:
			next = muistamov1.ModelApprovalStatusRejected
		case decision == muistamov1.ModelApprovalDecisionDecisionRevoke && status == muistamov1.ModelApprovalStatusApproved:
			next = muistamov1.ModelApprovalStatusRevoked
		default:
			return fmt.Errorf("cannot %s a model that is %s: %w", decision, status, ErrConflict)
		}
		if _, err := tx.Exec(ctx, `UPDATE model_catalogue SET approval_status = $2, decided_by = $3, decision_reason = $4,
			decided_at = now() WHERE name = $1`, name, string(next), actor.Name, reason); err != nil {
			return fmt.Errorf("decide model %q: %w", name, err)
		}
		after := map[string]any{"approval": next, "reason": reason, "revision": current.Revision}
		if next == muistamov1.ModelApprovalStatusRevoked {
			aliases, templates, err := modelUsers(ctx, tx, name)
			if err != nil {
				return err
			}
			// What revocation stops: these aliases are no longer compliant, so these published
			// templates stop being assigned to joiners and cannot be republished.
			after["nonCompliantAliases"], after["affectedPublishedTemplates"] = aliases, templates
		}
		if err := recordEvidence(ctx, tx, s.signer, actor, "model.approval.decided", "ModelCatalogueItem", name,
			map[string]any{"approval": status}, after); err != nil {
			return err
		}
		rec, _, err = scanModel(tx.QueryRow(ctx, modelColumns+` WHERE name = $1`, name), name)
		return err
	})
	return rec, err
}

// modelUsers names the aliases that target a model and the published templates that use them.
func modelUsers(ctx context.Context, tx pgx.Tx, model string) ([]string, []string, error) {
	aliases, templates := []string{}, []string{}
	rows, err := tx.Query(ctx, `SELECT a.name, coalesce(array_agg(p.template ORDER BY p.template) FILTER (WHERE p.template IS NOT NULL), '{}')
		FROM model_aliases a
		LEFT JOIN agent_template_versions v ON v.tenant_id = a.tenant_id AND v.document -> 'spec' ->> 'modelAlias' = a.name
		LEFT JOIN catalogue_published p ON p.tenant_id = v.tenant_id AND p.template = v.name AND p.version = v.version
		WHERE a.target = $1 GROUP BY a.name ORDER BY a.name`, model)
	if err != nil {
		return nil, nil, fmt.Errorf("find users of model %q: %w", model, err)
	}
	defer rows.Close()
	for rows.Next() {
		var alias string
		var used []string
		if err := rows.Scan(&alias, &used); err != nil {
			return nil, nil, err
		}
		aliases = append(aliases, alias)
		templates = append(templates, used...)
	}
	return aliases, templates, rows.Err()
}

const aliasColumns = `SELECT revision, created_at, updated_at, updated_by, digest, document FROM model_aliases`

func scanAlias(row rowScanner, name string) (muistamov1.ModelAliasRecord, string, error) {
	var rec muistamov1.ModelAliasRecord
	var digest string
	var body []byte
	err := row.Scan(&rec.Revision, &rec.CreatedAt, &rec.UpdatedAt, &rec.UpdatedBy, &digest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, "", fmt.Errorf("model alias %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return rec, "", fmt.Errorf("read model alias %q: %w", name, err)
	}
	return rec, digest, json.Unmarshal(body, &rec.Document)
}

// aliasCompliance reports whether alias exists and targets an approved model, and why not.
func aliasCompliance(ctx context.Context, tx pgx.Tx, alias string) (bool, string, error) {
	var target, status string
	err := tx.QueryRow(ctx, `SELECT a.target, m.approval_status FROM model_aliases a
		JOIN model_catalogue m ON m.tenant_id = a.tenant_id AND m.name = a.target WHERE a.name = $1`, alias).Scan(&target, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Sprintf("model alias %q does not exist", alias), nil
	}
	if err != nil {
		return false, "", fmt.Errorf("check model alias %q: %w", alias, err)
	}
	if status != string(muistamov1.ModelApprovalStatusApproved) {
		return false, fmt.Sprintf("model alias %q targets model %s, which is %s, not approved", alias, target, status), nil
	}
	return true, "", nil
}

func withCompliance(ctx context.Context, tx pgx.Tx, rec muistamov1.ModelAliasRecord) (muistamov1.ModelAliasRecord, error) {
	ok, reason, err := aliasCompliance(ctx, tx, rec.Document.Metadata.Name)
	rec.Compliant = ok
	if reason != "" {
		rec.Reason = &reason
	}
	return rec, err
}

// requireApprovedModel refuses a model that is missing or not approved.
func requireApprovedModel(ctx context.Context, tx pgx.Tx, model string) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT approval_status FROM model_catalogue WHERE name = $1`, model).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("model %q is not in the catalogue: %w", model, ErrInvalid)
	}
	if err != nil {
		return fmt.Errorf("read model %q: %w", model, err)
	}
	if status != string(muistamov1.ModelApprovalStatusApproved) {
		return fmt.Errorf("model %q is %s; only approved models can be targeted: %w", model, status, ErrConflict)
	}
	return nil
}

// ApplyModelAlias creates an alias on an approved model, or changes its description. Changing
// its target is a rollout, never an edit.
func (s *Service) ApplyModelAlias(ctx context.Context, actor Actor, doc muistamov1.ModelAlias) (muistamov1.ModelAliasRecord, bool, error) {
	if doc.Kind != muistamov1.ModelAliasKindModelAlias {
		return muistamov1.ModelAliasRecord{}, false, fmt.Errorf("kind %q is not ModelAlias: %w", doc.Kind, ErrInvalid)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return muistamov1.ModelAliasRecord{}, false, err
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	name := doc.Metadata.Name

	var rec muistamov1.ModelAliasRecord
	var created bool
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		current, currentDigest, err := scanAlias(tx.QueryRow(ctx, aliasColumns+` WHERE name = $1 FOR UPDATE`, name), name)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		switch {
		case exists && currentDigest == digest:
			rec, err = withCompliance(ctx, tx, current)
			return err
		case exists && current.Document.Spec.Target != doc.Spec.Target:
			return fmt.Errorf("alias %q targets %s; switch it with a rollout (mst rollout start), not an edit: %w",
				name, current.Document.Spec.Target, ErrConflict)
		case !exists:
			if err := requireApprovedModel(ctx, tx, doc.Spec.Target); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO model_aliases (tenant_id, name, target, revision, digest, document, updated_by)
				VALUES ($1, $2, $3, 1, $4, $5, $6)`, actor.Tenant, name, doc.Spec.Target, digest, body, actor.Name)
			created = true
		default:
			_, err = tx.Exec(ctx, `UPDATE model_aliases SET revision = revision + 1, digest = $2, document = $3, updated_at = now(),
				updated_by = $4 WHERE name = $1`, name, digest, body, actor.Name)
		}
		if err != nil {
			return fmt.Errorf("store model alias %q: %w", name, err)
		}
		next, _, err := scanAlias(tx.QueryRow(ctx, aliasColumns+` WHERE name = $1`, name), name)
		if err != nil {
			return err
		}
		if rec, err = withCompliance(ctx, tx, next); err != nil {
			return err
		}
		var before any
		if exists {
			before = map[string]any{"revision": current.Revision, "document": current.Document}
		}
		return recordEvidence(ctx, tx, s.signer, actor, "model-alias.applied", "ModelAlias", name, before,
			map[string]any{"revision": rec.Revision, "document": doc})
	})
	return rec, created, err
}

// GetModelAlias returns an alias and whether it is compliant.
func (s *Service) GetModelAlias(ctx context.Context, actor Actor, name string) (muistamov1.ModelAliasRecord, error) {
	var rec muistamov1.ModelAliasRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		a, _, err := scanAlias(tx.QueryRow(ctx, aliasColumns+` WHERE name = $1`, name), name)
		if err != nil {
			return err
		}
		rec, err = withCompliance(ctx, tx, a)
		return err
	})
	return rec, err
}

// ListModelAliases returns every alias, by name.
func (s *Service) ListModelAliases(ctx context.Context, actor Actor) ([]muistamov1.ModelAliasRecord, error) {
	out := []muistamov1.ModelAliasRecord{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, aliasColumns+` ORDER BY name`)
		if err != nil {
			return fmt.Errorf("list model aliases: %w", err)
		}
		var aliases []muistamov1.ModelAliasRecord
		for rows.Next() {
			a, _, err := scanAlias(rows, "")
			if err != nil {
				rows.Close()
				return err
			}
			aliases = append(aliases, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, a := range aliases {
			rec, err := withCompliance(ctx, tx, a)
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, err
}

const rolloutColumns = `SELECT id, alias, from_model, to_model, strategy, evaluation, status, reason, created_by, created_at,
	rolled_back_by, rolled_back_at, rollback_reason FROM rollouts`

func scanRollout(row rowScanner, id string) (muistamov1.Rollout, error) {
	var r muistamov1.Rollout
	var strategy, status string
	var evaluation []byte
	err := row.Scan(&r.Id, &r.Alias, &r.From, &r.To, &strategy, &evaluation, &status, &r.Reason, &r.CreatedBy, &r.CreatedAt,
		&r.RolledBackBy, &r.RolledBackAt, &r.RollbackReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, fmt.Errorf("rollout %s: %w", id, ErrNotFound)
	}
	if err != nil {
		return r, fmt.Errorf("read rollout: %w", err)
	}
	r.Strategy, r.Status = muistamov1.RolloutStrategy(strategy), muistamov1.RolloutStatus(status)
	return r, json.Unmarshal(evaluation, &r.Evaluation)
}

// StartRollout switches an alias to another approved model. Release 1 has no evaluation gate,
// so the caller must acknowledge that the switch is unevaluated.
func (s *Service) StartRollout(ctx context.Context, actor Actor, alias string, req muistamov1.RolloutRequest) (muistamov1.Rollout, error) {
	var out muistamov1.Rollout
	if !bool(req.AcknowledgeUnevaluated) {
		return out, fmt.Errorf("a switch cannot be evaluated until the gateway exists; acknowledge that to proceed: %w", ErrInvalid)
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		current, _, err := scanAlias(tx.QueryRow(ctx, aliasColumns+` WHERE name = $1 FOR UPDATE`, alias), alias)
		if err != nil {
			return err
		}
		from := current.Document.Spec.Target
		if from == req.To {
			return fmt.Errorf("alias %q already targets %s: %w", alias, req.To, ErrConflict)
		}
		if err := requireApprovedModel(ctx, tx, req.To); err != nil {
			return err
		}
		id := uuid.New()
		evaluation, err := json.Marshal(map[string]string{"status": "not-run", "reason": evaluationNotRun})
		if err != nil {
			return err
		}
		if err := retarget(ctx, tx, actor, current, req.To); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO rollouts (tenant_id, id, alias, from_model, to_model, strategy, evaluation, status, reason, created_by)
			VALUES ($1, $2, $3, $4, $5, 'immediate', $6, 'completed', $7, $8)`,
			actor.Tenant, id, alias, from, req.To, evaluation, req.Reason, actor.Name); err != nil {
			return fmt.Errorf("record rollout: %w", err)
		}
		if out, err = scanRollout(tx.QueryRow(ctx, rolloutColumns+` WHERE id = $1`, id), id.String()); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "rollout.started", "ModelAlias", alias,
			map[string]any{"target": from}, map[string]any{"target": req.To, "rollout": id, "strategy": "immediate",
				"evaluation": out.Evaluation, "reason": req.Reason})
	})
	return out, err
}

// RollbackRollout returns an alias to the model it had before a rollout, if that model is still
// approved and the alias has not moved on since.
func (s *Service) RollbackRollout(ctx context.Context, actor Actor, id uuid.UUID, reason string) (muistamov1.Rollout, error) {
	var out muistamov1.Rollout
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		r, err := scanRollout(tx.QueryRow(ctx, rolloutColumns+` WHERE id = $1 FOR UPDATE`, id), id.String())
		if err != nil {
			return err
		}
		if r.Status != muistamov1.RolloutStatusCompleted {
			return fmt.Errorf("rollout %s is %s: %w", id, r.Status, ErrConflict)
		}
		current, _, err := scanAlias(tx.QueryRow(ctx, aliasColumns+` WHERE name = $1 FOR UPDATE`, r.Alias), r.Alias)
		if err != nil {
			return err
		}
		if current.Document.Spec.Target != r.To {
			return fmt.Errorf("alias %q has moved on to %s since this rollout; roll back the later one: %w",
				r.Alias, current.Document.Spec.Target, ErrConflict)
		}
		if err := requireApprovedModel(ctx, tx, r.From); err != nil {
			return err
		}
		if err := retarget(ctx, tx, actor, current, r.From); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE rollouts SET status = 'rolled-back', rolled_back_by = $2, rolled_back_at = $3,
			rollback_reason = $4 WHERE id = $1`, id, actor.Name, time.Now(), reason); err != nil {
			return fmt.Errorf("record rollback: %w", err)
		}
		if out, err = scanRollout(tx.QueryRow(ctx, rolloutColumns+` WHERE id = $1`, id), id.String()); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "rollout.rolled_back", "ModelAlias", r.Alias,
			map[string]any{"target": r.To}, map[string]any{"target": r.From, "rollout": id, "reason": reason})
	})
	return out, err
}

// retarget points an alias at another model. Only rollouts call it.
func retarget(ctx context.Context, tx pgx.Tx, actor Actor, current muistamov1.ModelAliasRecord, to string) error {
	doc := current.Document
	doc.Spec.Target = to
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if _, err := tx.Exec(ctx, `UPDATE model_aliases SET target = $2, revision = revision + 1, digest = $3, document = $4,
		updated_at = now(), updated_by = $5 WHERE name = $1`,
		doc.Metadata.Name, to, hex.EncodeToString(sum[:]), body, actor.Name); err != nil {
		return fmt.Errorf("retarget alias %q: %w", doc.Metadata.Name, err)
	}
	return nil
}

// GetRollout returns one rollout.
func (s *Service) GetRollout(ctx context.Context, actor Actor, id uuid.UUID) (muistamov1.Rollout, error) {
	var out muistamov1.Rollout
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		out, err = scanRollout(tx.QueryRow(ctx, rolloutColumns+` WHERE id = $1`, id), id.String())
		return err
	})
	return out, err
}

// ListRollouts returns rollouts, newest first.
func (s *Service) ListRollouts(ctx context.Context, actor Actor) ([]muistamov1.Rollout, error) {
	out := []muistamov1.Rollout{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, rolloutColumns+` ORDER BY created_at DESC, id`)
		if err != nil {
			return fmt.Errorf("list rollouts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRollout(rows, "")
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// requireCompliantAlias refuses a template version whose model alias is missing or not on an
// approved model (E5.4). Publication calls it.
func requireCompliantAlias(ctx context.Context, tx pgx.Tx, template string, version int) error {
	rec, _, err := templateVersion(ctx, tx, template, version)
	if err != nil {
		return err
	}
	ok, reason, err := aliasCompliance(ctx, tx, rec.Document.Spec.ModelAlias)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("template %q version %d cannot be published: %s: %w", template, version, reason, ErrConflict)
	}
	return nil
}

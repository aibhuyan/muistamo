// Package registry stores agent templates and instances.
//
// Template versions are immutable: a changed document becomes a new version, an identical one is
// a no-op. Every write appends a signed, hash-chained evidence event in the same transaction, so
// no change commits without its evidence (CLAUDE.md invariant 4).
package registry

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/evidencechain"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// Errors returned by Service. Each wraps one of these; the API maps them to status codes.
var (
	ErrNotFound             = errors.New("not found")
	ErrInvalid              = errors.New("invalid")
	ErrConflict             = errors.New("conflict")
	ErrPrecondition         = errors.New("precondition failed")
	ErrPreconditionRequired = errors.New("precondition required")
	ErrEvidence             = evidence.ErrNotRecorded
)

// Actor is who is acting, for which tenant, in which request.
type Actor struct {
	Tenant    uuid.UUID
	Name      string
	RequestID string
}

// Service implements the registry on top of store.DB.
type Service struct {
	db     *store.DB
	signer evidence.Signer
}

// New returns a Service that signs evidence with signer.
func New(db *store.DB, signer evidence.Signer) *Service { return &Service{db: db, signer: signer} }

// ApplyTemplate stores doc as a new version if it differs from the latest one. It reports
// whether a version was created.
func (s *Service) ApplyTemplate(ctx context.Context, actor Actor, doc muistamov1.AgentTemplate) (muistamov1.AgentTemplateRecord, bool, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return muistamov1.AgentTemplateRecord{}, false, fmt.Errorf("encode template: %w", err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	name := doc.Metadata.Name

	var rec muistamov1.AgentTemplateRecord
	var created bool
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var latest int
		err := tx.QueryRow(ctx, `SELECT latest_version FROM agent_templates WHERE name = $1 FOR UPDATE`, name).Scan(&latest)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Instances are named after their clone or template, so the two share one namespace.
			var clone bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_clones WHERE name = $1)`, name).Scan(&clone); err != nil {
				return fmt.Errorf("check clone %q: %w", name, err)
			}
			if clone {
				return fmt.Errorf("%q is already a clone's name; a template needs its own: %w", name, ErrConflict)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO agent_templates (tenant_id, name, latest_version) VALUES ($1, $2, 1)`, actor.Tenant, name); err != nil {
				if isUniqueViolation(err) {
					return fmt.Errorf("template %q was created concurrently; retry: %w", name, ErrConflict)
				}
				return fmt.Errorf("insert template %q: %w", name, err)
			}
		case err != nil:
			return fmt.Errorf("lock template %q: %w", name, err)
		default:
			current, currentDigest, err := templateVersion(ctx, tx, name, latest)
			if err != nil {
				return err
			}
			if currentDigest == digest {
				rec = current
				return nil
			}
			if _, err := tx.Exec(ctx, `UPDATE agent_templates SET latest_version = $2 WHERE name = $1`, name, latest+1); err != nil {
				return fmt.Errorf("advance template %q: %w", name, err)
			}
		}

		version := latest + 1
		var createdAt time.Time
		err = tx.QueryRow(ctx, `
			INSERT INTO agent_template_versions (tenant_id, name, version, digest, document, created_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at`,
			actor.Tenant, name, version, digest, body, actor.Name).Scan(&createdAt)
		if err != nil {
			return fmt.Errorf("insert template %q version %d: %w", name, version, err)
		}
		rec = muistamov1.AgentTemplateRecord{Version: version, CreatedAt: createdAt, CreatedBy: actor.Name, Document: doc}
		created = true
		return recordEvidence(ctx, tx, s.signer, actor, "template.version.created", "AgentTemplate", name, nil, rec)
	})
	return rec, created, err
}

// GetTemplate returns the latest version of a template.
func (s *Service) GetTemplate(ctx context.Context, actor Actor, name string) (muistamov1.AgentTemplateRecord, error) {
	var rec muistamov1.AgentTemplateRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var latest int
		err := tx.QueryRow(ctx, `SELECT latest_version FROM agent_templates WHERE name = $1`, name).Scan(&latest)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("template %q: %w", name, ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("read template %q: %w", name, err)
		}
		rec, _, err = templateVersion(ctx, tx, name, latest)
		return err
	})
	return rec, err
}

// GetTemplateVersion returns one version of a template.
func (s *Service) GetTemplateVersion(ctx context.Context, actor Actor, name string, version int) (muistamov1.AgentTemplateRecord, error) {
	var rec muistamov1.AgentTemplateRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		rec, _, err = templateVersion(ctx, tx, name, version)
		return err
	})
	return rec, err
}

// ListTemplates returns the latest version of each template, ordered by name.
func (s *Service) ListTemplates(ctx context.Context, actor Actor, cursor string, limit int) (muistamov1.AgentTemplatePage, error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return muistamov1.AgentTemplatePage{}, err
	}
	page := muistamov1.AgentTemplatePage{Items: []muistamov1.AgentTemplateRecord{}}
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT v.version, v.created_at, v.created_by, v.document
			FROM agent_templates t
			JOIN agent_template_versions v ON v.tenant_id = t.tenant_id AND v.name = t.name AND v.version = t.latest_version
			WHERE t.name > $1 ORDER BY t.name LIMIT $2`, after, limit+1)
		if err != nil {
			return fmt.Errorf("list templates: %w", err)
		}
		for rows.Next() {
			var rec muistamov1.AgentTemplateRecord
			var body []byte
			if err := rows.Scan(&rec.Version, &rec.CreatedAt, &rec.CreatedBy, &body); err != nil {
				return fmt.Errorf("scan template: %w", err)
			}
			if err := json.Unmarshal(body, &rec.Document); err != nil {
				return fmt.Errorf("decode stored template: %w", err)
			}
			page.Items = append(page.Items, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return muistamov1.AgentTemplatePage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		next := encodeCursor(page.Items[limit-1].Document.Metadata.Name)
		page.NextCursor = &next
	}
	return page, nil
}

// ApplyInstance creates an instance, or updates its sponsor, delegate and cost centre.
// ifMatch must be empty on create and carry the current revision on update.
func (s *Service) ApplyInstance(ctx context.Context, actor Actor, doc muistamov1.AgentInstance, ifMatch string) (muistamov1.AgentInstanceRecord, bool, error) {
	name := doc.Metadata.Name
	var rec muistamov1.AgentInstanceRecord
	var created bool
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
			return err
		}
		current, err := lockInstance(ctx, tx, name)
		if errors.Is(err, ErrNotFound) {
			if ifMatch != "" {
				return fmt.Errorf("instance %q does not exist: %w", name, ErrPrecondition)
			}
			rec, err = createInstance(ctx, tx, s.signer, actor, doc)
			created = err == nil
			return err
		}
		if err != nil {
			return err
		}
		if err := checkRevision(ifMatch, current.Revision); err != nil {
			return err
		}
		if err := sameImmutableFields(current.Document, doc); err != nil {
			return err
		}
		if equalJSON(current.Document, doc) {
			rec = current
			return nil
		}
		rec, err = updateInstance(ctx, tx, current, doc)
		if err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "instance.updated", "AgentInstance", name, current, rec)
	})
	return rec, created, err
}

// GetInstance returns an instance.
func (s *Service) GetInstance(ctx context.Context, actor Actor, name string) (muistamov1.AgentInstanceRecord, error) {
	var rec muistamov1.AgentInstanceRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		rec, err = scanInstance(tx.QueryRow(ctx, instanceColumns+` WHERE name = $1`, name), name)
		return err
	})
	return rec, err
}

// ListInstances returns instances ordered by name.
func (s *Service) ListInstances(ctx context.Context, actor Actor, cursor string, limit int) (muistamov1.AgentInstancePage, error) {
	after, err := decodeCursor(cursor)
	if err != nil {
		return muistamov1.AgentInstancePage{}, err
	}
	page := muistamov1.AgentInstancePage{Items: []muistamov1.AgentInstanceRecord{}}
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, instanceColumns+` WHERE name > $1 ORDER BY name LIMIT $2`, after, limit+1)
		if err != nil {
			return fmt.Errorf("list instances: %w", err)
		}
		for rows.Next() {
			rec, err := scanInstance(rows, "")
			if err != nil {
				return err
			}
			page.Items = append(page.Items, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return muistamov1.AgentInstancePage{}, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		next := encodeCursor(page.Items[limit-1].Document.Metadata.Name)
		page.NextCursor = &next
	}
	return page, nil
}

// Transition moves an instance to another lifecycle state.
func (s *Service) Transition(ctx context.Context, actor Actor, name string, to muistamov1.InstanceState, ifMatch string) (muistamov1.AgentInstanceRecord, error) {
	var rec muistamov1.AgentInstanceRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		person, err := identityPersonLock(ctx, tx, actor.Tenant, name)
		if err != nil {
			return err
		}
		current, err := lockInstance(ctx, tx, name)
		if err != nil {
			return err
		}
		if ifMatch == "" {
			return fmt.Errorf("transition of %q: %w", name, ErrPreconditionRequired)
		}
		if err := checkRevision(ifMatch, current.Revision); err != nil {
			return err
		}
		from := current.Document.Spec.State
		if !CanTransition(from, to) {
			return fmt.Errorf("instance %q cannot move from %s to %s: %w", name, from, to, ErrConflict)
		}
		if err := checkIdentityTransition(ctx, tx, current, to, person); err != nil {
			return err
		}
		next := current.Document
		next.Spec.State = to
		rec, err = updateInstance(ctx, tx, current, next)
		if err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "instance.transitioned", "AgentInstance", name,
			map[string]any{"state": from}, map[string]any{"state": to, "revision": rec.Revision})
	})
	return rec, err
}

// ETag formats a version or revision as a strong entity tag.
func ETag(n int) string { return strconv.Quote(strconv.Itoa(n)) }

func templateVersion(ctx context.Context, tx pgx.Tx, name string, version int) (muistamov1.AgentTemplateRecord, string, error) {
	rec := muistamov1.AgentTemplateRecord{Version: version}
	var digest string
	var body []byte
	err := tx.QueryRow(ctx, `
		SELECT digest, document, created_at, created_by FROM agent_template_versions
		WHERE name = $1 AND version = $2`, name, version).Scan(&digest, &body, &rec.CreatedAt, &rec.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, "", fmt.Errorf("template %q version %d: %w", name, version, ErrNotFound)
	}
	if err != nil {
		return rec, "", fmt.Errorf("read template %q version %d: %w", name, version, err)
	}
	if err := json.Unmarshal(body, &rec.Document); err != nil {
		return rec, "", fmt.Errorf("decode stored template: %w", err)
	}
	return rec, digest, nil
}

const instanceColumns = `SELECT name, revision, created_at, updated_at, document FROM agent_instances`

type rowScanner interface{ Scan(dest ...any) error }

func scanInstance(row rowScanner, name string) (muistamov1.AgentInstanceRecord, error) {
	var rec muistamov1.AgentInstanceRecord
	var scanned string
	var body []byte
	err := row.Scan(&scanned, &rec.Revision, &rec.CreatedAt, &rec.UpdatedAt, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return rec, fmt.Errorf("instance %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return rec, fmt.Errorf("read instance: %w", err)
	}
	if err := json.Unmarshal(body, &rec.Document); err != nil {
		return rec, fmt.Errorf("decode stored instance %q: %w", scanned, err)
	}
	return rec, nil
}

func lockInstance(ctx context.Context, tx pgx.Tx, name string) (muistamov1.AgentInstanceRecord, error) {
	return scanInstance(tx.QueryRow(ctx, instanceColumns+` WHERE name = $1 FOR UPDATE`, name), name)
}

func createInstance(ctx context.Context, tx pgx.Tx, signer evidence.Signer, actor Actor, doc muistamov1.AgentInstance) (muistamov1.AgentInstanceRecord, error) {
	return createInstanceWithIdentity(ctx, tx, signer, actor, doc, nil)
}

func createInstanceWithIdentity(ctx context.Context, tx pgx.Tx, signer evidence.Signer, actor Actor, doc muistamov1.AgentInstance, identity *muistamov1.InstanceIdentityStatus) (muistamov1.AgentInstanceRecord, error) {
	if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
		return muistamov1.AgentInstanceRecord{}, err
	}
	version, err := store.IdentityEnrollmentVersion(ctx, tx)
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, err
	}
	if (identity == nil && version != nil) || (identity != nil && (version == nil || identity.BindingVersion == nil || *identity.BindingVersion != *version)) {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("instance creation must follow the enrolled HR identity route: %w", ErrConflict)
	}
	name := doc.Metadata.Name
	if doc.Spec.State != muistamov1.InstanceStateRequested {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("instance %q must be created in state requested, not %s: %w", name, doc.Spec.State, ErrInvalid)
	}
	ref := doc.Spec.TemplateRef
	templateVersionNumber, err := strconv.Atoi(ref.Version)
	if err != nil || templateVersionNumber < 1 {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("templateRef.version %q must be a template version number: %w", ref.Version, ErrInvalid)
	}
	if _, _, err := templateVersion(ctx, tx, ref.Name, templateVersionNumber); err != nil {
		if errors.Is(err, ErrNotFound) {
			return muistamov1.AgentInstanceRecord{}, fmt.Errorf("templateRef %s version %d does not exist: %w", ref.Name, templateVersionNumber, ErrInvalid)
		}
		return muistamov1.AgentInstanceRecord{}, err
	}
	if doc.Spec.CloneRef != nil {
		if err := cloneForInstance(ctx, tx, *doc.Spec.CloneRef, ref.Name, templateVersionNumber); err != nil {
			return muistamov1.AgentInstanceRecord{}, err
		}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("encode instance: %w", err)
	}
	rec := muistamov1.AgentInstanceRecord{Revision: 1, Document: doc}
	err = tx.QueryRow(ctx, `
		INSERT INTO agent_instances (tenant_id, name, template_name, template_version, state, revision, document)
		VALUES ($1, $2, $3, $4, $5, 1, $6) RETURNING created_at, updated_at`,
		actor.Tenant, name, ref.Name, templateVersionNumber, string(doc.Spec.State), body).Scan(&rec.CreatedAt, &rec.UpdatedAt)
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("insert instance %q: %w", name, err)
	}
	if identity == nil {
		_, err = tx.Exec(ctx, `INSERT INTO instance_identities(tenant_id,instance_name,provider_mode,observed_state) VALUES($1,$2,'simulated','simulated')`, actor.Tenant, name)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO instance_identities(tenant_id,instance_name,provider_mode,binding_version,entra_tenant_id,assignment_receipt_id,observed_state) VALUES($1,$2,'entra',$3,$4,$5,'unprovisioned')`, actor.Tenant, name, identity.BindingVersion, identity.EntraTenantId, identity.AssignmentReceiptId)
	}
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("pin instance identity metadata: %w", err)
	}
	return rec, recordEvidence(ctx, tx, signer, actor, "instance.created", "AgentInstance", name, nil, rec)
}

func updateInstance(ctx context.Context, tx pgx.Tx, current muistamov1.AgentInstanceRecord, next muistamov1.AgentInstance) (muistamov1.AgentInstanceRecord, error) {
	body, err := json.Marshal(next)
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("encode instance: %w", err)
	}
	rec := muistamov1.AgentInstanceRecord{Revision: current.Revision + 1, CreatedAt: current.CreatedAt, Document: next}
	err = tx.QueryRow(ctx, `
		UPDATE agent_instances SET document = $2, state = $3, revision = $4, updated_at = now()
		WHERE name = $1 RETURNING updated_at`,
		next.Metadata.Name, body, string(next.Spec.State), rec.Revision).Scan(&rec.UpdatedAt)
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, fmt.Errorf("update instance %q: %w", next.Metadata.Name, err)
	}
	return rec, nil
}

// sameImmutableFields refuses changes to anything but sponsor, delegate and cost centre.
func sameImmutableFields(current, next muistamov1.AgentInstance) error {
	a, b := current, next
	a.Spec.Sponsor, a.Spec.Delegate, a.Spec.CostCentre = nil, nil, nil
	b.Spec.Sponsor, b.Spec.Delegate, b.Spec.CostCentre = nil, nil, nil
	if !equalJSON(a, b) {
		return fmt.Errorf("instance %q: only sponsor, delegate and costCentre may change; state changes use transitions: %w",
			next.Metadata.Name, ErrConflict)
	}
	return nil
}

func equalJSON(a, b any) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(x) == string(y)
}

func checkRevision(ifMatch string, revision int) error {
	if ifMatch == "" {
		return fmt.Errorf("If-Match is required to change an existing instance: %w", ErrPreconditionRequired)
	}
	if ifMatch != ETag(revision) {
		return fmt.Errorf("If-Match %s does not match current revision %s: %w", ifMatch, ETag(revision), ErrPrecondition)
	}
	return nil
}

// recordEvidence appends a signed event inside the caller's transaction. A failure aborts the
// whole write (CLAUDE.md invariants 3 and 4).
func recordEvidence(ctx context.Context, tx pgx.Tx, signer evidence.Signer, actor Actor, action, kind, name string, before, after any) error {
	_, err := evidence.Append(ctx, tx, signer, evidence.Entry{
		Tenant: actor.Tenant, Actor: actor.Name, Action: action,
		SubjectKind: kind, SubjectName: name, Before: before, After: after, RequestID: actor.RequestID,
	})
	return err
}

// ListEvents returns the tenant's evidence events after afterSeq, in chain order.
func (s *Service) ListEvents(ctx context.Context, actor Actor, afterSeq int64, limit int) ([]evidencechain.Event, error) {
	var events []evidencechain.Event
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		events, err = evidence.List(ctx, tx, afterSeq, limit)
		return err
	})
	return events, err
}

func encodeCursor(name string) string { return base64.RawURLEncoding.EncodeToString([]byte(name)) }

func decodeCursor(cursor string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return "", fmt.Errorf("cursor: %w", ErrInvalid)
	}
	return string(raw), nil
}

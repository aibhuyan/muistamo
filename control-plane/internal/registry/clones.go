package registry

// Clones (FR-103, E1.3, J5): variants of a template with their own instances.
//
// HUMAN REVIEW REQUIRED (CLAUDE.md): which template version a clone resolves to decides what its
// instances run, and whether joiners get it.
//
// A clone's overlay may add knowledge packs and set its own budget and HR assignment; the
// contract refuses anything else, and the merge below touches nothing else, so a clone never
// widens what the catalogue approved. Its template never changes. resolveClone is the only place
// that decides a clone's version:
//   - follow: the template's catalogue-published version; nothing while it is unpublished.
//   - pin: spec.version.
//   - manual: the version last synced to, which moves only on SyncClone.
//
// A clone is assignable to joiners only while its resolved version is the published one.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

type cloneRow struct {
	revision             int
	createdAt, updatedAt time.Time
	updatedBy            string
	digest               string
	synced               *int
	doc                  muistamov1.AgentClone
}

const cloneColumns = `SELECT revision, created_at, updated_at, updated_by, digest, synced_version, document FROM agent_clones`

func scanClone(row rowScanner, name string) (cloneRow, error) {
	var c cloneRow
	var body []byte
	err := row.Scan(&c.revision, &c.createdAt, &c.updatedAt, &c.updatedBy, &c.digest, &c.synced, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, fmt.Errorf("clone %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return c, fmt.Errorf("read clone %q: %w", name, err)
	}
	return c, json.Unmarshal(body, &c.doc)
}

// publishedVersion returns the template's catalogue-published version, or nil.
func publishedVersion(ctx context.Context, tx pgx.Tx, template string) (*int, error) {
	var v int
	err := tx.QueryRow(ctx, `SELECT version FROM catalogue_published WHERE template = $1`, template).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read published version of %q: %w", template, err)
	}
	return &v, nil
}

// cloneResolution is how a clone resolves now.
type cloneResolution struct {
	version    *int // nil: cannot resolve
	upstream   *int // the published version, when it differs from version
	assignable bool
	reason     string
}

func resolveClone(ctx context.Context, tx pgx.Tx, c cloneRow) (cloneResolution, error) {
	published, err := publishedVersion(ctx, tx, c.doc.Spec.Template)
	if err != nil {
		return cloneResolution{}, err
	}
	var r cloneResolution
	switch c.doc.Spec.Sync {
	case muistamov1.AgentCloneSpecSyncFollow:
		r.version = published
	case muistamov1.AgentCloneSpecSyncPin:
		r.version = c.doc.Spec.Version
	case muistamov1.AgentCloneSpecSyncManual:
		r.version = c.synced
	default:
		return r, fmt.Errorf("clone %q has unknown sync policy %q", c.doc.Metadata.Name, c.doc.Spec.Sync)
	}
	switch {
	case published == nil && r.version == nil:
		r.reason = fmt.Sprintf("template %s is not published to the catalogue", c.doc.Spec.Template)
	case published == nil:
		r.reason = fmt.Sprintf("template %s is not published to the catalogue, so joiners cannot get this clone", c.doc.Spec.Template)
	case r.version != nil && *r.version == *published:
		r.assignable = true
	default:
		r.upstream = published
		if c.doc.Spec.Sync == muistamov1.AgentCloneSpecSyncManual {
			r.reason = fmt.Sprintf("published version %d is newer than synced version %d; run mst clone sync", *published, *r.version)
		} else {
			r.reason = fmt.Sprintf("pinned to version %d but version %d is published, so joiners cannot get this clone", *r.version, *published)
		}
	}
	return r, nil
}

func (c cloneRow) record(r cloneResolution) muistamov1.AgentCloneRecord {
	rec := muistamov1.AgentCloneRecord{Revision: c.revision, CreatedAt: c.createdAt, UpdatedAt: c.updatedAt,
		UpdatedBy: c.updatedBy, Document: c.doc, ResolvedVersion: r.version, UpstreamVersion: r.upstream, Assignable: r.assignable}
	if r.reason != "" {
		rec.Reason = &r.reason
	}
	return rec
}

// ApplyClone creates or changes a clone. It reports whether the clone was created.
func (s *Service) ApplyClone(ctx context.Context, actor Actor, doc muistamov1.AgentClone) (muistamov1.AgentCloneRecord, bool, error) {
	if doc.Kind != muistamov1.AgentCloneKindAgentClone {
		return muistamov1.AgentCloneRecord{}, false, fmt.Errorf("kind %q is not AgentClone: %w", doc.Kind, ErrInvalid)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return muistamov1.AgentCloneRecord{}, false, err
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	name, template := doc.Metadata.Name, doc.Spec.Template

	var rec muistamov1.AgentCloneRecord
	var created bool
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		// A clone changes who gets an agent and with what knowledge, so it is a catalogue
		// decision: catalogue approvers only.
		if err := requireApprover(ctx, tx, actor, "create or change clones"); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_templates WHERE name = $1)`, template).Scan(&exists); err != nil {
			return fmt.Errorf("check template %q: %w", template, err)
		}
		if !exists {
			return fmt.Errorf("template %q does not exist: %w", template, ErrInvalid)
		}
		// Instances are named after their clone or template, so the two share one namespace.
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_templates WHERE name = $1)`, name).Scan(&exists); err != nil {
			return fmt.Errorf("check template %q: %w", name, err)
		}
		if exists {
			return fmt.Errorf("%q is already a template's name; a clone needs its own: %w", name, ErrConflict)
		}
		if doc.Spec.Sync == muistamov1.AgentCloneSpecSyncPin {
			if _, _, err := templateVersion(ctx, tx, template, *doc.Spec.Version); err != nil {
				if errors.Is(err, ErrNotFound) {
					return fmt.Errorf("template %q has no version %d to pin: %w", template, *doc.Spec.Version, ErrInvalid)
				}
				return err
			}
		}

		current, err := scanClone(tx.QueryRow(ctx, cloneColumns+` WHERE name = $1 FOR UPDATE`, name), name)
		existing := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if existing && current.doc.Spec.Template != template {
			return fmt.Errorf("clone %q is a clone of %s; its template cannot change: %w", name, current.doc.Spec.Template, ErrConflict)
		}
		if existing && current.digest == digest {
			r, err := resolveClone(ctx, tx, current)
			rec = current.record(r)
			return err
		}

		// A manual clone starts at, or switching to manual keeps, a concrete version.
		var synced *int
		if doc.Spec.Sync == muistamov1.AgentCloneSpecSyncManual {
			if existing && current.synced != nil {
				synced = current.synced
			} else if synced, err = publishedVersion(ctx, tx, template); err != nil {
				return err
			} else if synced == nil {
				return fmt.Errorf("template %q is not published, so a manual clone has no version to start from; publish it or pin a version: %w", template, ErrConflict)
			}
		}

		var next cloneRow
		if existing {
			err = tx.QueryRow(ctx, `UPDATE agent_clones SET sync = $2, synced_version = $3, revision = revision + 1, digest = $4,
				document = $5, updated_at = now(), updated_by = $6 WHERE name = $1
				RETURNING revision, created_at, updated_at, updated_by, digest, synced_version, document`,
				name, string(doc.Spec.Sync), synced, digest, body, actor.Name).
				Scan(&next.revision, &next.createdAt, &next.updatedAt, &next.updatedBy, &next.digest, &next.synced, new([]byte))
		} else {
			err = tx.QueryRow(ctx, `INSERT INTO agent_clones (tenant_id, name, template, sync, synced_version, revision, digest, document, updated_by)
				VALUES ($1, $2, $3, $4, $5, 1, $6, $7, $8)
				RETURNING revision, created_at, updated_at, updated_by, digest, synced_version, document`,
				actor.Tenant, name, template, string(doc.Spec.Sync), synced, digest, body, actor.Name).
				Scan(&next.revision, &next.createdAt, &next.updatedAt, &next.updatedBy, &next.digest, &next.synced, new([]byte))
			created = true
		}
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("clone %q was created concurrently; retry: %w", name, ErrConflict)
			}
			return fmt.Errorf("store clone %q: %w", name, err)
		}
		next.doc = doc
		r, err := resolveClone(ctx, tx, next)
		if err != nil {
			return err
		}
		rec = next.record(r)
		var before any
		action := "clone.created"
		if existing {
			action, before = "clone.updated", map[string]any{"revision": current.revision, "document": current.doc, "syncedVersion": current.synced}
		}
		return recordEvidence(ctx, tx, s.signer, actor, action, "AgentClone", name, before,
			map[string]any{"revision": next.revision, "document": doc, "syncedVersion": next.synced, "resolvedVersion": r.version})
	})
	return rec, created, err
}

// GetClone returns a clone and how it resolves.
func (s *Service) GetClone(ctx context.Context, actor Actor, name string) (muistamov1.AgentCloneRecord, error) {
	var rec muistamov1.AgentCloneRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		c, err := scanClone(tx.QueryRow(ctx, cloneColumns+` WHERE name = $1`, name), name)
		if err != nil {
			return err
		}
		r, err := resolveClone(ctx, tx, c)
		rec = c.record(r)
		return err
	})
	return rec, err
}

// ListClones returns every clone, or the clones of one template, by name.
func (s *Service) ListClones(ctx context.Context, actor Actor, template string) ([]muistamov1.AgentCloneRecord, error) {
	out := []muistamov1.AgentCloneRecord{}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		clones, err := listClones(ctx, tx, template)
		if err != nil {
			return err
		}
		for _, c := range clones {
			r, err := resolveClone(ctx, tx, c)
			if err != nil {
				return err
			}
			out = append(out, c.record(r))
		}
		return nil
	})
	return out, err
}

func listClones(ctx context.Context, tx pgx.Tx, template string) ([]cloneRow, error) {
	rows, err := tx.Query(ctx, cloneColumns+` WHERE $1 = '' OR template = $1 ORDER BY name`, template)
	if err != nil {
		return nil, fmt.Errorf("list clones: %w", err)
	}
	defer rows.Close()
	var out []cloneRow
	for rows.Next() {
		c, err := scanClone(rows, "")
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SyncClone moves a manual clone to its template's published version.
func (s *Service) SyncClone(ctx context.Context, actor Actor, name string) (muistamov1.AgentCloneRecord, error) {
	var rec muistamov1.AgentCloneRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := requireApprover(ctx, tx, actor, "sync clones"); err != nil {
			return err
		}
		c, err := scanClone(tx.QueryRow(ctx, cloneColumns+` WHERE name = $1 FOR UPDATE`, name), name)
		if err != nil {
			return err
		}
		if c.doc.Spec.Sync != muistamov1.AgentCloneSpecSyncManual {
			return fmt.Errorf("clone %q syncs by %s; only manual clones are synced by hand: %w", name, c.doc.Spec.Sync, ErrConflict)
		}
		published, err := publishedVersion(ctx, tx, c.doc.Spec.Template)
		if err != nil {
			return err
		}
		if published == nil {
			return fmt.Errorf("template %q is not published; there is nothing to sync to: %w", c.doc.Spec.Template, ErrConflict)
		}
		if *published != *c.synced {
			from := *c.synced
			if err := tx.QueryRow(ctx, `UPDATE agent_clones SET synced_version = $2, revision = revision + 1, updated_at = now(),
				updated_by = $3 WHERE name = $1 RETURNING revision, updated_at, updated_by`, name, *published, actor.Name).
				Scan(&c.revision, &c.updatedAt, &c.updatedBy); err != nil {
				return fmt.Errorf("sync clone %q: %w", name, err)
			}
			c.synced = published
			if err := recordEvidence(ctx, tx, s.signer, actor, "clone.synced", "AgentClone", name,
				map[string]any{"version": from}, map[string]any{"version": *published, "revision": c.revision}); err != nil {
				return err
			}
		}
		r, err := resolveClone(ctx, tx, c)
		rec = c.record(r)
		return err
	})
	return rec, err
}

// EffectiveSpec returns what an instance runs with: its template version's spec, through its
// clone if it has one. A clone that cannot resolve is a conflict, never a fallback.
func (s *Service) EffectiveSpec(ctx context.Context, actor Actor, instance string) (muistamov1.EffectiveAgentSpec, error) {
	var out muistamov1.EffectiveAgentSpec
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		inst, err := scanInstance(tx.QueryRow(ctx, instanceColumns+` WHERE name = $1`, instance), instance)
		if err != nil {
			return err
		}
		ref := inst.Document.Spec.TemplateRef
		out = muistamov1.EffectiveAgentSpec{Instance: instance, Template: ref.Name}
		if inst.Document.Spec.CloneRef == nil {
			if _, err := fmt.Sscan(ref.Version, &out.Version); err != nil {
				return fmt.Errorf("instance %q has version %q: %w", instance, ref.Version, ErrInvalid)
			}
			tv, _, err := templateVersion(ctx, tx, ref.Name, out.Version)
			out.Spec = tv.Document.Spec
			return err
		}
		cloneName := *inst.Document.Spec.CloneRef
		c, err := scanClone(tx.QueryRow(ctx, cloneColumns+` WHERE name = $1`, cloneName), cloneName)
		if err != nil {
			return err
		}
		if c.doc.Spec.Template != ref.Name {
			return fmt.Errorf("clone %q is not a clone of %s: %w", cloneName, ref.Name, ErrConflict)
		}
		r, err := resolveClone(ctx, tx, c)
		if err != nil {
			return err
		}
		if r.version == nil {
			return fmt.Errorf("clone %q cannot resolve a template version (%s): %w", cloneName, r.reason, ErrConflict)
		}
		tv, _, err := templateVersion(ctx, tx, ref.Name, *r.version)
		if err != nil {
			return err
		}
		spec, err := applyOverlay(tv.Document.Spec, c.doc)
		if err != nil {
			return err
		}
		out.Version, out.Clone, out.Spec = *r.version, &cloneName, spec
		return nil
	})
	return out, err
}

// applyOverlay merges a clone's overlay into a template spec: knowledge packs added (the
// overlay's constraint wins for a pack both name), budget and assignment replaced. No other
// field is read from the overlay, and the result must still match the template spec contract.
func applyOverlay(spec muistamov1.AgentTemplateSpec, clone muistamov1.AgentClone) (muistamov1.AgentTemplateSpec, error) {
	overlay := clone.Spec.Overlay
	if overlay == nil {
		return spec, nil
	}
	base, err := json.Marshal(spec)
	if err != nil {
		return spec, err
	}
	var merged map[string]any
	if err := json.Unmarshal(base, &merged); err != nil {
		return spec, err
	}
	if overlay.KnowledgePacks != nil {
		packs := []muistamov1.KnowledgePackRef{}
		if spec.KnowledgePacks != nil {
			packs = append(packs, *spec.KnowledgePacks...)
		}
		for _, add := range *overlay.KnowledgePacks {
			i := slices.IndexFunc(packs, func(p muistamov1.KnowledgePackRef) bool { return p.Name == add.Name })
			if i >= 0 {
				packs[i] = add
			} else {
				packs = append(packs, add)
			}
		}
		merged["knowledgePacks"] = packs
	}
	if overlay.Budget != nil {
		merged["budget"] = overlay.Budget
	}
	if overlay.Assignment != nil {
		merged["assignment"] = overlay.Assignment
	}
	body, err := json.Marshal(merged)
	if err != nil {
		return spec, err
	}
	if err := contracts.ValidateAgainst("agenttemplatespec.json", body); err != nil {
		return spec, fmt.Errorf("clone %q does not merge into a valid spec: %w", clone.Metadata.Name, err)
	}
	var out muistamov1.AgentTemplateSpec
	return out, json.Unmarshal(body, &out)
}

// cloneForInstance checks a new instance's cloneRef: the clone exists, is a clone of the
// instance's template, and resolves to the instance's template version.
func cloneForInstance(ctx context.Context, tx pgx.Tx, name, template string, version int) error {
	c, err := scanClone(tx.QueryRow(ctx, cloneColumns+` WHERE name = $1`, name), name)
	if errors.Is(err, ErrNotFound) {
		return fmt.Errorf("cloneRef %q does not exist: %w", name, ErrInvalid)
	}
	if err != nil {
		return err
	}
	if c.doc.Spec.Template != template {
		return fmt.Errorf("cloneRef %q is a clone of %s, not %s: %w", name, c.doc.Spec.Template, template, ErrInvalid)
	}
	r, err := resolveClone(ctx, tx, c)
	if err != nil {
		return err
	}
	if r.version == nil || *r.version != version {
		return fmt.Errorf("clone %q resolves to %v, not version %d: %w", name, r.version, version, ErrInvalid)
	}
	return nil
}

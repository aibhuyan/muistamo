package registry

// HUMAN REVIEW REQUIRED (AGENTS.md): identity ownership, HR fencing, evidence and retention.
// This registry journal does not call Graph. The adapter must load the exact historical binding,
// verify provider ownership/creation correlation and hold the HR fence through its bounded call.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// RegisterIdentityBinding pins metadata without activating a tenant or changing any instance.
// The complete, exact historical config remains operator-controlled outside this journal.
func (s *Service) RegisterIdentityBinding(ctx context.Context, actor Actor, b muistamov1.EntraIdentityBinding) (muistamov1.IdentityBindingStatus, bool, error) {
	var out muistamov1.IdentityBindingStatus
	created := false
	body, err := json.Marshal(b)
	if err != nil || contracts.ValidateAgainst("entraidentitybinding.json", body) != nil || b.TenantId != actor.Tenant.String() {
		return out, false, fmt.Errorf("invalid Entra binding: %w", ErrInvalid)
	}
	ids := append([]string{b.TenantId, b.BindingVersion, b.EntraTenantId, b.BlueprintAppId, b.BlueprintObjectId, b.BlueprintPrincipalId}, b.SponsorUserIds...)
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil {
			return out, false, fmt.Errorf("invalid Entra binding identifier: %w", ErrInvalid)
		}
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	version := uuid.MustParse(b.BindingVersion)
	err = s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "identity-binding/"+actor.Tenant.String()); err != nil {
			return err
		}
		var err error
		out, err = identityBindingRow(ctx, tx, version)
		if err == nil {
			if out.ConfigDigest != digest {
				return fmt.Errorf("binding version is immutable: %w", ErrConflict)
			}
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		out = muistamov1.IdentityBindingStatus{TenantId: actor.Tenant, BindingVersion: version, ConfigDigest: digest, EntraTenantId: uuid.MustParse(b.EntraTenantId), BlueprintAppId: uuid.MustParse(b.BlueprintAppId)}
		if err := tx.QueryRow(ctx, `INSERT INTO entra_bindings(tenant_id,binding_version,config_digest,entra_tenant_id,blueprint_app_id) VALUES($1,$2,$3,$4,$5) RETURNING created_at`, actor.Tenant, version, digest, out.EntraTenantId, out.BlueprintAppId).Scan(&out.CreatedAt); err != nil {
			return fmt.Errorf("register identity binding: %w", err)
		}
		if err := recordEvidence(ctx, tx, s.signer, actor, "identity.binding-registered", "IdentityBinding", version.String(), nil, out); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return muistamov1.IdentityBindingStatus{}, false, err
	}
	return out, created, nil
}

func identityBindingRow(ctx context.Context, tx pgx.Tx, version uuid.UUID) (muistamov1.IdentityBindingStatus, error) {
	var out muistamov1.IdentityBindingStatus
	err := tx.QueryRow(ctx, `SELECT tenant_id,binding_version,config_digest,entra_tenant_id,blueprint_app_id,created_at FROM entra_bindings WHERE binding_version=$1`, version).Scan(&out.TenantId, &out.BindingVersion, &out.ConfigDigest, &out.EntraTenantId, &out.BlueprintAppId, &out.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}

const identityColumns = `SELECT i.tenant_id,i.id,i.instance_name,i.provider_mode,i.binding_version,b.config_digest,i.entra_tenant_id,i.assignment_receipt_id,i.provider_id,i.creation_id,i.observed_state,i.enabled_generation,i.updated_at FROM instance_identities i LEFT JOIN entra_bindings b ON b.tenant_id=i.tenant_id AND b.binding_version=i.binding_version`

func identityRow(ctx context.Context, tx pgx.Tx, name string) (muistamov1.InstanceIdentityStatus, error) {
	var out muistamov1.InstanceIdentityStatus
	err := tx.QueryRow(ctx, identityColumns+` WHERE i.instance_name=$1`, name).Scan(&out.TenantId, &out.Id, &out.InstanceName, &out.ProviderMode, &out.BindingVersion, &out.ConfigDigest, &out.EntraTenantId, &out.AssignmentReceiptId, &out.ProviderId, &out.CreationId, &out.ObservedState, &out.EnabledGeneration, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, fmt.Errorf("identity metadata missing: %w", ErrNotFound)
	}
	return out, err
}

// IdentityStatus reports last observations, not a use-time authorization decision.
func (s *Service) IdentityStatus(ctx context.Context, actor Actor, name string) (muistamov1.InstanceIdentityStatus, error) {
	var out muistamov1.InstanceIdentityStatus
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error { var err error; out, err = identityRow(ctx, tx, name); return err })
	return out, err
}

// AssertSimulated guards legacy activities before they call the original simulated provider.
func (s *Service) AssertSimulated(ctx context.Context, actor Actor, name string) error {
	status, err := s.IdentityStatus(ctx, actor, name)
	if err != nil {
		return err
	}
	if status.ProviderMode != "simulated" {
		return fmt.Errorf("legacy activity cannot mutate an Entra instance: %w", ErrConflict)
	}
	return nil
}

// identityPersonLock precedes instance/operation row locks, matching HR intake's person lock.
// Empty means no trusted live association was visible; a later live row must fail closed.
func identityPersonLock(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, name string) (string, error) {
	if err := store.LockHRPrivacy(ctx, tx, tenant, false); err != nil {
		return "", err
	}
	var person string
	err := tx.QueryRow(ctx, `SELECT h.person_id FROM instance_identities i JOIN hr_events h ON h.tenant_id=i.tenant_id AND h.receipt_id=i.assignment_receipt_id WHERE i.instance_name=$1`, name).Scan(&person)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if err := lockIdentityHRPerson(ctx, tx, tenant, person); err != nil {
		return "", err
	}
	return person, nil
}

func lockIdentityHRPerson(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, person string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant.String()+"/"+person)
	return err
}

func latestIdentityHR(ctx context.Context, tx pgx.Tx, person string) (string, int64, string, error) {
	var id, kind string
	var generation int64
	err := tx.QueryRow(ctx, `SELECT event_id,generation,type FROM hr_events WHERE person_id=$1 AND decision IN ('accepted','legacy') ORDER BY generation DESC,occurred_at DESC,(type='leaver') DESC,event_id DESC LIMIT 1`, person).Scan(&id, &generation, &kind)
	return id, generation, kind, err
}

func requireIdentityHRReceipt(ctx context.Context, tx pgx.Tx, receipt uuid.UUID) error {
	var proof bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM hr_events h JOIN evidence_events e ON e.tenant_id=h.tenant_id AND e.action='hr.event.received' AND e.subject_kind='HRPerson' AND e.subject_name=h.person_id AND e.after->>'eventId'=h.event_id AND e.after->>'type'=h.type AND e.after->>'generation'=h.generation::text AND e.after->>'decision'='accepted' WHERE h.receipt_id=$1 AND h.decision='accepted')`, receipt).Scan(&proof)
	if err != nil {
		return err
	}
	if !proof {
		return fmt.Errorf("signed HR acceptance receipt is missing: %w", ErrConflict)
	}
	return nil
}

// CreateEntraInstance establishes mode and the trusted HR association in the creation commit.
// It never reinterprets an existing simulated instance or an editable HR-person label.
func (s *Service) CreateEntraInstance(ctx context.Context, actor Actor, doc muistamov1.AgentInstance, eventID string, generation int64, version uuid.UUID) (muistamov1.AgentInstanceRecord, bool, error) {
	var rec muistamov1.AgentInstanceRecord
	created := false
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		if err := store.LockHRPrivacy(ctx, tx, actor.Tenant, false); err != nil {
			return err
		}
		binding, err := identityBindingRow(ctx, tx, version)
		if err != nil {
			return err
		}
		var receipt uuid.UUID
		var person, email, kind, decision, dispatch string
		var storedGen int64
		if err := tx.QueryRow(ctx, `SELECT receipt_id,person_id,payload->'person'->>'email',type,generation,decision,dispatch_state FROM hr_events WHERE event_id=$1`, eventID).Scan(&receipt, &person, &email, &kind, &storedGen, &decision, &dispatch); err != nil {
			return fmt.Errorf("read trusted HR assignment: %w", err)
		}
		if generation <= 0 || storedGen != generation || decision != "accepted" || kind != "joiner" || dispatch == "cancelled" || doc.Spec.Binding.Type != "user" || doc.Spec.Binding.Ref != email || doc.Spec.IdentityRef != nil {
			return fmt.Errorf("instance does not match an accepted HR joiner: %w", ErrConflict)
		}
		if err := lockIdentityHRPerson(ctx, tx, actor.Tenant, person); err != nil {
			return err
		}
		if err := requireIdentityHRReceipt(ctx, tx, receipt); err != nil {
			return err
		}
		latest, gen, kind, err := latestIdentityHR(ctx, tx, person)
		if err != nil {
			return err
		}
		if latest != eventID || gen != generation || kind != "joiner" {
			return fmt.Errorf("HR assignment is superseded: %w", ErrConflict)
		}
		current, err := lockInstance(ctx, tx, doc.Metadata.Name)
		if err == nil {
			owned, err := identityRow(ctx, tx, doc.Metadata.Name)
			if err != nil {
				return err
			}
			var originalPerson string
			if owned.AssignmentReceiptId != nil {
				if err := tx.QueryRow(ctx, `SELECT person_id FROM hr_events WHERE receipt_id=$1`, *owned.AssignmentReceiptId).Scan(&originalPerson); err != nil {
					return err
				}
			}
			if owned.ProviderMode != "entra" || owned.BindingVersion == nil || *owned.BindingVersion != version || originalPerson != person || current.Document.Spec.State == "retired" || current.Document.Spec.Binding.Ref != email || current.Document.Spec.TemplateRef != doc.Spec.TemplateRef || !equalJSON(current.Document.Spec.CloneRef, doc.Spec.CloneRef) {
				return fmt.Errorf("existing instance requires explicit provider/assignment migration: %w", ErrConflict)
			}
			rec = current
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		labels := map[string]string{}
		if doc.Metadata.Labels != nil {
			for key, value := range *doc.Metadata.Labels {
				labels[key] = value
			}
		}
		if label, ok := labels[PersonLabel]; ok && label != person {
			return fmt.Errorf("HR person label conflicts with trusted assignment: %w", ErrConflict)
		}
		labels[PersonLabel] = person
		doc.Metadata.Labels = &labels
		seed := muistamov1.InstanceIdentityStatus{TenantId: actor.Tenant, InstanceName: doc.Metadata.Name, ProviderMode: "entra", BindingVersion: &version, EntraTenantId: &binding.EntraTenantId, AssignmentReceiptId: &receipt, ObservedState: "unprovisioned"}
		rec, err = createInstanceWithIdentity(ctx, tx, s.signer, actor, doc, &seed)
		if err != nil {
			return err
		}
		owned, err := identityRow(ctx, tx, doc.Metadata.Name)
		if err != nil {
			return err
		}
		if err := recordEvidence(ctx, tx, s.signer, actor, "identity.mode-pinned", "AgentInstance", doc.Metadata.Name, nil, owned); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return muistamov1.AgentInstanceRecord{}, false, err
	}
	return rec, created, nil
}

const operationColumns = `SELECT tenant_id,id,instance_identity_id,binding_version,hr_receipt_id,hr_generation,action,attempt,state,creation_id,provider_id,candidate_id,error_code,result_evidence_seq,created_at,updated_at FROM identity_operations`

func operationRow(row pgx.Row) (muistamov1.IdentityOperationStatus, error) {
	var op muistamov1.IdentityOperationStatus
	err := row.Scan(&op.TenantId, &op.Id, &op.InstanceIdentityId, &op.BindingVersion, &op.HrReceiptId, &op.HrGeneration, &op.Action, &op.Attempt, &op.State, &op.CreationId, &op.ProviderId, &op.CandidateId, &op.ErrorCode, &op.ResultEvidenceSeq, &op.CreatedAt, &op.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return op, ErrNotFound
	}
	return op, err
}

// IdentityOperation returns scoped journal metadata without retained HR payloads.
func (s *Service) IdentityOperation(ctx context.Context, actor Actor, id uuid.UUID) (muistamov1.IdentityOperationStatus, error) {
	var op muistamov1.IdentityOperationStatus
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		var err error
		op, err = operationRow(tx.QueryRow(ctx, operationColumns+` WHERE id=$1`, id))
		return err
	})
	return op, err
}

// ReserveIdentityOperation commits signed intent. Only created=true is a first-attempt permit;
// a retry must inspect/reconcile the original operation, never blindly repeat a create.
func (s *Service) ReserveIdentityOperation(ctx context.Context, actor Actor, name, eventID string, generation int64, action muistamov1.IdentityOperationStatusAction) (muistamov1.IdentityOperationStatus, bool, error) {
	var op muistamov1.IdentityOperationStatus
	created := false
	if action != "create" && action != "enable" && action != "disable" && action != "delete" {
		return op, false, ErrInvalid
	}
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		person, err := identityPersonLock(ctx, tx, actor.Tenant, name)
		if err != nil {
			return err
		}
		instance, err := lockInstance(ctx, tx, name)
		if err != nil {
			return err
		}
		owned, err := identityRow(ctx, tx, name)
		if err != nil {
			return err
		}
		if owned.ProviderMode != "entra" || person == "" {
			return fmt.Errorf("live ownership is not established: %w", ErrConflict)
		}
		latest, gen, kind, err := latestIdentityHR(ctx, tx, person)
		if err != nil {
			return err
		}
		want := "joiner"
		if action == "disable" || action == "delete" {
			want = "leaver"
		}
		if generation <= 0 || gen != generation || latest != eventID || kind != want {
			return fmt.Errorf("identity operation HR generation is superseded: %w", ErrConflict)
		}
		if (action == "create" || action == "enable") && (instance.Document.Spec.State == "retired" || instance.Document.Spec.State == "quarantined") {
			return fmt.Errorf("instance cannot be enabled: %w", ErrConflict)
		}
		if (action == "disable" || action == "delete") && instance.Document.Spec.State != "suspended" && instance.Document.Spec.State != "retired" {
			return fmt.Errorf("suspend the instance before provider cleanup: %w", ErrConflict)
		}
		attempt := int64(1)
		prior, err := operationRow(tx.QueryRow(ctx, operationColumns+` WHERE instance_identity_id=$1 AND hr_generation=$2 AND action=$3 ORDER BY attempt DESC LIMIT 1`, owned.Id, generation, string(action)))
		if err == nil {
			if action != "disable" || prior.State != "succeeded" || owned.ObservedState == "disabled" {
				op = prior
				return nil
			}
			// A later verified enable can invalidate a completed disable. Preserve that
			// original result and reserve a distinct corrective request under the same leaver.
			attempt = prior.Attempt + 1
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		var unresolved bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1 AND state IN ('pending','indeterminate'))`, owned.Id).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved && action != "disable" {
			return fmt.Errorf("resolve outstanding provider operations first: %w", ErrConflict)
		}
		if action == "create" {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1 AND action='create')`, owned.Id).Scan(&exists); err != nil {
				return err
			}
			if exists || owned.CreationId != nil || owned.ProviderId != nil {
				return fmt.Errorf("original creation marker must be reconciled: %w", ErrConflict)
			}
		} else if owned.ProviderId == nil || owned.CreationId == nil || owned.ObservedState == "deleted" {
			return fmt.Errorf("owned identity is unavailable: %w", ErrConflict)
		}
		if action == "delete" && owned.ObservedState != "disabled" {
			return fmt.Errorf("confirmed disablement is required before deletion: %w", ErrConflict)
		}
		var receipt uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT receipt_id FROM hr_events WHERE event_id=$1 AND decision='accepted' AND generation=$2`, eventID, generation).Scan(&receipt); err != nil {
			return err
		}
		if err := requireIdentityHRReceipt(ctx, tx, receipt); err != nil {
			return err
		}
		op = muistamov1.IdentityOperationStatus{TenantId: actor.Tenant, Id: uuid.New(), InstanceIdentityId: owned.Id, BindingVersion: *owned.BindingVersion, HrReceiptId: receipt, HrGeneration: generation, Action: action, Attempt: attempt, State: "pending", ProviderId: owned.ProviderId}
		if action == "create" {
			op.CreationId = op.Id
			if _, err := tx.Exec(ctx, `UPDATE instance_identities SET creation_id=$2,updated_at=now() WHERE id=$1`, owned.Id, op.Id); err != nil {
				return err
			}
		} else {
			op.CreationId = *owned.CreationId
		}
		if err := tx.QueryRow(ctx, `INSERT INTO identity_operations(tenant_id,id,instance_identity_id,binding_version,hr_receipt_id,hr_generation,action,creation_id,provider_id,attempt) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING created_at,updated_at`, actor.Tenant, op.Id, owned.Id, op.BindingVersion, receipt, generation, string(action), op.CreationId, op.ProviderId, attempt).Scan(&op.CreatedAt, &op.UpdatedAt); err != nil {
			return identityWriteError(err)
		}
		if err := recordEvidence(ctx, tx, s.signer, actor, "identity.operation.intent", "IdentityOperation", op.Id.String(), nil, op); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return muistamov1.IdentityOperationStatus{}, false, err
	}
	return op, created, nil
}

func identityWriteError(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return fmt.Errorf("identity ownership or operation already reserved: %w", ErrConflict)
	}
	return fmt.Errorf("persist identity state: %w", err)
}

func operationInstance(ctx context.Context, tx pgx.Tx, id uuid.UUID) (string, error) {
	var name string
	err := tx.QueryRow(ctx, `SELECT i.instance_name FROM identity_operations o JOIN instance_identities i ON i.tenant_id=o.tenant_id AND i.id=o.instance_identity_id WHERE o.id=$1`, id).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return name, err
}

// MarkIdentityIndeterminate retains uncertainty without exposing transport/provider text.
func (s *Service) MarkIdentityIndeterminate(ctx context.Context, actor Actor, id uuid.UUID, code muistamov1.IdentityOperationStatusErrorCode) error {
	if code != "uncertain" && code != "provider_unavailable" && code != "ownership_unproved" && code != "generation_superseded" && code != "provider_refused" {
		return ErrInvalid
	}
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		name, err := operationInstance(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := identityPersonLock(ctx, tx, actor.Tenant, name); err != nil {
			return err
		}
		if _, err := lockInstance(ctx, tx, name); err != nil {
			return err
		}
		op, err := operationRow(tx.QueryRow(ctx, operationColumns+` WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if op.State != "pending" && op.State != "indeterminate" {
			return ErrConflict
		}
		if op.State == "indeterminate" && op.ErrorCode != nil && *op.ErrorCode == code {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE identity_operations SET state='indeterminate',error_code=$2,updated_at=now() WHERE id=$1`, id, string(code)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE instance_identities SET observed_state='reconciliation_required',updated_at=now() WHERE id=$1`, op.InstanceIdentityId); err != nil {
			return err
		}
		return recordEvidence(ctx, tx, s.signer, actor, "identity.operation.indeterminate", "IdentityOperation", id.String(), nil, map[string]any{"errorCode": code, "generation": op.HrGeneration})
	})
}

// CommitIdentityResult is for a verified adapter observation, never an operator-supplied ID.
// The adapter must verify the exact original create marker, blueprint and identity type first.
func (s *Service) CommitIdentityResult(ctx context.Context, actor Actor, id, creationID, providerID uuid.UUID, observed muistamov1.InstanceIdentityStatusObservedState) error {
	if creationID == uuid.Nil || providerID == uuid.Nil {
		return ErrInvalid
	}
	return s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		name, err := operationInstance(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := identityPersonLock(ctx, tx, actor.Tenant, name); err != nil {
			return err
		}
		current, err := lockInstance(ctx, tx, name)
		if err != nil {
			return err
		}
		owned, err := identityRow(ctx, tx, name)
		if err != nil {
			return err
		}
		op, err := operationRow(tx.QueryRow(ctx, operationColumns+` WHERE id=$1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		want := muistamov1.InstanceIdentityStatusObservedState("disabled")
		if op.Action == "enable" {
			want = "enabled"
		}
		if op.Action == "delete" {
			want = "deleted"
		}
		if owned.ProviderMode != "entra" || op.CreationId != creationID || owned.CreationId == nil || *owned.CreationId != creationID || observed != want || (owned.ProviderId != nil && *owned.ProviderId != providerID) {
			return fmt.Errorf("provider result does not match the original operation: %w", ErrConflict)
		}
		if op.State == "succeeded" {
			if op.ProviderId != nil && *op.ProviderId == providerID {
				return nil
			}
			return ErrConflict
		}
		if op.State != "pending" && op.State != "indeterminate" {
			return ErrConflict
		}
		var other bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1 AND id<>$2 AND state IN ('pending','indeterminate'))`, owned.Id, id).Scan(&other); err != nil {
			return err
		}
		// A successful best-effort disable cannot settle a different late enable/delete.
		state := observed
		if other {
			state = "reconciliation_required"
		}
		var enabledGeneration *int64
		if observed == "enabled" {
			enabledGeneration = &op.HrGeneration
		}
		if _, err := tx.Exec(ctx, `UPDATE instance_identities SET provider_id=$2,observed_state=$3,enabled_generation=$4,updated_at=now() WHERE id=$1`, owned.Id, providerID, string(state), enabledGeneration); err != nil {
			return identityWriteError(err)
		}
		if op.Action == "create" {
			ref := "entra:" + providerID.String()
			if current.Document.Spec.IdentityRef != nil && *current.Document.Spec.IdentityRef != ref {
				return ErrConflict
			}
			next := current.Document
			next.Spec.IdentityRef = &ref
			if _, err := updateInstance(ctx, tx, current, next); err != nil {
				return err
			}
		}
		entry, err := evidence.Append(ctx, tx, s.signer, evidence.Entry{Tenant: actor.Tenant, Actor: actor.Name, RequestID: actor.RequestID, Action: "identity.operation.succeeded", SubjectKind: "IdentityOperation", SubjectName: id.String(), After: map[string]any{"action": op.Action, "providerId": providerID, "creationId": creationID, "observedState": observed, "ownershipState": state, "generation": op.HrGeneration, "bindingVersion": op.BindingVersion}})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE identity_operations SET state='succeeded',provider_id=$2,error_code=NULL,result_evidence_seq=$3,updated_at=now() WHERE id=$1`, id, providerID, entry.Seq)
		return err
	})
}

func checkIdentityTransition(ctx context.Context, tx pgx.Tx, current muistamov1.AgentInstanceRecord, to muistamov1.InstanceState, lockedPerson string) error {
	owned, err := identityRow(ctx, tx, current.Document.Metadata.Name)
	if err != nil {
		return err
	}
	if owned.ProviderMode == "simulated" {
		return nil
	}
	if to != "active" && to != "retired" {
		return nil
	}
	if lockedPerson == "" {
		return fmt.Errorf("identity association changed; retry: %w", ErrConflict)
	}
	var pending bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations WHERE instance_identity_id=$1 AND state IN ('pending','indeterminate'))`, owned.Id).Scan(&pending); err != nil {
		return err
	}
	if pending {
		return fmt.Errorf("identity reconciliation is outstanding: %w", ErrConflict)
	}
	if to == "retired" {
		if owned.ObservedState != "deleted" || owned.ProviderId == nil {
			return fmt.Errorf("provider cleanup is incomplete: %w", ErrConflict)
		}
		var proof bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations o JOIN evidence_events e ON e.tenant_id=o.tenant_id AND e.seq=o.result_evidence_seq WHERE o.instance_identity_id=$1 AND o.binding_version=$2 AND o.provider_id=$3 AND o.action='delete' AND o.state='succeeded' AND e.action='identity.operation.succeeded' AND e.subject_kind='IdentityOperation' AND e.subject_name=o.id::text AND e.after->>'providerId'=o.provider_id::text AND e.after->>'creationId'=o.creation_id::text AND e.after->>'observedState'='deleted')`, owned.Id, *owned.BindingVersion, *owned.ProviderId).Scan(&proof); err != nil {
			return err
		}
		if !proof {
			return fmt.Errorf("verified provider deletion evidence is missing: %w", ErrConflict)
		}
		return nil
	}
	_, generation, kind, err := latestIdentityHR(ctx, tx, lockedPerson)
	if err != nil {
		return err
	}
	if kind != "joiner" || owned.ObservedState != "enabled" || owned.EnabledGeneration == nil || *owned.EnabledGeneration != generation || owned.ProviderId == nil {
		return fmt.Errorf("identity is not ready for the current HR generation: %w", ErrConflict)
	}
	var proof bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_operations o JOIN evidence_events e ON e.tenant_id=o.tenant_id AND e.seq=o.result_evidence_seq WHERE o.instance_identity_id=$1 AND o.binding_version=$2 AND o.provider_id=$3 AND o.action='enable' AND o.state='succeeded' AND o.hr_generation=$4 AND e.action='identity.operation.succeeded' AND e.subject_kind='IdentityOperation' AND e.subject_name=o.id::text)`, owned.Id, *owned.BindingVersion, *owned.ProviderId, generation).Scan(&proof)
	if err != nil {
		return err
	}
	if !proof {
		return fmt.Errorf("verified identity result evidence is missing: %w", ErrConflict)
	}
	return nil
}

func (s *Service) checkSameIdentityState(ctx context.Context, actor Actor, name string, to muistamov1.InstanceState) (muistamov1.AgentInstanceRecord, error) {
	var rec muistamov1.AgentInstanceRecord
	err := s.db.InTenant(ctx, actor.Tenant, func(tx pgx.Tx) error {
		person, err := identityPersonLock(ctx, tx, actor.Tenant, name)
		if err != nil {
			return err
		}
		rec, err = lockInstance(ctx, tx, name)
		if err != nil {
			return err
		}
		if rec.Document.Spec.State != to {
			return ErrPrecondition
		}
		return checkIdentityTransition(ctx, tx, rec, to, person)
	})
	return rec, err
}

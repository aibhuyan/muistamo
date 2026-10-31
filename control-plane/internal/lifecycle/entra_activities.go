package lifecycle

// HUMAN REVIEW REQUIRED: live identity lifecycle, revocation coverage and HR authorization.
import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"go.temporal.io/sdk/temporal"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// IdentityAdapter executes only the journal protocol, never the legacy Provisioner seam.
type IdentityAdapter interface {
	Apply(context.Context, registry.Actor, string, string, int64, muistamov1.IdentityOperationStatusAction) (muistamov1.IdentityOperationStatus, error)
	Reconcile(context.Context, registry.Actor, uuid.UUID) (muistamov1.IdentityOperationStatus, error)
}

// UserDirectory finds a person's Entra user (docs/obo-retrieval-plan.md, PR A).
type UserDirectory interface {
	LookupUser(context.Context, registry.Actor, uuid.UUID, string) (registry.EntraUserMatch, error)
}

type EntraActivities struct {
	Registry *registry.Service
	Identity IdentityAdapter
	Revoker  Revoker
	Users    UserDirectory
}

func liveActor(ref muistamov1.EntraLifecycleRef) registry.Actor {
	return registry.Actor{Tenant: ref.TenantId, Name: "workflow:entra:" + ref.ReceiptId.String(), RequestID: "hr-receipt:" + ref.ReceiptId.String()}
}

func liveError(err error) error {
	if errors.Is(err, registry.ErrConflict) || errors.Is(err, registry.ErrNotFound) || errors.Is(err, registry.ErrInvalid) {
		return temporal.NewNonRetryableApplicationError("live lifecycle scope refused", "scope-refused", err)
	}
	return err
}

func (a *EntraActivities) EntraEventKind(ctx context.Context, ref muistamov1.EntraLifecycleRef) (string, error) {
	e, _, _, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, false)
	return string(e.Type), liveError(err)
}

func (a *EntraActivities) EntraPriorLeavers(ctx context.Context, ref muistamov1.EntraLifecycleRef) ([]string, error) {
	ids, err := a.Registry.PriorEntraLeavers(ctx, liveActor(ref), ref.ReceiptId)
	return ids, liveError(err)
}

func (a *EntraActivities) EntraMatchTemplates(ctx context.Context, ref muistamov1.EntraLifecycleRef) ([]registry.TemplateVersionRef, error) {
	e, _, _, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, true)
	if err != nil {
		return nil, liveError(err)
	}
	if e.Type != "joiner" {
		return nil, liveError(registry.ErrConflict)
	}
	return a.Registry.MatchTemplatesByJobCode(ctx, liveActor(ref), e.Person.JobCode)
}

// EntraLinkUser records which Entra user the joiner's person is: the one user whose employeeId
// is the HR person id. A definite provider refusal is evidenced and not retried; the person then
// stays unlinked and knowledge retrieval refuses for them until a later joiner links them.
func (a *EntraActivities) EntraLinkUser(ctx context.Context, ref muistamov1.EntraLifecycleRef) error {
	if a.Users == nil {
		return temporal.NewNonRetryableApplicationError("Entra user directory unavailable", "unconfigured", nil)
	}
	e, route, _, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, true)
	if err != nil {
		return liveError(err)
	}
	if e.Type != "joiner" || route.BindingVersion == nil {
		return liveError(registry.ErrConflict)
	}
	match, err := a.Users.LookupUser(ctx, liveActor(ref), *route.BindingVersion, e.Person.Id)
	var refusal *registry.ProviderRefusal
	if errors.As(err, &refusal) {
		if err := a.Registry.RecordEntraUserLookupFailure(ctx, liveActor(ref), ref.ReceiptId, refusal.Code); err != nil {
			return liveError(err)
		}
		return temporal.NewNonRetryableApplicationError("Entra user lookup refused", "lookup-refused", refusal)
	}
	if err != nil {
		return liveError(err)
	}
	_, err = a.Registry.RecordEntraUserLink(ctx, liveActor(ref), ref.ReceiptId, match.Status, match.ObjectID)
	return liveError(err)
}

// EntraUnlinkUser records that the joiner could not look the person's user up, replacing any
// earlier link. It needs no provider call; after a refusal EntraLinkUser has already recorded it.
func (a *EntraActivities) EntraUnlinkUser(ctx context.Context, ref muistamov1.EntraLifecycleRef) error {
	return liveError(a.Registry.RecordEntraUserLookupFailure(ctx, liveActor(ref), ref.ReceiptId, "lookup-failed"))
}

func (a *EntraActivities) EntraEnsureInstance(ctx context.Context, ref muistamov1.EntraLifecycleRef, template registry.TemplateVersionRef) (string, error) {
	e, route, generation, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, true)
	if err != nil {
		return "", liveError(err)
	}
	if e.Type != "joiner" || route.BindingVersion == nil {
		return "", liveError(registry.ErrConflict)
	}
	person := Person{ID: e.Person.Id, Email: e.Person.Email, JobCode: e.Person.JobCode}
	base := template.Name
	if template.Clone != "" {
		base = template.Clone
	}
	for attempt := 1; attempt <= 9; attempt++ {
		name := InstanceName(base, person.ID, attempt)
		prior, err := a.Registry.GetInstance(ctx, liveActor(ref), name)
		if err == nil && (prior.Document.Spec.State == "retired" || !sameAgent(prior.Document, template)) {
			continue
		}
		if err != nil && !errors.Is(err, registry.ErrNotFound) {
			return "", err
		}
		if err == nil {
			owned, err := a.Registry.IdentityStatus(ctx, liveActor(ref), name)
			if err != nil {
				return "", err
			}
			if owned.ObservedState == "deleted" {
				continue
			}
		}
		_, _, err = a.Registry.CreateEntraInstance(ctx, liveActor(ref), newInstance(name, template, person), e.Id, generation, *route.BindingVersion)
		return name, liveError(err)
	}
	return "", temporal.NewNonRetryableApplicationError("too many retired instances", "exhausted", nil)
}

func (a *EntraActivities) mutate(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string, action muistamov1.IdentityOperationStatusAction) error {
	if a.Identity == nil {
		return temporal.NewNonRetryableApplicationError("live identity configuration unavailable", "unconfigured", nil)
	}
	e, _, generation, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, true)
	if err != nil {
		return liveError(err)
	}
	_, err = a.Identity.Apply(ctx, liveActor(ref), name, e.Id, generation, action)
	return liveError(err)
}

func (a *EntraActivities) EntraCreate(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string) error {
	_, route, _, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, true)
	if err != nil {
		return liveError(err)
	}
	owned, err := a.Registry.IdentityStatus(ctx, liveActor(ref), name)
	if err != nil {
		return err
	}
	if owned.CreationId != nil {
		if a.Identity == nil {
			return temporal.NewNonRetryableApplicationError("live identity configuration unavailable", "unconfigured", nil)
		}
		op, err := a.Identity.Reconcile(ctx, liveActor(ref), *owned.CreationId)
		if err != nil {
			return liveError(err)
		}
		settled, clear, err := a.Registry.SettledIdentityObservation(ctx, liveActor(ref), *owned.CreationId)
		if err != nil {
			return err
		}
		if !clear || op.Action != "create" || op.State != "succeeded" || op.ProviderId == nil || settled.ProviderId == nil || *op.ProviderId != *settled.ProviderId || settled.BindingVersion == nil || route.BindingVersion == nil || *settled.BindingVersion != *route.BindingVersion {
			return liveError(registry.ErrConflict)
		}
		return nil
	}
	return a.mutate(ctx, ref, name, "create")
}
func (a *EntraActivities) EntraEnable(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string) error {
	return a.mutate(ctx, ref, name, "enable")
}
func (a *EntraActivities) EntraDisable(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string) error {
	absent, err := a.Registry.ConfirmEntraNoIdentity(ctx, liveActor(ref), ref.ReceiptId, name)
	if err != nil {
		return liveError(err)
	}
	if absent {
		return nil
	}
	return a.mutate(ctx, ref, name, "disable")
}
func (a *EntraActivities) EntraActivate(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string) error {
	return liveError(a.Registry.SetEntraState(ctx, liveActor(ref), ref.ReceiptId, name, "active"))
}

func (a *EntraActivities) EntraPrepareLeaver(ctx context.Context, ref muistamov1.EntraLifecycleRef) ([]string, error) {
	names, err := a.Registry.SuspendEntraPerson(ctx, liveActor(ref), ref.ReceiptId)
	return names, liveError(err)
}

func (a *EntraActivities) EntraRevoke(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string) error {
	e, _, _, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, true)
	if err != nil {
		return liveError(err)
	}
	if e.Type != "leaver" {
		return liveError(registry.ErrConflict)
	}
	if a.Revoker == nil {
		return temporal.NewNonRetryableApplicationError("gateway revocation unavailable", "unconfigured", nil)
	}
	report, err := a.Revoker.Revoke(ctx, liveActor(ref), name)
	if err != nil {
		// A refusal (for example an instance that is not suspended) is permanent: fail fast.
		return liveError(fmt.Errorf("revoke instance credentials: %w", err))
	}
	return a.Registry.RecordLifecycleEvent(ctx, liveActor(ref), "credentials.revoked", name, report.evidence())
}

func (a *EntraActivities) EntraRecordReviewCoverage(ctx context.Context, ref muistamov1.EntraLifecycleRef) error {
	e, _, _, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(ref), ref.ReceiptId, false)
	if err != nil {
		return liveError(err)
	}
	return a.Registry.RecordPersonEvent(ctx, liveActor(ref), "personal-layer.review-not-opened", e.Person.Id, map[string]any{"reason": "live knowledge review requires a generation-aware ordering protocol; not implemented", "coverage": "not-integrated"})
}

func (a *EntraActivities) EntraSettleSetup(ctx context.Context, ref muistamov1.EntraLifecycleRef) error {
	return liveError(a.Registry.SettleEntraSetup(ctx, liveActor(ref), ref.ReceiptId))
}

func (a *EntraActivities) EntraConfirmRehire(ctx context.Context, oldRef, newRef muistamov1.EntraLifecycleRef) error {
	if oldRef.TenantId != newRef.TenantId {
		return liveError(registry.ErrConflict)
	}
	old, _, oldGeneration, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(oldRef), oldRef.ReceiptId, false)
	if err != nil {
		return liveError(err)
	}
	current, _, generation, err := a.Registry.ResolveEntraReceipt(ctx, liveActor(newRef), newRef.ReceiptId, true)
	if err != nil {
		return liveError(err)
	}
	if old.Type != "leaver" || current.Type != "joiner" || old.Person.Id != current.Person.Id || generation <= oldGeneration {
		return liveError(registry.ErrConflict)
	}
	return a.Registry.RecordPersonEvent(ctx, liveActor(newRef), "identity.leaver.rehire-confirmed", current.Person.Id, map[string]any{"leaverReceiptId": oldRef.ReceiptId, "joinerReceiptId": newRef.ReceiptId, "generation": generation})
}

func (a *EntraActivities) EntraRetire(ctx context.Context, ref muistamov1.EntraLifecycleRef, name string) error {
	owned, err := a.Registry.IdentityStatus(ctx, liveActor(ref), name)
	if err != nil {
		return err
	}
	if owned.ObservedState == "deleted" {
		return liveError(a.Registry.SetEntraState(ctx, liveActor(ref), ref.ReceiptId, name, "retired"))
	}
	absent, err := a.Registry.ConfirmEntraNoIdentity(ctx, liveActor(ref), ref.ReceiptId, name)
	if err != nil {
		return liveError(err)
	}
	if absent {
		return liveError(a.Registry.SetEntraState(ctx, liveActor(ref), ref.ReceiptId, name, "retired"))
	}
	if err := a.mutate(ctx, ref, name, "disable"); err != nil {
		return err
	}
	if err := a.mutate(ctx, ref, name, "delete"); err != nil {
		return err
	}
	return liveError(a.Registry.SetEntraState(ctx, liveActor(ref), ref.ReceiptId, name, "retired"))
}

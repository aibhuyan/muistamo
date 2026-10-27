package entra

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// Adapter joins the fixed-host provider primitive to the durable registry protocol. It is not
// the legacy Provisioner: old activity names must continue using their simulated implementation.
type Adapter struct {
	registry *registry.Service
	clients  map[uuid.UUID]*Client
}

// NewAdapter loads explicit historical clients. Missing versions never use a current/default
// client, and the full immutable configuration digest is checked before resolving a credential.
func NewAdapter(service *registry.Service, clients ...*Client) (*Adapter, error) {
	if service == nil {
		return nil, ErrConfiguration
	}
	a := &Adapter{registry: service, clients: map[uuid.UUID]*Client{}}
	for _, client := range clients {
		if client == nil {
			return nil, ErrConfiguration
		}
		version, ok := canonicalID(client.binding.BindingVersion)
		if !ok || a.clients[version] != nil {
			return nil, ErrConfiguration
		}
		a.clients[version] = client
	}
	return a, nil
}

func (a *Adapter) clientFor(actor registry.Actor, owned muistamov1.InstanceIdentityStatus) (*Client, error) {
	if owned.TenantId != actor.Tenant || owned.ProviderMode != "entra" || owned.BindingVersion == nil || owned.ConfigDigest == nil {
		return nil, ErrConfiguration
	}
	c := a.clients[*owned.BindingVersion]
	if c == nil || c.binding.TenantId != actor.Tenant.String() {
		return nil, ErrConfiguration
	}
	raw, err := json.Marshal(c.binding)
	if err != nil {
		return nil, ErrConfiguration
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != *owned.ConfigDigest {
		return nil, ErrConfiguration
	}
	return c, nil
}

// Apply performs a mutation only in the registry's fresh-intent callback. Every later invocation
// is read-only reconciliation. One deadline bounds token acquisition, inspection and polling.
func (a *Adapter) Apply(ctx context.Context, actor registry.Actor, name, eventID string, generation int64, action muistamov1.IdentityOperationStatusAction) (muistamov1.IdentityOperationStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	owned, err := a.registry.IdentityStatus(ctx, actor, name)
	if err != nil {
		return muistamov1.IdentityOperationStatus{}, err
	}
	if _, err := a.clientFor(actor, owned); err != nil {
		return muistamov1.IdentityOperationStatus{}, err
	}
	var observation Identity
	op, called, err := a.registry.RunIdentityMutation(ctx, actor, name, eventID, generation, action, func(ctx context.Context, op muistamov1.IdentityOperationStatus, owned muistamov1.InstanceIdentityStatus) (uuid.UUID, muistamov1.InstanceIdentityStatusObservedState, error) {
		c, err := a.clientFor(actor, owned)
		if err != nil {
			return uuid.Nil, "", err
		}
		if owned.BindingVersion == nil || op.BindingVersion != *owned.BindingVersion {
			return uuid.Nil, "", ErrConfiguration
		}
		state := muistamov1.InstanceIdentityStatusObservedState("disabled")
		if action == "create" {
			observation, err = c.CreateDisabled(ctx, actor.Tenant, op.CreationId)
		} else {
			if owned.ProviderId == nil || owned.CreationId == nil {
				return uuid.Nil, "", ErrOwnership
			}
			ref := Reference{ID: *owned.ProviderId, CreationID: *owned.CreationId}
			if action == "delete" {
				err = c.Delete(ctx, actor.Tenant, ref, op.Id)
				observation = Identity{Ref: ref}
				state = "deleted"
			} else {
				observation, err = c.SetEnabled(ctx, actor.Tenant, ref, action == "enable", op.Id)
				if action == "enable" {
					state = "enabled"
				}
			}
		}
		return observation.Ref.ID, state, err
	})
	if err != nil {
		if op.Id == uuid.Nil {
			return op, err
		}
		if op.Id != uuid.Nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			var candidates []uuid.UUID
			if op.Action == "create" && observation.Ref.ID != uuid.Nil {
				candidates = append(candidates, observation.Ref.ID)
			}
			if recordErr := a.registry.MarkIdentityIndeterminate(cleanup, actor, op.Id, "uncertain", candidates...); recordErr != nil {
				return op, fmt.Errorf("record provider uncertainty: %w: %w", ErrUncertain, recordErr)
			}
		}
		return op, fmt.Errorf("provider effect or result persistence is unresolved: %w", ErrUncertain)
	}
	if !called {
		if op.State == "succeeded" {
			return a.confirmGlobalState(ctx, actor, op)
		}
		if op.Action == "create" {
			return a.Reconcile(ctx, actor, op.Id)
		}
		return op, ErrUncertain
	}
	return a.confirmGlobalState(ctx, actor, op)
}

func (a *Adapter) confirmGlobalState(ctx context.Context, actor registry.Actor, op muistamov1.IdentityOperationStatus) (muistamov1.IdentityOperationStatus, error) {
	owned, settled, err := a.registry.SettledIdentityObservation(ctx, actor, op.Id)
	if err != nil {
		return op, err
	}
	if !settled || owned.ObservedState == "reconciliation_required" || owned.ProviderId == nil || op.ProviderId == nil || *owned.ProviderId != *op.ProviderId {
		return op, ErrUncertain
	}
	want := muistamov1.InstanceIdentityStatusObservedState("disabled")
	if op.Action == "enable" {
		want = "enabled"
	}
	if op.Action == "delete" {
		want = "deleted"
	}
	if op.Action == "create" {
		if owned.ObservedState != "disabled" && owned.ObservedState != "enabled" {
			return op, ErrUncertain
		}
	} else if owned.ObservedState != want {
		return op, ErrUncertain
	}
	if op.Action == "enable" && (owned.EnabledGeneration == nil || *owned.EnabledGeneration != op.HrGeneration) {
		return op, ErrUncertain
	}
	return op, nil
}

// Reconcile recovers creation only through a complete scoped provider match and direct owned
// disabled observation. Current state cannot prove an uncertain PATCH/DELETE request ended;
// those operations remain pending for documented administrator reconciliation, never guessed.
func (a *Adapter) Reconcile(ctx context.Context, actor registry.Actor, id uuid.UUID) (muistamov1.IdentityOperationStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	op, err := a.registry.IdentityOperation(ctx, actor, id)
	if err != nil {
		return op, err
	}
	owned, err := a.registry.IdentityForOperation(ctx, actor, id)
	if err != nil {
		return op, err
	}
	c, err := a.clientFor(actor, owned)
	if err != nil {
		return op, err
	}
	if owned.BindingVersion == nil || op.BindingVersion != *owned.BindingVersion {
		return op, ErrConfiguration
	}
	if op.State == "succeeded" {
		return a.confirmGlobalState(ctx, actor, op)
	}
	if op.Action != "create" || (op.State != "pending" && op.State != "indeterminate") {
		return op, ErrUncertain
	}
	observation, err := c.FindCreated(ctx, actor.Tenant, op.CreationId)
	if err != nil || observation.Enabled {
		return op, ErrUncertain
	}
	if op.CandidateId != nil && *op.CandidateId != observation.Ref.ID {
		return op, ErrUncertain
	}
	if err := a.registry.CommitIdentityResult(ctx, actor, op.Id, op.CreationId, observation.Ref.ID, "disabled"); err != nil {
		return op, err
	}
	stored, err := a.registry.IdentityOperation(ctx, actor, id)
	if err != nil {
		return op, err
	}
	return a.confirmGlobalState(ctx, actor, stored)
}

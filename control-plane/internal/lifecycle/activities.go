package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"go.temporal.io/sdk/temporal"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// Person is the HR person a workflow acts on.
type Person struct {
	ID      string
	Email   string
	JobCode string
}

// Scope identifies who and what a workflow step acts for. It is carried from the HR event into
// every activity so evidence names the triggering event.
type Scope struct {
	Tenant     uuid.UUID
	WorkflowID string
	EventID    string
}

func (s Scope) actor() registry.Actor {
	return registry.Actor{Tenant: s.Tenant, Name: "workflow:" + s.WorkflowID, RequestID: "hr-event:" + s.EventID}
}

// Activities are the side-effecting steps of the lifecycle workflows. Each is idempotent.
type Activities struct {
	Registry    *registry.Service
	Provisioner Provisioner
	Revoker     Revoker
}

// MatchTemplates returns the templates assigned to the person's job code.
func (a *Activities) MatchTemplates(ctx context.Context, scope Scope, jobCode string) ([]registry.TemplateVersionRef, error) {
	return a.Registry.MatchTemplatesByJobCode(ctx, scope.actor(), jobCode)
}

// EnsureInstance creates the person's instance of a template, or returns the existing one. A
// retired earlier instance is left alone and a new name is used.
func (a *Activities) EnsureInstance(ctx context.Context, scope Scope, template registry.TemplateVersionRef, person Person) (string, error) {
	actor := scope.actor()
	for attempt := 1; attempt <= 9; attempt++ {
		name := InstanceName(template.Name, person.ID, attempt)
		existing, err := a.Registry.GetInstance(ctx, actor, name)
		switch {
		case err == nil && existing.Document.Spec.State == muistamov1.InstanceStateRetired:
			continue
		case err == nil:
			return name, nil
		case !errors.Is(err, registry.ErrNotFound):
			return "", err
		}
		doc := newInstance(name, template, person)
		body, err := json.Marshal(doc)
		if err != nil {
			return "", err
		}
		if err := contracts.Validate(body); err != nil {
			return "", temporal.NewNonRetryableApplicationError("instance document invalid", "invalid", err)
		}
		if _, _, err := a.Registry.ApplyInstance(ctx, actor, doc, ""); err != nil {
			return "", err
		}
		return name, nil
	}
	return "", temporal.NewNonRetryableApplicationError(
		fmt.Sprintf("person %s has too many retired instances of %s", person.ID, template.Name), "exhausted", nil)
}

// ProvisionIdentity creates the instance's identity and records its id.
func (a *Activities) ProvisionIdentity(ctx context.Context, scope Scope, instance string, person Person) error {
	ref, err := a.Provisioner.Provision(ctx, scope.Tenant, instance, person.Email)
	if err != nil {
		return fmt.Errorf("provision identity for %s: %w", instance, err)
	}
	_, err = a.Registry.SetIdentityRef(ctx, scope.actor(), instance, ref)
	return err
}

// SetState moves an instance to a state, doing nothing if it is already there.
func (a *Activities) SetState(ctx context.Context, scope Scope, instance string, to muistamov1.InstanceState) error {
	_, err := a.Registry.TransitionTo(ctx, scope.actor(), instance, to)
	if errors.Is(err, registry.ErrConflict) {
		return temporal.NewNonRetryableApplicationError(err.Error(), "illegal-transition", err)
	}
	return err
}

// PersonInstances lists the person's instances that are not retired.
func (a *Activities) PersonInstances(ctx context.Context, scope Scope, personID string) ([]string, error) {
	recs, err := a.Registry.InstancesForPerson(ctx, scope.actor(), personID)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, rec := range recs {
		if rec.Document.Spec.State != muistamov1.InstanceStateRetired {
			names = append(names, rec.Document.Metadata.Name)
		}
	}
	return names, nil
}

// RevokeCredentials revokes an instance's credentials and records that it did.
func (a *Activities) RevokeCredentials(ctx context.Context, scope Scope, instance string) error {
	if err := a.Revoker.Revoke(ctx, scope.Tenant, instance); err != nil {
		return fmt.Errorf("revoke credentials of %s: %w", instance, err)
	}
	return a.Registry.RecordLifecycleEvent(ctx, scope.actor(), "credentials.revoked", instance,
		map[string]any{"revoker": revokerName(a.Revoker)})
}

// SetIdentityEnabled disables or re-enables the instance's identity and records it.
func (a *Activities) SetIdentityEnabled(ctx context.Context, scope Scope, instance string, enabled bool) error {
	rec, err := a.Registry.GetInstance(ctx, scope.actor(), instance)
	if err != nil {
		return err
	}
	if rec.Document.Spec.IdentityRef == nil {
		return a.Registry.RecordLifecycleEvent(ctx, scope.actor(), "identity.skipped", instance,
			map[string]any{"reason": "instance has no identity", "enabled": enabled})
	}
	ref := *rec.Document.Spec.IdentityRef
	action := "identity.disabled"
	if enabled {
		action = "identity.enabled"
		err = a.Provisioner.Enable(ctx, scope.Tenant, ref)
	} else {
		err = a.Provisioner.Disable(ctx, scope.Tenant, ref)
	}
	if err != nil {
		return fmt.Errorf("%s for %s: %w", action, instance, err)
	}
	return a.Registry.RecordLifecycleEvent(ctx, scope.actor(), action, instance, map[string]any{"identityRef": ref})
}

// RecordPersonalLayerDecision records the leaver's personal-layer step (E4.2). Knowledge layers
// do not exist yet, so the record says so rather than the step being skipped silently.
func (a *Activities) RecordPersonalLayerDecision(ctx context.Context, scope Scope, instance string) error {
	return a.Registry.RecordLifecycleEvent(ctx, scope.actor(), "personal-layer.decision", instance,
		map[string]any{"decision": "none", "reason": "no personal knowledge layer exists yet"})
}

func newInstance(name string, template registry.TemplateVersionRef, person Person) muistamov1.AgentInstance {
	var doc muistamov1.AgentInstance
	doc.ApiVersion = muistamov1.AgentInstanceApiVersionMuistamoDevv1
	doc.Kind = muistamov1.AgentInstanceKindAgentInstance
	doc.Metadata.Name = name
	labels := map[string]string{registry.PersonLabel: person.ID}
	doc.Metadata.Labels = &labels
	doc.Spec.TemplateRef.Name = template.Name
	doc.Spec.TemplateRef.Version = strconv.Itoa(template.Version)
	doc.Spec.Binding.Type = muistamov1.AgentInstanceSpecBindingTypeUser
	doc.Spec.Binding.Ref = person.Email
	doc.Spec.State = muistamov1.InstanceStateRequested
	return doc
}

func revokerName(r Revoker) string {
	if _, ok := r.(*Simulated); ok {
		return "simulated (no credentials exist until the gateway, D28)"
	}
	return fmt.Sprintf("%T", r)
}

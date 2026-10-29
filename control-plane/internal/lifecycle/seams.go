package lifecycle

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// Provisioner manages an instance's identity in the tenant's identity provider. Every method
// must be idempotent: activities retry, so a call can repeat after it already succeeded.
type Provisioner interface {
	// Provision creates (or finds) the identity for an instance and returns its id.
	Provision(ctx context.Context, tenant uuid.UUID, instance, personEmail string) (identityRef string, err error)
	Disable(ctx context.Context, tenant uuid.UUID, identityRef string) error
	Enable(ctx context.Context, tenant uuid.UUID, identityRef string) error
}

// Revoker revokes an instance's credentials (virtual keys, tokens). Must be idempotent. The actor
// is the lifecycle workflow, so evidence names it.
type Revoker interface {
	Revoke(ctx context.Context, actor registry.Actor, instance string) (RevocationReport, error)
}

// RevocationReport says what one Revoke call did. VirtualKeys lists the keys this call revoked;
// a retry after success revokes none, and each revocation has its own gateway.key.revoked event.
type RevocationReport struct {
	Simulated   bool
	VirtualKeys []uuid.UUID
}

// evidence is the credentials.revoked payload. It never presents simulation as revocation.
func (r RevocationReport) evidence() map[string]any {
	if r.Simulated {
		return map[string]any{"revoker": "simulated (no credentials revoked)", "simulated": true}
	}
	ids := make([]string, len(r.VirtualKeys))
	for i, id := range r.VirtualKeys {
		ids[i] = id.String()
	}
	// The scope says exactly what was revoked (invariant 8): Muistamo's gateway keys, refused from
	// the next authorization. Responses already in flight are not cut off.
	return map[string]any{"revoker": "gateway-virtual-keys", "simulated": false,
		"scope":                 "gateway virtual keys; next authorization refused; in-flight responses not terminated",
		"keysRevokedByThisCall": len(ids), "keyIds": ids}
}

// KeyRevoker revokes every active gateway virtual key of an instance. The gateway checks keys
// live on every call, so this is real revocation for all tenants. HUMAN REVIEW REQUIRED.
type KeyRevoker struct {
	Registry *registry.Service
}

// Revoke revokes the instance's active keys with the fixed reason "leaver".
func (k KeyRevoker) Revoke(ctx context.Context, actor registry.Actor, instance string) (RevocationReport, error) {
	ids, err := k.Registry.RevokeInstanceKeys(ctx, actor, instance)
	if err != nil {
		return RevocationReport{}, fmt.Errorf("revoke virtual keys of %s: %w", instance, err)
	}
	return RevocationReport{VirtualKeys: ids}, nil
}

// Simulated is the legacy Provisioner until Entra (FR-201), and a test Revoker. It provisions
// nothing and revokes nothing: it records calls, so tests can assert them and evidence can say
// exactly what was simulated. Never present it as real revocation.
type Simulated struct {
	mu    sync.Mutex
	Calls []string
}

const simulatedPrefix = "simulated:"

// Provision returns a deterministic, obviously fake identity ref.
func (s *Simulated) Provision(_ context.Context, tenant uuid.UUID, instance, _ string) (string, error) {
	s.record("provision " + instance)
	return simulatedPrefix + tenant.String() + "/" + instance, nil
}

// Disable records the call.
func (s *Simulated) Disable(_ context.Context, _ uuid.UUID, identityRef string) error {
	s.record("disable " + identityRef)
	return nil
}

// Enable records the call.
func (s *Simulated) Enable(_ context.Context, _ uuid.UUID, identityRef string) error {
	s.record("enable " + identityRef)
	return nil
}

// Revoke records the call and reports that nothing was revoked.
func (s *Simulated) Revoke(_ context.Context, _ registry.Actor, instance string) (RevocationReport, error) {
	s.record("revoke " + instance)
	return RevocationReport{Simulated: true}, nil
}

// Recorded returns a copy of the calls made so far.
func (s *Simulated) Recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Calls...)
}

func (s *Simulated) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Calls = append(s.Calls, call)
}

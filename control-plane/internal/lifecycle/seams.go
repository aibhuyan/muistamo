package lifecycle

import (
	"context"
	"sync"

	"github.com/google/uuid"
)

// Provisioner manages an instance's identity in the tenant's identity provider. Every method
// must be idempotent: activities retry, so a call can repeat after it already succeeded.
type Provisioner interface {
	// Provision creates (or finds) the identity for an instance and returns its id.
	Provision(ctx context.Context, tenant uuid.UUID, instance, personEmail string) (identityRef string, err error)
	Disable(ctx context.Context, tenant uuid.UUID, identityRef string) error
	Enable(ctx context.Context, tenant uuid.UUID, identityRef string) error
}

// Revoker revokes an instance's credentials (virtual keys, tokens). Must be idempotent.
type Revoker interface {
	Revoke(ctx context.Context, tenant uuid.UUID, instance string) error
}

// Simulated is the only Provisioner and Revoker until Entra (FR-201) and the gateway (D28)
// exist. It provisions nothing and revokes nothing: it records calls, so tests can assert them
// and evidence can say exactly what was simulated. Never present it as real revocation.
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

// Revoke records the call.
func (s *Simulated) Revoke(_ context.Context, _ uuid.UUID, instance string) error {
	s.record("revoke " + instance)
	return nil
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

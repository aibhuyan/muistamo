package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/entra"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

type workerEntraBinding struct {
	Binding muistamov1.EntraIdentityBinding
	Client  *entra.Client
}

// Collect development credentials before opening the worker's database/provider phase.
// There is no environment-secret fallback or provider endpoint override.
func readEntraWorkerBindings(cmd *cobra.Command, paths []string, credentialStdin bool) ([]workerEntraBinding, error) {
	if len(paths) == 0 {
		if credentialStdin {
			return nil, errors.New("--credential-stdin requires --entra-binding")
		}
		return nil, nil
	}
	if !credentialStdin {
		return nil, errors.New("development Entra worker requires --credential-stdin and a private hidden-input launcher")
	}
	var configs []workerEntraBinding
	seen := map[string]bool{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read historical Entra binding: %w", err)
		}
		b, err := entra.ParseBinding(raw)
		if err != nil {
			return nil, err
		}
		if seen[b.BindingVersion] {
			return nil, entra.ErrConfiguration
		}
		seen[b.BindingVersion] = true
		configs = append(configs, workerEntraBinding{Binding: b})
	}
	scanner := bufio.NewScanner(cmd.InOrStdin())
	scanner.Buffer(make([]byte, 1024), 8192)
	for i := range configs {
		if !scanner.Scan() || scanner.Err() != nil || strings.TrimSpace(scanner.Text()) == "" {
			return nil, errors.New("credential input unavailable")
		}
		secret := scanner.Text()
		binding := configs[i].Binding
		client, err := entra.New(binding, func(_ context.Context, ref, version string) (string, error) {
			if ref != binding.CredentialRef || version != binding.CredentialVersion {
				return "", entra.ErrConfiguration
			}
			return secret, nil
		})
		if err != nil {
			return nil, err
		}
		configs[i].Client = client
	}
	return configs, nil
}

func validateEntraWorkerBindings(ctx context.Context, service *registry.Service, configs []workerEntraBinding) (*entra.Adapter, error) {
	clients, err := checkEntraBindings(ctx, service, configs)
	if err != nil {
		return nil, err
	}
	return entra.NewAdapter(service, clients...)
}

// entraDelegator serves knowledge delegations with the tenants' enrolled bindings only: a
// historical binding cannot validate tokens or exchange them.
func entraDelegator(ctx context.Context, service *registry.Service, configs []workerEntraBinding, log *slog.Logger) (*entra.Delegator, error) {
	clients, err := checkEntraBindings(ctx, service, configs)
	if err != nil {
		return nil, err
	}
	return entra.NewDelegator(service, log, clients...)
}

func checkEntraBindings(ctx context.Context, service *registry.Service, configs []workerEntraBinding) ([]*entra.Client, error) {
	clients := make([]*entra.Client, 0, len(configs))
	for _, config := range configs {
		actor := registry.Actor{Tenant: uuid.MustParse(config.Binding.TenantId), Name: "operator:worker-start", RequestID: uuid.NewString()}
		enrolled, err := service.IdentityEnrollment(ctx, actor)
		if err != nil {
			return nil, fmt.Errorf("worker tenant is not enrolled for Entra: %w", err)
		}
		if enrolled.BindingVersion != uuid.MustParse(config.Binding.BindingVersion) {
			return nil, entra.ErrConfiguration
		}
		// Registration already exists by enrollment's FK; this checks its immutable full
		// digest without retargeting or auto-enrolling the tenant.
		if _, _, err := service.RegisterIdentityBinding(ctx, actor, config.Binding); err != nil {
			return nil, err
		}
		clients = append(clients, config.Client)
	}
	return clients, nil
}

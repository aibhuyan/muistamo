package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/control-plane/internal/entra"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

// entraCmd exposes operator-only scoped diagnostics and conservative create reconciliation.
// No command accepts an arbitrary provider ID or an override that settles unknown PATCH/DELETE.
func entraCmd() *cobra.Command {
	root := &cobra.Command{Use: "entra", Short: "Inspect and reconcile durable Entra identity operations"}
	var tenant, actor, instance, operation, bindingFile string
	var credentialStdin bool
	open := func(cmd *cobra.Command) (context.Context, context.CancelFunc, *store.DB, registry.Actor, error) {
		id, err := uuid.Parse(tenant)
		if err != nil || id == uuid.Nil {
			return nil, nil, nil, registry.Actor{}, errors.New("a valid tenant id is required")
		}
		if strings.TrimSpace(actor) == "" {
			return nil, nil, nil, registry.Actor{}, errors.New("an operator actor is required")
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), 40*time.Second)
		db, err := store.Open(ctx, requireEnv("MUISTAMO_DATABASE_URL"))
		if err != nil {
			cancel()
			return nil, nil, nil, registry.Actor{}, err
		}
		return ctx, cancel, db, registry.Actor{Tenant: id, Name: actor, RequestID: uuid.NewString()}, nil
	}
	status := &cobra.Command{Use: "status --tenant ID --actor OPERATOR --instance NAME | --operation ID", Short: "Print scoped ownership or operation metadata", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if (instance == "") == (operation == "") {
			return errors.New("select exactly one instance or operation")
		}
		ctx, cancel, db, who, err := open(cmd)
		if err != nil {
			return err
		}
		defer cancel()
		defer db.Close()
		svc := registry.New(db, nil)
		if operation != "" {
			id, err := uuid.Parse(operation)
			if err != nil || id == uuid.Nil {
				return errors.New("a valid operation id is required")
			}
			out, err := svc.IdentityOperation(ctx, who, id)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
		}
		out, err := svc.IdentityStatus(ctx, who, instance)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}}
	status.Flags().StringVar(&instance, "instance", "", "instance name")
	status.Flags().StringVar(&operation, "operation", "", "opaque operation id")
	reconcile := &cobra.Command{Use: "reconcile --tenant ID --actor OPERATOR --operation ID --binding FILE --credential-stdin", Short: "Reconcile an original create through verified provider discovery", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if !credentialStdin {
			return errors.New("development reconciliation requires --credential-stdin; use a private hidden-input launcher")
		}
		id, err := uuid.Parse(operation)
		if err != nil || id == uuid.Nil {
			return errors.New("a valid operation id is required")
		}
		raw, err := os.ReadFile(bindingFile)
		if err != nil {
			return fmt.Errorf("read historical binding: %w", err)
		}
		binding, err := entra.ParseBinding(raw)
		if err != nil {
			return err
		}
		// Private input is collected before the bounded database/provider phase. Credential
		// resolution inside the adapter must never wait on terminal or pipe input.
		if binding.TenantId != tenant {
			return entra.ErrConfiguration
		}
		scanner := bufio.NewScanner(cmd.InOrStdin())
		scanner.Buffer(make([]byte, 1024), 8192)
		if !scanner.Scan() || scanner.Err() != nil || strings.TrimSpace(scanner.Text()) == "" {
			return errors.New("credential input unavailable")
		}
		secret := scanner.Text()
		ctx, cancel, db, who, err := open(cmd)
		if err != nil {
			return err
		}
		defer cancel()
		defer db.Close()
		if binding.TenantId != who.Tenant.String() {
			return entra.ErrConfiguration
		}
		key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
		if err != nil {
			return err
		}
		client, err := entra.New(binding, func(_ context.Context, ref, version string) (string, error) {
			if ref != binding.CredentialRef || version != binding.CredentialVersion {
				return "", entra.ErrConfiguration
			}
			return secret, nil
		})
		if err != nil {
			return err
		}
		adapter, err := entra.NewAdapter(registry.New(db, key), client)
		if err != nil {
			return err
		}
		out, err := adapter.Reconcile(ctx, who, id)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}}
	reconcile.Flags().StringVar(&operation, "operation", "", "opaque original operation id")
	reconcile.Flags().StringVar(&bindingFile, "binding", "", "exact historical binding JSON; no credential value")
	reconcile.Flags().BoolVar(&credentialStdin, "credential-stdin", false, "read local development credential privately from redirected stdin")
	var enrollBinding string
	enroll := &cobra.Command{Use: "enroll --tenant ID --actor OPERATOR --binding FILE", Short: "Select one immutable Entra binding for a fresh development tenant", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(enrollBinding)
		if err != nil {
			return fmt.Errorf("read enrollment binding: %w", err)
		}
		binding, err := entra.ParseBinding(raw)
		if err != nil {
			return err
		}
		ctx, cancel, db, who, err := open(cmd)
		if err != nil {
			return err
		}
		defer cancel()
		defer db.Close()
		if binding.TenantId != who.Tenant.String() {
			return entra.ErrConfiguration
		}
		key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
		if err != nil {
			return err
		}
		service := registry.New(db, key)
		if _, _, err := service.RegisterIdentityBinding(ctx, who, binding); err != nil {
			return err
		}
		out, err := service.EnrollIdentityTenant(ctx, who, uuid.MustParse(binding.BindingVersion))
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}}
	enroll.Flags().StringVar(&enrollBinding, "binding", "", "development binding JSON metadata; no credential value")
	root.PersistentFlags().StringVar(&tenant, "tenant", "", "Muistamo tenant id")
	root.PersistentFlags().StringVar(&actor, "actor", "", "operator identity recorded in evidence")
	root.AddCommand(status, reconcile, enroll)
	return root
}

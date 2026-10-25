// Command control-plane runs the Muistamo control plane.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	root := &cobra.Command{Use: "control-plane", SilenceUsage: true, SilenceErrors: true}
	// cobra's Print helpers default to stderr; command output belongs on stdout.
	root.SetOut(os.Stdout)
	root.AddCommand(serveCmd(log), migrateCmd(), tenantCmd(), evidenceCmd())
	if err := root.Execute(); err != nil {
		log.Error("control-plane failed", "err", err)
		os.Exit(1)
	}
}

func serveCmd(log *slog.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Serve the API (MUISTAMO_DATABASE_URL, CONTROL_PLANE_ADDR)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			db, err := store.Open(ctx, requireEnv("MUISTAMO_DATABASE_URL"))
			if err != nil {
				return err
			}
			defer db.Close()

			key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
			if err != nil {
				return err
			}

			var resolver api.TenantResolver = api.DenyAll{}
			if os.Getenv("MUISTAMO_INSECURE_DEV_TENANT_HEADER") == "true" {
				log.Warn("INSECURE: trusting X-Muistamo-Tenant and X-Muistamo-Actor headers; development only")
				resolver = api.InsecureDevHeaders{}
			}

			addr := envOr("CONTROL_PLANE_ADDR", "127.0.0.1:8080")
			srv := &http.Server{
				Addr:              addr,
				Handler:           api.Handler(registry.New(db, key), resolver, log),
				ReadHeaderTimeout: 5 * time.Second,
			}
			go func() {
				<-ctx.Done()
				shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdown)
			}()
			log.Info("control-plane listening", "addr", addr, "evidence_key", key.KeyID())
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("serve: %w", err)
			}
			return nil
		},
	}
}

func migrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "migrate",
		Short: "Apply database migrations (MUISTAMO_MIGRATE_DATABASE_URL, table owner)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return store.Migrate(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"))
		},
	}
}

func tenantCmd() *cobra.Command {
	tenant := &cobra.Command{Use: "tenant", Short: "Manage tenants (development)"}
	tenant.AddCommand(&cobra.Command{
		Use:   "create NAME",
		Short: "Create a tenant and print its id (MUISTAMO_MIGRATE_DATABASE_URL)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := store.CreateTenant(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"), args[0])
			if err != nil {
				return err
			}
			cmd.Println(id)
			return nil
		},
	})
	return tenant
}

// loadSigner fails closed: without a readable, registered signing key no write could carry
// evidence, so the server must not start.
func loadSigner(ctx context.Context, db *store.DB, path string) (evidence.LocalKey, error) {
	key, err := evidence.LoadLocalKey(path)
	if err != nil {
		return evidence.LocalKey{}, err
	}
	registered, err := db.SigningKeyRegistered(ctx, key.KeyID())
	if err != nil {
		return evidence.LocalKey{}, err
	}
	if !registered {
		return evidence.LocalKey{}, fmt.Errorf("evidence signing key %s is not registered; run control-plane evidence keygen", key.KeyID())
	}
	return key, nil
}

func evidenceCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "evidence", Short: "Manage evidence signing keys"}
	var out string
	keygen := &cobra.Command{
		Use:   "keygen --out FILE",
		Short: "Create an Ed25519 signing key, write FILE and FILE.pub, register it (MUISTAMO_MIGRATE_DATABASE_URL)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, private, err := evidence.GenerateLocalKey()
			if err != nil {
				return err
			}
			public, err := evidence.EncodePublicKey(key.Public())
			if err != nil {
				return err
			}
			// O_EXCL: never overwrite an existing key, which would orphan every event it signed.
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("create key file: %w", err)
			}
			if _, err := f.Write(private); err != nil {
				_ = f.Close()
				return fmt.Errorf("write key file: %w", err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("write key file: %w", err)
			}
			if err := os.WriteFile(out+".pub", public, 0o644); err != nil {
				return fmt.Errorf("write public key: %w", err)
			}
			if err := store.RegisterSigningKey(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"), key.KeyID(), key.Public()); err != nil {
				return err
			}
			cmd.Printf("key %s written to %s (public half %s.pub) and registered\n", key.KeyID(), out, out)
			return nil
		},
	}
	keygen.Flags().StringVar(&out, "out", "", "private key file to create")
	_ = keygen.MarkFlagRequired("out")
	cmd.AddCommand(keygen)
	return cmd
}

func requireEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "control-plane: %s is required\n", name)
		os.Exit(2)
	}
	return value
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

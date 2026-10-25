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
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	root := &cobra.Command{Use: "control-plane", SilenceUsage: true, SilenceErrors: true}
	// cobra's Print helpers default to stderr; command output belongs on stdout.
	root.SetOut(os.Stdout)
	root.AddCommand(serveCmd(log), migrateCmd(), tenantCmd())
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

			var resolver api.TenantResolver = api.DenyAll{}
			if os.Getenv("MUISTAMO_INSECURE_DEV_TENANT_HEADER") == "true" {
				log.Warn("INSECURE: trusting X-Muistamo-Tenant and X-Muistamo-Actor headers; development only")
				resolver = api.InsecureDevHeaders{}
			}

			addr := envOr("CONTROL_PLANE_ADDR", "127.0.0.1:8080")
			srv := &http.Server{
				Addr:              addr,
				Handler:           api.Handler(registry.New(db), resolver, log),
				ReadHeaderTimeout: 5 * time.Second,
			}
			go func() {
				<-ctx.Done()
				shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdown)
			}()
			log.Info("control-plane listening", "addr", addr)
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

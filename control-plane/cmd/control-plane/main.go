// Command control-plane runs the Muistamo control plane.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"

	"muistamo.dev/muistamo/control-plane/internal/api"
	"muistamo.dev/muistamo/control-plane/internal/evidence"
	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	root := &cobra.Command{Use: "control-plane", SilenceUsage: true, SilenceErrors: true}
	// cobra's Print helpers default to stderr; command output belongs on stdout.
	root.SetOut(os.Stdout)
	root.AddCommand(serveCmd(log), workerCmd(log), migrateCmd(), tenantCmd(), evidenceCmd(), catalogueCmd(), privacyCmd(), hrCmd(), entraCmd())
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

			// HR events need the workflow engine. Without it they are refused, never queued silently.
			var hr api.HRIntake
			if address := os.Getenv("TEMPORAL_ADDRESS"); address != "" {
				temporal, err := client.Dial(client.Options{HostPort: address, Namespace: envOr("TEMPORAL_NAMESPACE", "default")})
				if err != nil {
					return fmt.Errorf("connect to Temporal at %s: %w", address, err)
				}
				defer temporal.Close()
				hr = &lifecycle.Intake{DB: db, Signer: key, Dispatcher: lifecycle.TemporalDispatcher{Client: temporal}}
			} else {
				log.Warn("TEMPORAL_ADDRESS not set: HR events will be refused")
			}

			addr := envOr("CONTROL_PLANE_ADDR", "127.0.0.1:8080")
			srv := &http.Server{
				Addr:              addr,
				Handler:           api.Handler(registry.New(db, key), resolver, hr, log),
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

func workerCmd(log *slog.Logger) *cobra.Command {
	var bindingPaths []string
	var credentialStdin bool
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run lifecycle workflows (MUISTAMO_DATABASE_URL, MUISTAMO_EVIDENCE_KEY_FILE, TEMPORAL_ADDRESS)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configs, err := readEntraWorkerBindings(cmd, bindingPaths, credentialStdin)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			db, err := store.Open(ctx, requireEnv("MUISTAMO_DATABASE_URL"))
			if err != nil {
				return err
			}
			defer db.Close()
			key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
			if err != nil {
				return err
			}
			temporal, err := client.Dial(client.Options{HostPort: requireEnv("TEMPORAL_ADDRESS"), Namespace: envOr("TEMPORAL_NAMESPACE", "default")})
			if err != nil {
				return fmt.Errorf("connect to Temporal: %w", err)
			}
			defer temporal.Close()

			// Invariant 8: say plainly what is not real yet.
			log.Warn("SIMULATED: legacy workflow identities and gateway credential revocation remain simulated and are labeled in evidence")
			simulated := &lifecycle.Simulated{}
			service := registry.New(db, key)
			if len(configs) > 0 {
				identity, err := validateEntraWorkerBindings(ctx, service, configs)
				if err != nil {
					return err
				}
				live := worker.New(temporal, lifecycle.EntraTaskQueue, worker.Options{})
				live.RegisterWorkflow(lifecycle.EntraHRDispatch)
				live.RegisterWorkflow(lifecycle.EntraJoiner)
				live.RegisterWorkflow(lifecycle.EntraLeaver)
				live.RegisterActivity(&lifecycle.EntraActivities{Registry: service, Identity: identity, Revoker: simulated})
				if err := live.Start(); err != nil {
					return fmt.Errorf("start Entra lifecycle worker: %w", err)
				}
				defer live.Stop()
				log.Info("Entra lifecycle worker running", "task_queue", lifecycle.EntraTaskQueue, "binding_count", len(configs))
				log.Warn("live knowledge reviews are not integrated; leaver evidence records review-not-opened")
			} else {
				log.Warn("no Entra binding configured: live lifecycle queue is not served; live HR handoffs remain pending")
			}
			w := worker.New(temporal, lifecycle.TaskQueue, worker.Options{})
			w.RegisterWorkflow(lifecycle.Joiner)
			w.RegisterWorkflow(lifecycle.Leaver)
			w.RegisterWorkflow(lifecycle.HRDispatch)
			acts := &lifecycle.Activities{Registry: registry.New(db, key), Provisioner: simulated, Revoker: simulated}
			if url := os.Getenv("MUISTAMO_KNOWLEDGE_URL"); url != "" {
				acts.Knowledge = lifecycle.NewKnowledgeClient(url)
			} else {
				log.Warn("MUISTAMO_KNOWLEDGE_URL is not set: leavers' personal layers will not be reviewed, and evidence will say so")
			}
			w.RegisterActivity(acts)
			log.Info("lifecycle worker running", "task_queue", lifecycle.TaskQueue, "evidence_key", key.KeyID())
			return w.Run(worker.InterruptCh())
		},
	}
	cmd.Flags().StringSliceVar(&bindingPaths, "entra-binding", nil, "historical development binding JSON files, one private credential line per file")
	cmd.Flags().BoolVar(&credentialStdin, "credential-stdin", false, "read development Entra credentials privately from redirected stdin")
	return cmd
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
	tenant.AddCommand(&cobra.Command{
		Use:   "hr-secret TENANT_ID",
		Short: "Create the tenant's HR webhook secret and print it once (MUISTAMO_MIGRATE_DATABASE_URL)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("tenant id: %w", err)
			}
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return fmt.Errorf("generate secret: %w", err)
			}
			// The printed string itself is the HMAC key, as with most webhook providers.
			secret := "mhr_" + hex.EncodeToString(raw)
			if err := store.SetHRSecret(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"), id, []byte(secret)); err != nil {
				return err
			}
			cmd.Println(secret)
			return nil
		},
	})
	tenant.AddCommand(&cobra.Command{
		Use:   "knowledge-secret TENANT_ID",
		Short: "Create the secret the leaver workflow signs knowledge-service calls with, and print it once (MUISTAMO_MIGRATE_DATABASE_URL)",
		Long: "Store the printed value in the knowledge service too: python -m muistamo_knowledge tenant service-secret TENANT_ID SECRET. " +
			"Running this again replaces the secret, so set the new value there as well.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(args[0])
			if err != nil {
				return fmt.Errorf("tenant id: %w", err)
			}
			raw := make([]byte, 32)
			if _, err := rand.Read(raw); err != nil {
				return fmt.Errorf("generate secret: %w", err)
			}
			secret := "mks_" + hex.EncodeToString(raw)
			if err := store.SetKnowledgeSecret(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"), id, []byte(secret)); err != nil {
				return err
			}
			cmd.Println(secret)
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

func catalogueCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "catalogue", Short: "Manage the template catalogue"}
	approvers := &cobra.Command{Use: "approvers", Short: "Manage catalogue approvers"}
	var tenant string
	set := &cobra.Command{
		Use:   "set --tenant ID APPROVER...",
		Short: "Replace the tenant's catalogue approvers (MUISTAMO_MIGRATE_DATABASE_URL)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(tenant)
			if err != nil {
				return fmt.Errorf("tenant id: %w", err)
			}
			if err := store.SetCatalogueApprovers(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"), id, args); err != nil {
				return err
			}
			cmd.Printf("tenant %s now has %d catalogue approvers\n", id, len(args))
			return nil
		},
	}
	set.Flags().StringVar(&tenant, "tenant", "", "tenant id")
	_ = set.MarkFlagRequired("tenant")
	approvers.AddCommand(set)
	cmd.AddCommand(approvers)
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

func privacyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "privacy", Short: "Manage privacy officers (erasure and access requests)"}
	officers := &cobra.Command{Use: "officers", Short: "Manage privacy officers"}
	var tenant string
	set := &cobra.Command{
		Use:   "set --tenant ID OFFICER...",
		Short: "Replace the tenant's privacy officers (MUISTAMO_MIGRATE_DATABASE_URL)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := uuid.Parse(tenant)
			if err != nil {
				return fmt.Errorf("tenant id: %w", err)
			}
			if err := store.SetPrivacyOfficers(cmd.Context(), requireEnv("MUISTAMO_MIGRATE_DATABASE_URL"), id, args); err != nil {
				return err
			}
			cmd.Printf("tenant %s now has %d privacy officers\n", id, len(args))
			return nil
		},
	}
	set.Flags().StringVar(&tenant, "tenant", "", "tenant id")
	_ = set.MarkFlagRequired("tenant")
	officers.AddCommand(set)
	cmd.AddCommand(officers)
	return cmd
}

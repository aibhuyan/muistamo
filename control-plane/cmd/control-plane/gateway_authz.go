package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/spf13/cobra"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"

	"muistamo.dev/muistamo/contracts"
	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/gateway"
	"muistamo.dev/muistamo/control-plane/internal/registry"
	"muistamo.dev/muistamo/control-plane/internal/store"
)

func parseGatewayConfig(raw []byte) (muistamov1.GatewayAuthzConfig, error) {
	var cfg muistamov1.GatewayAuthzConfig
	if err := contracts.ValidateAgainst("gatewayauthzconfig.json", raw); err != nil {
		return cfg, errors.New("invalid gateway authorization configuration")
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode gateway authorization configuration: %w", err)
	}
	return cfg, nil
}

func gatewayDigestCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{Use: "config-digest --config FILE", Short: "Print the fingerprint required in the gateway's ext_authz metadata", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		cfg, err := parseGatewayConfig(raw)
		if err != nil {
			return err
		}
		cmd.Println(gateway.ConfigDigest(cfg))
		return nil
	}}
	cmd.Flags().StringVar(&file, "config", "", "trusted tenant and pinned model routes")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func gatewayRenderCmd() *cobra.Command {
	var file, authzHost, ingestHost, readiness, out string
	cmd := &cobra.Command{Use: "render-config --config FILE --authz-host HOST:PORT [--out FILE]", Short: "Render agentgateway's configuration from the checker's configuration; failureMode is always deny", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		cfg, err := parseGatewayConfig(raw)
		if err != nil {
			return err
		}
		rendered, err := gateway.RenderConfig(cfg, gateway.RenderOptions{AuthzHost: authzHost, IngestHost: ingestHost, ReadinessAddr: readiness})
		if err != nil {
			return err
		}
		if out == "" {
			_, err := cmd.OutOrStdout().Write(rendered)
			return err
		}
		return writeReplacing(out, rendered)
	}}
	cmd.Flags().StringVar(&file, "config", "", "the configuration `gateway authz` serves")
	cmd.Flags().StringVar(&authzHost, "authz-host", "", "host:port where the gateway reaches `gateway authz`")
	cmd.Flags().StringVar(&ingestHost, "ingest-host", "", "host:port where the gateway exports usage to `gateway ingest`; the gateway reads its credential from "+gateway.IngestTokenEnv)
	cmd.Flags().StringVar(&readiness, "readiness-addr", "", "optional gateway readiness listener, host:port")
	cmd.Flags().StringVar(&out, "out", "", "write here, replacing the file whole; default stdout")
	_ = cmd.MarkFlagRequired("config")
	_ = cmd.MarkFlagRequired("authz-host")
	return cmd
}

// writeReplacing writes through a temporary file in the same directory and renames it, so the
// gateway never reloads a partly written configuration.
func writeReplacing(path string, body []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gateway-config-*")
	if err != nil {
		return fmt.Errorf("write gateway configuration: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write gateway configuration: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write gateway configuration: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("write gateway configuration: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write gateway configuration: %w", err)
	}
	return nil
}

func gatewayIngestCmd() *cobra.Command {
	var file, address string
	var development bool
	cmd := &cobra.Command{Use: "ingest --config FILE --insecure-development", Short: "Receive the gateway's usage export and record it at provider cost", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		// Like authorization, this bounded slice has no production transport: the export arrives
		// in plaintext on an isolated network. TLS/mTLS is a later plan.
		if !development {
			return errors.New("usage ingest currently requires --insecure-development on an isolated local/test network; production transport is not integrated")
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		cfg, err := parseGatewayConfig(raw)
		if err != nil {
			return err
		}
		token, err := os.ReadFile(requireEnv("MUISTAMO_GATEWAY_INGEST_TOKEN_FILE"))
		if err != nil {
			return fmt.Errorf("read ingest token: %w", err)
		}
		token = []byte(strings.TrimSpace(string(token)))
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		db, err := store.Open(ctx, requireEnv("MUISTAMO_DATABASE_URL"))
		if err != nil {
			return err
		}
		defer db.Close()
		if err := db.RequireApplicationRole(ctx); err != nil {
			return err
		}
		key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
		if err != nil {
			return err
		}
		log := slog.Default()
		service, err := gateway.NewIngest(registry.New(db, key), cfg, token, log)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		server := grpc.NewServer(grpc.MaxRecvMsgSize(4*1024*1024), grpc.MaxConcurrentStreams(16))
		collogs.RegisterLogsServiceServer(server, service)
		go func() { <-ctx.Done(); server.Stop() }()
		log.Warn("development gateway usage ingest: isolate this plaintext endpoint", "tenant", cfg.TenantId, "config_digest", gateway.ConfigDigest(cfg))
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			return fmt.Errorf("serve gateway usage ingest: %w", err)
		}
		return nil
	}}
	cmd.Flags().StringVar(&file, "config", "", "the configuration `gateway authz` serves")
	cmd.Flags().StringVar(&address, "listen", "127.0.0.1:4317", "OTLP/gRPC listener on the isolated development network")
	cmd.Flags().BoolVar(&development, "insecure-development", false, "acknowledge plaintext development transport; no production authentication")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func gatewayAuthorizationCmd() *cobra.Command {
	var file, address, kind string
	var development bool
	cmd := &cobra.Command{Use: "authz --config FILE --insecure-development", Short: "Serve development model authorization; MCP calls are refused", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		// This bounded slice does not expose a production plaintext bearer endpoint. A later
		// transport plan must establish the gateway caller with TLS/mTLS before deployment.
		if !development {
			return errors.New("authorization currently requires --insecure-development on an isolated local/test network; production transport is not integrated")
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		cfg, err := parseGatewayConfig(raw)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		db, err := store.Open(ctx, requireEnv("MUISTAMO_DATABASE_URL"))
		if err != nil {
			return err
		}
		defer db.Close()
		if err := db.RequireApplicationRole(ctx); err != nil {
			return err
		}
		key, err := loadSigner(ctx, db, requireEnv("MUISTAMO_EVIDENCE_KEY_FILE"))
		if err != nil {
			return err
		}
		log := slog.Default()
		service, err := gateway.NewAuthorization(registry.New(db, key), cfg, muistamov1.GatewayAuthorizationRequestKind(kind), log)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		server := grpc.NewServer(grpc.MaxRecvMsgSize(64*1024), grpc.MaxConcurrentStreams(64))
		auth.RegisterAuthorizationServer(server, service)
		go func() { <-ctx.Done(); server.Stop() }()
		log.Warn("development gateway authorization: isolate this plaintext endpoint; MCP disabled", "tenant", cfg.TenantId, "kind", kind, "config_digest", gateway.ConfigDigest(cfg))
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			return fmt.Errorf("serve gateway authorization: %w", err)
		}
		return nil
	}}
	cmd.Flags().StringVar(&file, "config", "", "trusted tenant and pinned model routes")
	cmd.Flags().StringVar(&address, "listen", "127.0.0.1:18081", "gRPC listener on the isolated development network")
	cmd.Flags().StringVar(&kind, "kind", "model", "trusted listener protocol: model or mcp (MCP always refused)")
	cmd.Flags().BoolVar(&development, "insecure-development", false, "acknowledge plaintext development transport; no production authentication")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

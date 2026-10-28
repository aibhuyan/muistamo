package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/spf13/cobra"
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

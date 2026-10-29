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
	var plaintext bool
	var tlsFiles gateway.GatewayTLS
	cmd := &cobra.Command{Use: "render-config --config FILE --authz-host HOST:PORT (--tls-root F --tls-cert F --tls-key F --authz-server-name N [--ingest-server-name N] | --insecure-plaintext) [--out FILE]", Short: "Render agentgateway's configuration from the checker's configuration; failureMode is always deny", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		raw, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		cfg, err := parseGatewayConfig(raw)
		if err != nil {
			return err
		}
		opts := gateway.RenderOptions{AuthzHost: authzHost, IngestHost: ingestHost, ReadinessAddr: readiness, Plaintext: plaintext}
		if tlsFiles != (gateway.GatewayTLS{}) {
			opts.TLS = &tlsFiles
		}
		rendered, err := gateway.RenderConfig(cfg, opts)
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
	cmd.Flags().StringVar(&tlsFiles.Root, "tls-root", "", "CA (PEM path inside the gateway) that issued the endpoints' certificates")
	cmd.Flags().StringVar(&tlsFiles.Cert, "tls-cert", "", "the gateway's client certificate (PEM path inside the gateway)")
	cmd.Flags().StringVar(&tlsFiles.Key, "tls-key", "", "the gateway's client key (PEM path inside the gateway)")
	cmd.Flags().StringVar(&tlsFiles.AuthzServerName, "authz-server-name", "", "DNS name the authorization endpoint's certificate must carry")
	cmd.Flags().StringVar(&tlsFiles.IngestServerName, "ingest-server-name", "", "DNS name the ingest endpoint's certificate must carry")
	cmd.Flags().BoolVar(&plaintext, "insecure-plaintext", false, "render plaintext connections to the endpoints, which also sends the ingest bearer token in cleartext (isolated development only)")
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
	var tlsFlags endpointTLS
	cmd := &cobra.Command{Use: "ingest --config FILE (--tls-cert F --tls-key F --client-ca F --client-identity ID | --insecure-development)", Short: "Receive the gateway's usage export over mutual TLS and record it at provider cost", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		transport, err := tlsFlags.choose(development)
		if err != nil {
			return err
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
		log := transport.logger()
		service, err := gateway.NewIngest(registry.New(db, key), cfg, token, log)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		server := grpc.NewServer(append(transport.ServerOptions(), grpc.MaxRecvMsgSize(4*1024*1024), grpc.MaxConcurrentStreams(16))...)
		collogs.RegisterLogsServiceServer(server, service)
		go func() { <-ctx.Done(); server.Stop() }()
		transport.announce(log, "gateway usage ingest", "tenant", cfg.TenantId, "config_digest", gateway.ConfigDigest(cfg))
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			return fmt.Errorf("serve gateway usage ingest: %w", err)
		}
		return nil
	}}
	cmd.Flags().StringVar(&file, "config", "", "the configuration `gateway authz` serves")
	cmd.Flags().StringVar(&address, "listen", "127.0.0.1:4317", "OTLP/gRPC listener")
	cmd.Flags().BoolVar(&development, "insecure-development", false, "plaintext without caller certificates, for an isolated local network only")
	tlsFlags.register(cmd)
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func gatewayAuthorizationCmd() *cobra.Command {
	var file, address, kind string
	var development bool
	var tlsFlags endpointTLS
	cmd := &cobra.Command{Use: "authz --config FILE (--tls-cert F --tls-key F --client-ca F --client-identity ID | --insecure-development)", Short: "Serve model authorization to the gateway over mutual TLS; MCP calls are refused", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		// The gateway is the only caller: mutual TLS proves it is (operator's CA, pinned identity).
		transport, err := tlsFlags.choose(development)
		if err != nil {
			return err
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
		log := transport.logger()
		service, err := gateway.NewAuthorization(registry.New(db, key), cfg, muistamov1.GatewayAuthorizationRequestKind(kind), log)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return err
		}
		defer func() { _ = listener.Close() }()
		server := grpc.NewServer(append(transport.ServerOptions(), grpc.MaxRecvMsgSize(64*1024), grpc.MaxConcurrentStreams(64))...)
		auth.RegisterAuthorizationServer(server, service)
		go func() { <-ctx.Done(); server.Stop() }()
		transport.announce(log, "gateway authorization (MCP disabled)", "tenant", cfg.TenantId, "kind", kind, "config_digest", gateway.ConfigDigest(cfg))
		if err := server.Serve(listener); err != nil && ctx.Err() == nil {
			return fmt.Errorf("serve gateway authorization: %w", err)
		}
		return nil
	}}
	cmd.Flags().StringVar(&file, "config", "", "trusted tenant and pinned model routes")
	cmd.Flags().StringVar(&address, "listen", "127.0.0.1:18081", "gRPC listener")
	cmd.Flags().StringVar(&kind, "kind", "model", "trusted listener protocol: model or mcp (MCP always refused)")
	cmd.Flags().BoolVar(&development, "insecure-development", false, "plaintext without caller certificates, for an isolated local network only")
	tlsFlags.register(cmd)
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

// endpointTLS are the operator-provided files and identity both gateway endpoints take.
type endpointTLS struct{ cert, key, clientCA, clientIdentity string }

func (e *endpointTLS) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&e.cert, "tls-cert", "", "server certificate (PEM) issued by the operator's PKI")
	cmd.Flags().StringVar(&e.key, "tls-key", "", "server private key (PEM)")
	cmd.Flags().StringVar(&e.clientCA, "client-ca", "", "CA (PEM) that issues the gateway's client certificate")
	cmd.Flags().StringVar(&e.clientIdentity, "client-identity", "", "the gateway's identity: a SPIFFE id matched against the certificate's single URI SAN (spiffe://example.org/agentgateway), or a lowercase DNS name matched against its DNS SANs")
}

func (e endpointTLS) choose(development bool) (endpointTransport, error) {
	t, err := gateway.ChooseTransport(development, e.cert, e.key, e.clientCA, e.clientIdentity, slog.Default())
	return endpointTransport{t}, err
}

type endpointTransport struct{ gateway.ServerTransport }

// logger carries the gateway identity on every entry: under mutual TLS the handshake has already
// refused any client certificate that does not name it.
func (t endpointTransport) logger() *slog.Logger {
	if t.TLS == nil {
		return slog.Default()
	}
	return slog.Default().With("gateway_identity", t.Identity.String())
}

// announce logs the transport at startup; never key material.
func (t endpointTransport) announce(log *slog.Logger, what string, args ...any) {
	if t.TLS == nil {
		log.Warn(what+": plaintext development transport with no caller certificates; isolate this endpoint", args...)
		return
	}
	log.Info(what+": mutual TLS 1.3", append(args, "server_certificate_not_after", gateway.ServerNotAfter(t.TLS),
		"max_connection_age", gateway.MaxConnectionAge.String())...)
}

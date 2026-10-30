package gateway

// HUMAN REVIEW REQUIRED: the rendered failureMode and the provider credential reference.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// RenderOptions places the checker the gateway calls. Nothing here can relax authorization.
type RenderOptions struct {
	AuthzHost     string // host:port of `control-plane gateway authz`
	IngestHost    string // optional host:port of `control-plane gateway ingest`; usage export
	ReadinessAddr string // optional gateway readiness listener
	// TLS is how the gateway authenticates to both endpoints (mutual TLS). Nil renders plaintext,
	// which is refused unless Plaintext explicitly asks for it (isolated development only).
	TLS       *GatewayTLS
	Plaintext bool
}

// GatewayTLS are files as the gateway sees them: the CA that issued the endpoints' certificates,
// and the gateway's own client certificate and key. The server names are what the endpoints'
// certificates must name. HUMAN REVIEW REQUIRED.
type GatewayTLS struct {
	Root, Cert, Key                   string
	AuthzServerName, IngestServerName string
}

// providers maps catalogue providers to the pinned gateway's provider names. Only providers
// validated against agentgateway v1.6.0 are listed; anything else is refused, not guessed.
var providers = map[string]string{"openai": "openAI"}

// failureMode is constant: an unreachable or failing checker refuses the call (invariant 3).
// There is deliberately no option to change it.
const failureMode = "deny"

// modelMetadata are the parsed fields sent to the checker (validation report, rules A and B).
// The request body itself is never sent.
const modelMetadata = `{"value": json(request.body).model}`

// RenderConfig renders agentgateway's configuration from the same configuration the checker
// serves, bound to it by ConfigDigest. Only the model listener is rendered: MCP stays refused.
func RenderConfig(cfg muistamov1.GatewayAuthzConfig, opts RenderOptions) ([]byte, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if err := hostPort(opts.AuthzHost); err != nil {
		return nil, fmt.Errorf("authz host: %w", err)
	}
	authzTLS, ingestTLS, err := backendTLS(opts)
	if err != nil {
		return nil, err
	}
	var models []yaml.MapSlice
	for _, route := range cfg.Models {
		provider, ok := providers[route.Provider]
		if !ok {
			return nil, fmt.Errorf("provider %q is not validated with the pinned gateway", route.Provider)
		}
		params := yaml.MapSlice{{Key: "model", Value: route.Model}}
		if route.CredentialEnv != nil {
			// A reference the gateway expands from its own environment; it never starts without it.
			params = append(params, yaml.MapItem{Key: "apiKey", Value: "$" + *route.CredentialEnv})
		}
		params = append(params, yaml.MapItem{Key: "baseUrl", Value: route.BaseUrl})
		models = append(models, yaml.MapSlice{
			{Key: "name", Value: route.Alias},
			{Key: "provider", Value: provider},
			{Key: "params", Value: params},
		})
	}
	doc := yaml.MapSlice{}
	if opts.ReadinessAddr != "" {
		if err := hostPort(opts.ReadinessAddr); err != nil {
			return nil, fmt.Errorf("readiness address: %w", err)
		}
		doc = append(doc, yaml.MapItem{Key: "config", Value: yaml.MapSlice{{Key: "readinessAddr", Value: opts.ReadinessAddr}}})
	}
	if opts.IngestHost != "" {
		if err := hostPort(opts.IngestHost); err != nil {
			return nil, fmt.Errorf("ingest host: %w", err)
		}
		// One access-log record per request, sent with the ingest credential the gateway reads from
		// its environment, carrying the request id the checker inserted (rules D and E).
		doc = append(doc, yaml.MapItem{Key: "frontendPolicies", Value: yaml.MapSlice{{Key: "accessLog", Value: yaml.MapSlice{
			{Key: "otlp", Value: yaml.MapSlice{
				{Key: "host", Value: opts.IngestHost},
				{Key: "policies", Value: append(yaml.MapSlice{{Key: "backendAuth", Value: yaml.MapSlice{{Key: "key", Value: "$" + IngestTokenEnv}}}}, ingestTLS...)},
				{Key: "fields", Value: yaml.MapSlice{{Key: "add", Value: yaml.MapSlice{
					{Key: "muistamo.request_id", Value: `request.headers["x-muistamo-request-id"]`},
				}}}},
			}},
		}}}})
	}
	extAuthz := yaml.MapSlice{
		{Key: "host", Value: opts.AuthzHost},
		{Key: "failureMode", Value: failureMode},
		{Key: "protocol", Value: yaml.MapSlice{{Key: "grpc", Value: yaml.MapSlice{{Key: "metadata", Value: yaml.MapSlice{
			{Key: "muistamo.model", Value: modelMetadata},
			{Key: "muistamo.config", Value: `{"value": "` + ConfigDigest(cfg) + `"}`},
		}}}}}},
	}
	if authzTLS != nil {
		extAuthz = append(extAuthz, yaml.MapItem{Key: "policies", Value: authzTLS})
	}
	doc = append(doc, yaml.MapItem{Key: "llm", Value: yaml.MapSlice{
		{Key: "port", Value: 4000},
		{Key: "policies", Value: yaml.MapSlice{{Key: "extAuthz", Value: extAuthz}}},
		{Key: "models", Value: models},
	}})
	body, err := yaml.MarshalWithOptions(doc, yaml.UseLiteralStyleIfMultiline(false))
	if err != nil {
		return nil, fmt.Errorf("render gateway configuration: %w", err)
	}
	var out bytes.Buffer
	out.WriteString("# Rendered by `control-plane gateway render-config`; do not edit. The checker must serve the\n")
	out.WriteString("# same configuration (digest " + ConfigDigest(cfg) + ").\n")
	out.WriteString("# No MCP listener: MCP calls stay refused until person-specific rights exist.\n")
	out.Write(body)
	return out.Bytes(), nil
}

// backendTLS renders the gateway's mutual TLS to each endpoint, or nothing in explicit plaintext.
// Either both connections are secured or neither: no half-secured deployment.
func backendTLS(opts RenderOptions) (authz, ingest yaml.MapSlice, err error) {
	switch {
	case opts.TLS == nil && !opts.Plaintext:
		return nil, nil, errors.New("give the gateway's TLS files for mutual TLS to the endpoints, or ask for plaintext explicitly (isolated development only)")
	case opts.TLS != nil && opts.Plaintext:
		return nil, nil, errors.New("plaintext and TLS were both requested")
	case opts.Plaintext:
		return nil, nil, nil
	}
	t := opts.TLS
	for _, f := range []struct{ name, path string }{{"root", t.Root}, {"cert", t.Cert}, {"key", t.Key}} {
		if !strings.HasPrefix(f.path, "/") || strings.ContainsAny(f.path, "$") || strings.IndexFunc(f.path, unrenderable) >= 0 {
			return nil, nil, fmt.Errorf("gateway TLS %s must be an absolute path inside the gateway, without control characters or $", f.name)
		}
	}
	block := func(serverName string) (yaml.MapSlice, error) {
		if !dnsName.MatchString(serverName) {
			return nil, fmt.Errorf("server name %q is not a DNS name", serverName)
		}
		return yaml.MapSlice{{Key: "backendTLS", Value: yaml.MapSlice{
			{Key: "root", Value: t.Root}, {Key: "cert", Value: t.Cert}, {Key: "key", Value: t.Key}, {Key: "hostname", Value: serverName},
		}}}, nil
	}
	if authz, err = block(t.AuthzServerName); err != nil {
		return nil, nil, fmt.Errorf("authz: %w", err)
	}
	if opts.IngestHost == "" && t.IngestServerName != "" {
		return nil, nil, errors.New("an ingest server name was given without an ingest host")
	}
	if opts.IngestHost != "" {
		if ingest, err = block(t.IngestServerName); err != nil {
			return nil, nil, fmt.Errorf("ingest: %w", err)
		}
	}
	return authz, ingest, nil
}

// dnsName is a plain DNS name, as certificates and SNI use them.
var dnsName = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func hostPort(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return errors.New("port must be 1-65535")
	}
	plain := func(c rune) bool {
		return c == '.' || c == '-' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}
	if host == "" || strings.ContainsFunc(host, func(c rune) bool { return !plain(c) }) {
		return errors.New("host must be a plain hostname or IP address")
	}
	return nil
}

package gateway_test

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/google/uuid"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/gateway"
)

// The gateway configuration is rendered from the checker's own configuration (docs/agentgateway-
// plan.md, step 4). HUMAN REVIEW REQUIRED: failureMode and the credential reference.

func renderFixture() muistamov1.GatewayAuthzConfig {
	env := "MUISTAMO_PROVIDER_KEY_FAKE"
	return muistamov1.GatewayAuthzConfig{TenantId: uuid.MustParse("6f19b972-b333-446e-802b-d8145231a2ac"), Models: []muistamov1.GatewayModelRoute{{
		Alias: "reasoning-default", AliasRevision: 1, CatalogueName: "fake-model", ModelRevision: 1, Provider: "openai",
		Model: "test-model", Region: "eu-test", BaseUrl: "http://provider:18080/v1", CredentialEnv: &env,
	}}}
}

const golden = `# Rendered by ` + "`control-plane gateway render-config`" + `; do not edit. The checker must serve the
# same configuration (digest b7a635f4257571a33544d00634c0682a61574f21579b15d72358da08e4e5022a).
# No MCP listener: MCP calls stay refused until person-specific rights exist.
config:
  readinessAddr: 0.0.0.0:19001
llm:
  port: 4000
  policies:
    extAuthz:
      host: authz:18081
      failureMode: deny
      protocol:
        grpc:
          metadata:
            muistamo.model: "{\"value\": json(request.body).model}"
            muistamo.config: "{\"value\": \"b7a635f4257571a33544d00634c0682a61574f21579b15d72358da08e4e5022a\"}"
  models:
  - name: reasoning-default
    provider: openAI
    params:
      model: test-model
      apiKey: $MUISTAMO_PROVIDER_KEY_FAKE
      baseUrl: http://provider:18080/v1
`

func TestRenderedGatewayConfigMatchesGolden(t *testing.T) {
	out, err := gateway.RenderConfig(renderFixture(), gateway.RenderOptions{AuthzHost: "authz:18081", ReadinessAddr: "0.0.0.0:19001"})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != golden {
		t.Fatalf("rendered:\n%s\nwant:\n%s", out, golden)
	}
}

// Walk the parsed document, not the text: every extAuthz must deny on failure, carry the
// checker's digest and parsed model field only, and no MCP listener may exist.
func TestRenderedGatewayConfigFailsClosedAndBindsTheChecker(t *testing.T) {
	cfg := renderFixture()
	second := cfg.Models[0]
	second.Alias, second.CredentialEnv = "fast-default", nil
	cfg.Models = append(cfg.Models, second)
	out, err := gateway.RenderConfig(cfg, gateway.RenderOptions{AuthzHost: "authz:18081"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["mcp"]; ok {
		t.Fatal("an MCP listener was rendered; MCP must stay refused")
	}
	var policies []map[string]any
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				if k == "extAuthz" {
					policies = append(policies, child.(map[string]any))
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	if len(policies) != 1 {
		t.Fatalf("extAuthz policies = %d, want exactly the model listener's", len(policies))
	}
	p := policies[0]
	meta := p["protocol"].(map[string]any)["grpc"].(map[string]any)["metadata"].(map[string]any)
	if p["failureMode"] != "deny" || p["host"] != "authz:18081" ||
		meta["muistamo.config"] != `{"value": "`+gateway.ConfigDigest(cfg)+`"}` ||
		meta["muistamo.model"] != `{"value": json(request.body).model}` || len(meta) != 2 {
		t.Fatalf("extAuthz = %v", p)
	}
	models := doc["llm"].(map[string]any)["models"].([]any)
	if len(models) != 2 {
		t.Fatalf("models = %v", models)
	}
	params := models[1].(map[string]any)["params"].(map[string]any)
	if _, ok := params["apiKey"]; ok {
		t.Fatal("a route without a credential reference was given an apiKey")
	}
	if got := models[0].(map[string]any)["params"].(map[string]any)["apiKey"]; got != "$MUISTAMO_PROVIDER_KEY_FAKE" {
		t.Fatalf("credential = %v, want a reference only", got)
	}
}

func TestRenderRefusesWhatTheCheckerWouldRefuse(t *testing.T) {
	for name, mutate := range map[string]func(*muistamov1.GatewayAuthzConfig, *gateway.RenderOptions){
		"unvalidated provider": func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].Provider = "anthropic" },
		"credential value":     func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { v := "sk-fake-not-a-name"; c.Models[0].CredentialEnv = &v },
		"lowercase reference":  func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { v := "openai_key"; c.Models[0].CredentialEnv = &v },
		"another secret":       func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { v := "OTLP_TOKEN"; c.Models[0].CredentialEnv = &v },
		"url with credentials": func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].BaseUrl = "http://u:p@provider/v1" },
		"duplicate alias":      func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models = append(c.Models, c.Models[0]) },
		"no tenant":            func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.TenantId = uuid.Nil },
		"no authz host":        func(_ *muistamov1.GatewayAuthzConfig, o *gateway.RenderOptions) { o.AuthzHost = "" },
		"authz host injection": func(_ *muistamov1.GatewayAuthzConfig, o *gateway.RenderOptions) { o.AuthzHost = "authz:1\nfailureMode: allow" },
		"bad readiness":        func(_ *muistamov1.GatewayAuthzConfig, o *gateway.RenderOptions) { o.ReadinessAddr = "0.0.0.0" },
		"tab in alias":         func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].Alias = "x\ty" },
		"newline in model":     func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].Model = "m\nmcp: {}" },
		"line separator":       func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].Region = "eu\u2028x" },
		"dollar in base url":   func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].BaseUrl = "http://p/$SECRET" },
		"dollar in model":      func(c *muistamov1.GatewayAuthzConfig, _ *gateway.RenderOptions) { c.Models[0].Model = "$OTHER_KEY" },
	} {
		cfg, opts := renderFixture(), gateway.RenderOptions{AuthzHost: "authz:18081"}
		mutate(&cfg, &opts)
		if out, err := gateway.RenderConfig(cfg, opts); err == nil {
			t.Errorf("%s: rendered\n%s", name, out)
		}
	}
}

// Route values are data: a hostile model name cannot add keys or relax the policy.
func TestRenderedValuesCannotInjectConfiguration(t *testing.T) {
	cfg := renderFixture()
	cfg.Models[0].Model = "m'} failureMode: allow, mcp: {port: 4001}, x: !!binary *a #"
	out, err := gateway.RenderConfig(cfg, gateway.RenderOptions{AuthzHost: "authz:18081"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["mcp"]; ok || strings.Count(string(out), "failureMode: deny") != 1 {
		t.Fatalf("injected configuration:\n%s", out)
	}
	model := doc["llm"].(map[string]any)["models"].([]any)[0].(map[string]any)["params"].(map[string]any)["model"]
	if model != cfg.Models[0].Model {
		t.Fatalf("model round trip = %q", model)
	}
}

// With an ingest host, every request's access log goes to Muistamo's ingest with the credential
// the gateway reads from its environment, and the checker's request id.
func TestRenderedGatewayConfigExportsUsageToIngest(t *testing.T) {
	out, err := gateway.RenderConfig(renderFixture(), gateway.RenderOptions{AuthzHost: "authz:18081", IngestHost: "ingest:4317"})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	otlp := doc["frontendPolicies"].(map[string]any)["accessLog"].(map[string]any)["otlp"].(map[string]any)
	key := otlp["policies"].(map[string]any)["backendAuth"].(map[string]any)["key"]
	field := otlp["fields"].(map[string]any)["add"].(map[string]any)["muistamo.request_id"]
	if otlp["host"] != "ingest:4317" || key != "$MUISTAMO_GATEWAY_INGEST_TOKEN" || field != `request.headers["x-muistamo-request-id"]` {
		t.Fatalf("otlp = %v", otlp)
	}
	if _, err := gateway.RenderConfig(renderFixture(), gateway.RenderOptions{AuthzHost: "authz:18081", IngestHost: "ingest"}); err == nil {
		t.Fatal("an ingest host without a port was rendered")
	}
	plain, err := gateway.RenderConfig(renderFixture(), gateway.RenderOptions{AuthzHost: "authz:18081"})
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(plain, &doc); err != nil || doc["frontendPolicies"] != nil {
		t.Fatalf("usage export rendered without an ingest host: %v", err)
	}
}

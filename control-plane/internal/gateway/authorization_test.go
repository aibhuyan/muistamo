package gateway_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/structpb"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/gateway"
)

type recorder struct {
	req    muistamov1.GatewayAuthorizationRequest
	tenant uuid.UUID
	secret string
}

func (r *recorder) AuthorizeGateway(_ context.Context, tenant uuid.UUID, secret string, req muistamov1.GatewayAuthorizationRequest, route *muistamov1.GatewayModelRoute) (muistamov1.GatewayAuthorizationDecision, error) {
	r.req, r.tenant, r.secret = req, tenant, secret
	id, _ := uuid.NewV7()
	d := muistamov1.GatewayAuthorizationDecision{RequestId: id, Reason: "invalid-request"}
	if !req.MetadataValid || route == nil {
		return d, nil
	}
	agent, person := "test-agent", "person@example.invalid"
	d.Allowed, d.Reason, d.Instance, d.Person = true, "allowed", &agent, &person
	return d, nil
}

func config() muistamov1.GatewayAuthzConfig {
	return muistamov1.GatewayAuthzConfig{TenantId: uuid.New(), Models: []muistamov1.GatewayModelRoute{{Alias: "model-a", AliasRevision: 1, CatalogueName: "catalogue-a", ModelRevision: 1, Provider: "test", Model: "fake-model", Region: "eu-test", BaseUrl: "http://fake.invalid/v1"}}}
}

func TestAuthorizationConfigBindsExactSafeDeploymentURL(t *testing.T) {
	for _, base := range []string{"", "ftp://fake.invalid", "http:opaque", "https://user:fake-secret@fake.invalid", "https://fake.invalid?secret=fake", "https://fake.invalid/#fragment", "https://fake.invalid/\n"} {
		cfg := config()
		cfg.Models[0].BaseUrl = base
		if _, err := gateway.NewAuthorization(&recorder{}, cfg, "model", slog.Default()); err == nil {
			t.Errorf("unsafe deployment URL accepted")
		}
	}
	a := config()
	b := a
	b.Models = append([]muistamov1.GatewayModelRoute(nil), a.Models...)
	b.Models[0].BaseUrl = "http://other.invalid/v1"
	if gateway.ConfigDigest(a) == gateway.ConfigDigest(b) {
		t.Fatal("deployment URL change did not change fingerprint")
	}
}

func request(cfg muistamov1.GatewayAuthzConfig) *auth.CheckRequest {
	model, _ := structpb.NewStruct(map[string]any{"value": "model-a"})
	fingerprint, _ := structpb.NewStruct(map[string]any{"value": gateway.ConfigDigest(cfg)})
	return &auth.CheckRequest{Attributes: &auth.AttributeContext{
		Request: &auth.AttributeContext_Request{Http: &auth.AttributeContext_HttpRequest{Method: "POST", Path: "/v1/chat/completions", Headers: map[string]string{
			"authorization": "Bearer obviously-fake-key", "x-muistamo-person": "spoof", "x-muistamo-unknown": "spoof", "x-muistamo-cost-centre": "spoof", "x-muistamo-tenant": uuid.NewString(),
		}}},
		MetadataContext: &core.Metadata{FilterMetadata: map[string]*structpb.Struct{"muistamo.model": model, "muistamo.config": fingerprint}},
	}}
}

func TestAuthorizationProtocolStripsSpoofsAndUsesConfiguredTenant(t *testing.T) {
	cfg, r := config(), &recorder{}
	s, err := gateway.NewAuthorization(r, cfg, "model", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Check(t.Context(), request(cfg))
	if err != nil || res.GetStatus().GetCode() != 0 {
		t.Fatalf("protocol allow = %+v %v", res, err)
	}
	if r.tenant != cfg.TenantId || r.secret != "obviously-fake-key" {
		t.Fatal("client header selected a tenant or token was misparsed")
	}
	removed := strings.Join(res.GetOkResponse().GetHeadersToRemove(), ",")
	for _, name := range []string{"authorization", "x-muistamo-unknown", "x-muistamo-tenant", "x-muistamo-cost-centre"} {
		if !strings.Contains(removed, name) {
			t.Errorf("untrusted header not removed: %s", name)
		}
	}
	for _, h := range res.GetOkResponse().GetHeaders() {
		if h.GetHeader().GetValue() == "spoof" || h.GetAppendAction() != core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Error("identity was appended or client spoof retained")
		}
	}
}

func TestAuthorizationProtocolNeverFallsBackToBodiesOrClientMetadata(t *testing.T) {
	for _, scenario := range []string{"no-metadata", "wrong-config", "number-model", "mixed-protocol", "body", "raw-body", "duplicate-auth", "raw-headers", "query", "fragment"} {
		t.Run(scenario, func(t *testing.T) {
			cfg, r := config(), &recorder{}
			s, err := gateway.NewAuthorization(r, cfg, "model", slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			req := request(cfg)
			h := req.Attributes.Request.Http
			switch scenario {
			case "no-metadata":
				req.Attributes.MetadataContext = nil
			case "wrong-config":
				req.Attributes.MetadataContext.FilterMetadata["muistamo.config"], _ = structpb.NewStruct(map[string]any{"value": "wrong"})
			case "number-model":
				req.Attributes.MetadataContext.FilterMetadata["muistamo.model"], _ = structpb.NewStruct(map[string]any{"value": 7})
			case "mixed-protocol":
				req.Attributes.MetadataContext.FilterMetadata["muistamo.method"], _ = structpb.NewStruct(map[string]any{"value": "tools/call"})
			case "body":
				h.Body = `{"model":"model-a"}`
			case "raw-body":
				h.RawBody = []byte(`{"model":"model-a"}`)
			case "duplicate-auth":
				h.Headers["Authorization"] = "Bearer other"
			case "raw-headers":
				h.HeaderMap = &core.HeaderMap{}
			case "query":
				h.Query = "model=other"
			case "fragment":
				h.Fragment = "other"
			}
			res, err := s.Check(t.Context(), req)
			if err != nil || res.GetStatus().GetCode() == 0 || r.req.MetadataValid {
				t.Fatalf("untrusted protocol accepted (%s): %+v %v", scenario, res, err)
			}
		})
	}
}

type refuser struct{ reason muistamov1.GatewayAuthorizationDecisionReason }

func (r refuser) AuthorizeGateway(context.Context, uuid.UUID, string, muistamov1.GatewayAuthorizationRequest, *muistamov1.GatewayModelRoute) (muistamov1.GatewayAuthorizationDecision, error) {
	id, _ := uuid.NewV7()
	return muistamov1.GatewayAuthorizationDecision{RequestId: id, Reason: r.reason}, nil
}

// Rate limits answer 429 with a retry hint (RFC 6585); every other refusal stays 403.
func TestRateLimitRefusalsAre429WithRetryAfter(t *testing.T) {
	for reason, want := range map[muistamov1.GatewayAuthorizationDecisionReason]struct {
		status uint32
		retry  string
	}{"rate-limited": {429, "60"}, "too-many-in-flight": {429, "30"}, "budget-reached": {403, ""}, "calls-without-usage-limit": {403, ""}} {
		cfg := config()
		s, err := gateway.NewAuthorization(refuser{reason}, cfg, "model", slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Check(t.Context(), request(cfg))
		if err != nil || res.GetOkResponse() != nil {
			t.Fatalf("%s: %+v, %v", reason, res, err)
		}
		denied := res.GetDeniedResponse()
		retry := ""
		for _, h := range denied.GetHeaders() {
			if h.GetHeader().GetKey() == "retry-after" {
				retry = h.GetHeader().GetValue()
			}
		}
		if uint32(denied.GetStatus().GetCode()) != want.status || retry != want.retry {
			t.Errorf("%s: status %d, retry-after %q; want %d, %q", reason, denied.GetStatus().GetCode(), retry, want.status, want.retry)
		}
	}
}

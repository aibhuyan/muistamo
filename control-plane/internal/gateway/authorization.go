// Package gateway adapts the pinned agentgateway ext_authz protocol to the registry.
package gateway

// HUMAN REVIEW REQUIRED: gateway policy path and identity header handling.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
)

// DecisionMaker is the registry boundary; only its committed decision may allow a request.
type DecisionMaker interface {
	AuthorizeGateway(context.Context, uuid.UUID, string, muistamov1.GatewayAuthorizationRequest, *muistamov1.GatewayModelRoute) (muistamov1.GatewayAuthorizationDecision, error)
}

// Authorization serves exactly one tenant and protocol kind from trusted listener config.
type Authorization struct {
	auth.UnimplementedAuthorizationServer
	decisions DecisionMaker
	tenant    uuid.UUID
	kind      muistamov1.GatewayAuthorizationRequestKind
	digest    string
	routes    map[string]muistamov1.GatewayModelRoute
	log       *slog.Logger
}

// ConfigDigest binds both sides to the same normalized route configuration. Any route or
// revision change requires the gateway and checker to agree before more calls are allowed.
func ConfigDigest(cfg muistamov1.GatewayAuthzConfig) string {
	body, _ := json.Marshal(cfg) // generated fields contain only UUIDs, strings and integers
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func NewAuthorization(decisions DecisionMaker, cfg muistamov1.GatewayAuthzConfig, kind muistamov1.GatewayAuthorizationRequestKind, log *slog.Logger) (*Authorization, error) {
	if decisions == nil || log == nil || cfg.TenantId == uuid.Nil || len(cfg.Models) == 0 || (kind != "model" && kind != "mcp") {
		return nil, errors.New("gateway authorization requires a tenant, models, registry, logger and explicit protocol")
	}
	s := &Authorization{decisions: decisions, tenant: cfg.TenantId, kind: kind, digest: ConfigDigest(cfg), routes: map[string]muistamov1.GatewayModelRoute{}, log: log}
	for _, route := range cfg.Models {
		target, err := url.Parse(route.BaseUrl)
		if err != nil || target.Opaque != "" || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" || strings.Contains(route.BaseUrl, "#") || strings.IndexFunc(route.BaseUrl, func(c rune) bool { return c < 0x20 || c == 0x7f }) >= 0 {
			return nil, errors.New("gateway deployment URL must be HTTP(S) without credentials, query, fragment or control characters")
		}
		if route.Alias == "" || route.CatalogueName == "" || route.AliasRevision < 1 || route.ModelRevision < 1 || route.Provider == "" || route.Model == "" || route.Region == "" {
			return nil, errors.New("gateway route requires an exact alias, catalogue/model revision, provider, model and region")
		}
		if _, duplicate := s.routes[route.Alias]; duplicate {
			return nil, errors.New("gateway route aliases must be unique")
		}
		s.routes[route.Alias] = route
	}
	return s, nil
}

func value(req *auth.CheckRequest, namespace string) (string, bool) {
	meta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()[namespace]
	v, ok := meta.GetFields()["value"].GetKind().(*structpb.Value_StringValue)
	if !ok {
		return "", false
	}
	return v.StringValue, true
}

func (s *Authorization) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	h := req.GetAttributes().GetRequest().GetHttp()
	headers := map[string]string{}
	valid := h != nil && h.GetHeaderMap() == nil && h.GetBody() == "" && len(h.GetRawBody()) == 0 && h.GetQuery() == "" && h.GetFragment() == ""
	for name, v := range h.GetHeaders() {
		name = strings.ToLower(name)
		if _, duplicate := headers[name]; duplicate {
			valid = false
		}
		headers[name] = v
	}
	fingerprint, hasFingerprint := value(req, "muistamo.config")
	alias, hasAlias := value(req, "muistamo.model")
	meta := req.GetAttributes().GetMetadataContext().GetFilterMetadata()
	valid = valid && hasFingerprint && fingerprint == s.digest && hasAlias && alias != "" && meta["muistamo.method"] == nil && meta["muistamo.tool"] == nil
	call := muistamov1.GatewayAuthorizationRequest{Kind: s.kind, Method: h.GetMethod(), Path: h.GetPath(), MetadataValid: valid, Alias: &alias}
	scheme, token, ok := strings.Cut(headers["authorization"], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.ContainsAny(token, " ,\t\r\n") {
		token = ""
	}
	var route *muistamov1.GatewayModelRoute
	if r, exists := s.routes[alias]; exists {
		route = &r
	}
	d, err := s.decisions.AuthorizeGateway(ctx, s.tenant, token, call, route)
	// Do not log raw headers, paths, metadata, errors carrying SQL inputs, or credentials.
	s.log.Info("gateway authorization", "request_id", d.RequestId, "agent", d.Instance, "person", d.Person, "allowed", err == nil && d.Allowed, "reason", d.Reason)
	if err != nil || !d.Allowed || d.Instance == nil || d.Person == nil {
		return denied(), nil
	}
	okResponse := &auth.OkHttpResponse{HeadersToRemove: []string{"authorization"}}
	for name := range headers {
		if strings.HasPrefix(name, "x-muistamo-") {
			okResponse.HeadersToRemove = append(okResponse.HeadersToRemove, name)
		}
	}
	identity := map[string]string{"x-muistamo-agent": *d.Instance, "x-muistamo-person": *d.Person, "x-muistamo-request-id": d.RequestId.String()}
	if d.CostCentre != nil && *d.CostCentre != "" {
		identity["x-muistamo-cost-centre"] = *d.CostCentre
	}
	for name, v := range identity {
		if strings.ContainsAny(v, "\r\n\x00") {
			return denied(), nil
		}
		// Removal and overwrite lists must be disjoint: gateways can apply removal last.
		okResponse.HeadersToRemove = slices.DeleteFunc(okResponse.HeadersToRemove, func(n string) bool { return n == name })
		okResponse.Headers = append(okResponse.Headers, &core.HeaderValueOption{Header: &core.HeaderValue{Key: name, Value: v}, AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD})
	}
	slices.Sort(okResponse.HeadersToRemove)
	return &auth.CheckResponse{Status: &status.Status{Code: int32(codes.OK)}, HttpResponse: &auth.CheckResponse_OkResponse{OkResponse: okResponse}}, nil
}

func denied() *auth.CheckResponse {
	return &auth.CheckResponse{Status: &status.Status{Code: int32(codes.PermissionDenied)}, HttpResponse: &auth.CheckResponse_DeniedResponse{DeniedResponse: &auth.DeniedHttpResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden}, Body: `{"error":"gateway authorization refused"}`,
	}}}
}

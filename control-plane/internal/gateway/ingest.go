package gateway

// HUMAN REVIEW REQUIRED: ingest authentication and which gateway records become usage.
//
// The pinned agentgateway exports one OTLP log record per request (docs/agentgateway-
// validation-2026-10-28.md, results 7 and 8, and the 2026-10-29 addendum). Only records for a
// call the checker authorized carry muistamo.request_id; those become usage records, priced by
// the registry from the call's snapshot. Export loss is normal: an authorized call whose record
// never arrives is reported as unmetered, never estimated.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"muistamo.dev/muistamo/contracts/gen/go/muistamov1"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// IngestTokenEnv is the variable the rendered gateway configuration reads its export credential
// from. It is outside the MUISTAMO_PROVIDER_KEY_* names a route may reference, so no route can
// send it upstream.
const IngestTokenEnv = "MUISTAMO_GATEWAY_INGEST_TOKEN"

// MinIngestTokenBytes is the shortest export credential the ingest server accepts.
const MinIngestTokenBytes = 32

// MaxRecordsPerExport bounds one export, so a batch is one bounded transaction and one bounded
// evidence event. The gateway's exporter sends far smaller batches; larger ones are refused.
const MaxRecordsPerExport = 2048

// exportDeadline bounds the time one export may hold its transaction.
const exportDeadline = 30 * time.Second

// openAISemantics are the providers whose input token count includes cached tokens, the
// convention the pricing formula assumes. Others are refused until their usage is validated.
var openAISemantics = map[string]bool{"openai": true}

// UsageRecorder is the registry boundary: it prices and records usage, with evidence.
type UsageRecorder interface {
	RecordUsage(context.Context, uuid.UUID, []registry.UsageLine) (registry.UsageIngest, error)
}

// Ingest receives one tenant's gateway access logs over OTLP/gRPC.
type Ingest struct {
	collogs.UnimplementedLogsServiceServer
	usage  UsageRecorder
	tenant uuid.UUID
	bearer [sha256.Size]byte
	log    *slog.Logger
}

// NewIngest serves the tenant of the same configuration the checker serves.
func NewIngest(usage UsageRecorder, cfg muistamov1.GatewayAuthzConfig, token []byte, log *slog.Logger) (*Ingest, error) {
	if usage == nil || log == nil {
		return nil, errors.New("gateway ingest requires a registry and logger")
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if len(token) < MinIngestTokenBytes {
		return nil, errors.New("gateway ingest token must be at least 32 bytes")
	}
	return &Ingest{usage: usage, tenant: cfg.TenantId, bearer: sha256.Sum256(append([]byte("Bearer "), token...)), log: log}, nil
}

// authenticated compares hashes in constant time, so neither the token nor its length leaks.
func (s *Ingest) authenticated(ctx context.Context) bool {
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) != 1 {
		return false
	}
	presented := sha256.Sum256([]byte(values[0]))
	return subtle.ConstantTimeCompare(presented[:], s.bearer[:]) == 1
}

// Export records the usage in one export. Records the checker never authorized (they carry no
// request id) are ignored; malformed or unmatched ones are rejected and counted, never stored.
func (s *Ingest) Export(ctx context.Context, req *collogs.ExportLogsServiceRequest) (*collogs.ExportLogsServiceResponse, error) {
	if !s.authenticated(ctx) {
		s.log.Warn("gateway usage export refused: unauthenticated")
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}
	records := 0
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			records += len(sl.GetLogRecords())
		}
	}
	if records > MaxRecordsPerExport {
		s.log.Warn("gateway usage export refused: too many records", "tenant", s.tenant, "records", records)
		return nil, status.Error(codes.InvalidArgument, "too many records in one export")
	}
	ctx, cancel := context.WithTimeout(ctx, exportDeadline)
	defer cancel()
	var lines []registry.UsageLine
	invalid := map[string]int{}
	refused, ungoverned := 0, 0
	for _, rl := range req.GetResourceLogs() {
		for _, sl := range rl.GetScopeLogs() {
			for _, r := range sl.GetLogRecords() {
				l, reason := usageLine(r.GetAttributes())
				switch reason {
				case "":
					lines = append(lines, l)
				case "refused-call":
					refused++
				case "ungoverned-call":
					ungoverned++
				default:
					invalid[reason]++
				}
			}
		}
	}
	if ungoverned > 0 {
		// The checker gives every call it allows a request id, and the gateway fails closed. A
		// successful model call without one ran outside Muistamo's authorization: observed,
		// not governed (invariant 8). It is never recorded as usage.
		s.log.Warn("gateway reported successful model calls without a Muistamo authorization", "tenant", s.tenant, "calls", ungoverned)
	}
	var result registry.UsageIngest
	if len(lines) > 0 {
		var err error
		if result, err = s.usage.RecordUsage(ctx, s.tenant, lines); err != nil {
			s.log.Error("gateway usage not recorded", "tenant", s.tenant, "records", len(lines), "error", err)
			if errors.Is(err, registry.ErrInvalid) {
				// Malformed input fails the same way every time: never ask for a retry.
				return nil, status.Error(codes.InvalidArgument, "usage not recorded: invalid records")
			}
			// A transient failure: the gateway may resend; until then these calls show as unmetered.
			return nil, status.Error(codes.Unavailable, "usage not recorded")
		}
	}
	rejected := result.Conflicting + result.Unmatched + ungoverned
	for _, n := range invalid {
		rejected += n
	}
	if result.Conflicting > 0 {
		s.log.Warn("gateway reported different usage for already metered calls; the first record is kept",
			"tenant", s.tenant, "requests", result.ConflictingIDs)
	}
	level := slog.LevelInfo
	if rejected > 0 {
		level = slog.LevelWarn
	}
	s.log.Log(ctx, level, "gateway usage ingested", "tenant", s.tenant, "accepted", len(result.Accepted), "duplicate", result.Duplicate,
		"conflicting", result.Conflicting, "unmatched", result.Unmatched, "invalid", invalid, "refused_calls", refused, "ungoverned_calls", ungoverned)
	resp := &collogs.ExportLogsServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &collogs.ExportLogsPartialSuccess{RejectedLogRecords: int64(rejected),
			ErrorMessage: "records without a matching authorized model call, or malformed, were not recorded"}
	}
	return resp, nil
}

// usageLine reads one access-log record. The reason is empty for a usable usage line.
func usageLine(attrs []*common.KeyValue) (registry.UsageLine, string) {
	a := map[string]*common.AnyValue{}
	for _, kv := range attrs {
		if _, duplicate := a[kv.GetKey()]; duplicate {
			return registry.UsageLine{}, "duplicate-attribute"
		}
		a[kv.GetKey()] = kv.GetValue()
	}
	str := func(k string) (string, bool) {
		v, ok := a[k].GetValue().(*common.AnyValue_StringValue)
		if !ok {
			return "", false
		}
		return v.StringValue, true
	}
	num := func(k string) (int64, bool) {
		v, ok := a[k].GetValue().(*common.AnyValue_IntValue)
		if !ok {
			return 0, false
		}
		return v.IntValue, true
	}
	raw, ok := str("muistamo.request_id")
	if !ok || raw == "" {
		// Calls the checker refused get no request id. A successful model call without one is
		// not refused: it ran ungoverned.
		code, _ := num("http.response.status_code")
		if p, _ := str("protocol"); p == "llm" && code >= 200 && code <= 299 {
			return registry.UsageLine{}, "ungoverned-call"
		}
		return registry.UsageLine{}, "refused-call"
	}
	id, err := uuid.Parse(raw)
	if err != nil || id.String() != raw {
		return registry.UsageLine{}, "invalid-request-id"
	}
	if p, _ := str("protocol"); p != "llm" {
		return registry.UsageLine{}, "not-a-model-call"
	}
	// The only path the checker authorizes (rule 1); anything else is not metered usage.
	if path, _ := str("url.path"); path != "/v1/chat/completions" {
		return registry.UsageLine{}, "unmetered-path"
	}
	if code, ok := num("http.response.status_code"); !ok || code < 200 || code > 299 {
		return registry.UsageLine{}, "not-successful"
	}
	model, ok := str("gen_ai.request.model")
	if !ok || model == "" {
		return registry.UsageLine{}, "no-model"
	}
	if provider, _ := str("gen_ai.provider.name"); !openAISemantics[provider] {
		return registry.UsageLine{}, "unvalidated-provider-usage"
	}
	_, hasIn := a["gen_ai.usage.input_tokens"]
	_, hasOut := a["gen_ai.usage.output_tokens"]
	if !hasIn && !hasOut {
		// The call ran (authorized, successful) but the gateway reported no usage, as for a stream
		// the client aborted: recorded as such and counted against the key's cap, never priced.
		response, _ := str("gen_ai.response.model")
		return registry.UsageLine{RequestID: id, Model: model, ResponseModel: response, UsageMissing: true}, ""
	}
	in, okIn := num("gen_ai.usage.input_tokens")
	out, okOut := num("gen_ai.usage.output_tokens")
	if !okIn || !okOut {
		return registry.UsageLine{}, "partial-usage"
	}
	cached := int64(0)
	if _, present := a["gen_ai.usage.cache_read.input_tokens"]; present {
		if cached, ok = num("gen_ai.usage.cache_read.input_tokens"); !ok {
			return registry.UsageLine{}, "invalid-tokens"
		}
	}
	if in < 0 || out < 0 || cached < 0 || cached > in || in > registry.MaxTokens || out > registry.MaxTokens {
		return registry.UsageLine{}, "invalid-tokens"
	}
	response, _ := str("gen_ai.response.model")
	return registry.UsageLine{RequestID: id, Model: model, ResponseModel: response, InputTokens: in, CachedInputTokens: cached, OutputTokens: out}, ""
}

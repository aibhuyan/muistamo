package gateway_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	logs "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"muistamo.dev/muistamo/control-plane/internal/gateway"
	"muistamo.dev/muistamo/control-plane/internal/registry"
)

// HUMAN REVIEW REQUIRED: ingest authentication and record selection.

const ingestToken = "fake-ingest-token-not-a-secret-0123456789"

type usageRecorder struct {
	lines []registry.UsageLine
	calls int
	err   error
}

func (r *usageRecorder) RecordUsage(_ context.Context, _ uuid.UUID, lines []registry.UsageLine) (registry.UsageIngest, error) {
	r.calls++
	r.lines = append(r.lines, lines...)
	if r.err != nil {
		return registry.UsageIngest{}, r.err
	}
	var out registry.UsageIngest
	for _, l := range lines {
		out.Accepted = append(out.Accepted, l.RequestID)
	}
	return out, nil
}

func ingest(t *testing.T, r *usageRecorder) *gateway.Ingest {
	t.Helper()
	s, err := gateway.NewIngest(r, renderFixture(), []byte(ingestToken), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func authed(values ...string) context.Context {
	md := metadata.MD{}
	for _, v := range values {
		md.Append("authorization", v)
	}
	return metadata.NewIncomingContext(context.Background(), md)
}

func attr(k string, v any) *common.KeyValue {
	switch x := v.(type) {
	case string:
		return &common.KeyValue{Key: k, Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: x}}}
	case int:
		return &common.KeyValue{Key: k, Value: &common.AnyValue{Value: &common.AnyValue_IntValue{IntValue: int64(x)}}}
	}
	panic("unsupported attribute")
}

// record is the gateway's access-log record for an authorized, successful model call.
func record(id uuid.UUID, change func(map[string]any)) *logs.LogRecord {
	a := map[string]any{
		"muistamo.request_id": id.String(), "protocol": "llm", "url.path": "/v1/chat/completions",
		"http.response.status_code": 200, "gen_ai.request.model": "test-model", "gen_ai.response.model": "test-model",
		"gen_ai.usage.input_tokens": 7, "gen_ai.usage.cache_read.input_tokens": 4, "gen_ai.usage.output_tokens": 3,
	}
	if change != nil {
		change(a)
	}
	r := &logs.LogRecord{}
	for k, v := range a {
		if v != nil {
			r.Attributes = append(r.Attributes, attr(k, v))
		}
	}
	return r
}

func export(records ...*logs.LogRecord) *collogs.ExportLogsServiceRequest {
	return &collogs.ExportLogsServiceRequest{ResourceLogs: []*logs.ResourceLogs{{ScopeLogs: []*logs.ScopeLogs{{LogRecords: records}}}}}
}

func TestIngestRefusesUnauthenticatedExports(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"no metadata":  context.Background(),
		"no bearer":    authed(),
		"wrong token":  authed("Bearer fake-wrong-token-not-a-secret-0123456789"),
		"bare token":   authed(ingestToken),
		"prefix only":  authed("Bearer " + ingestToken[:20]),
		"two bearers":  authed("Bearer "+ingestToken, "Bearer "+ingestToken),
		"other scheme": authed("Basic " + ingestToken),
	} {
		r := &usageRecorder{}
		_, err := ingest(t, r).Export(ctx, export(record(uuid.New(), nil)))
		if status.Code(err) != codes.Unauthenticated || r.calls != 0 {
			t.Errorf("%s: err %v, recorder called %d times", name, err, r.calls)
		}
	}
}

func TestIngestRecordsOnlyAuthorizedSuccessfulModelUsage(t *testing.T) {
	r := &usageRecorder{}
	good := uuid.New()
	refused := record(uuid.Nil, func(a map[string]any) { delete(a, "muistamo.request_id"); a["http.response.status_code"] = 403 })
	bad := map[string]func(map[string]any){
		"mcp":            func(a map[string]any) { a["protocol"] = "mcp" },
		"other path":     func(a map[string]any) { a["url.path"] = "/v1/anything" },
		"upper path":     func(a map[string]any) { a["url.path"] = "/V1/CHAT/COMPLETIONS" },
		"failed":         func(a map[string]any) { a["http.response.status_code"] = 500 },
		"status as text": func(a map[string]any) { a["http.response.status_code"] = "200" },
		"no model":       func(a map[string]any) { delete(a, "gen_ai.request.model") },
		"no input":       func(a map[string]any) { delete(a, "gen_ai.usage.input_tokens") },
		"no output":      func(a map[string]any) { delete(a, "gen_ai.usage.output_tokens") },
		"text tokens":    func(a map[string]any) { a["gen_ai.usage.output_tokens"] = "3" },
		"negative":       func(a map[string]any) { a["gen_ai.usage.input_tokens"] = -1 },
		"cached > input": func(a map[string]any) { a["gen_ai.usage.cache_read.input_tokens"] = 8 },
		"cached as text": func(a map[string]any) { a["gen_ai.usage.cache_read.input_tokens"] = "4" },
		"uppercase id":   func(a map[string]any) { a["muistamo.request_id"] = "ABCDEF00-0000-4000-8000-000000000000" },
		"not an id":      func(a map[string]any) { a["muistamo.request_id"] = "req-1" },
	}
	records := []*logs.LogRecord{record(good, nil), refused}
	for _, change := range bad {
		records = append(records, record(uuid.New(), change))
	}
	dup := record(uuid.New(), nil)
	dup.Attributes = append(dup.Attributes, attr("gen_ai.usage.output_tokens", 99))
	records = append(records, dup)

	resp, err := ingest(t, r).Export(authed("Bearer "+ingestToken), export(records...))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.lines) != 1 {
		t.Fatalf("recorded %d lines, want only the authorized successful call: %+v", len(r.lines), r.lines)
	}
	l := r.lines[0]
	if l.RequestID != good || l.Model != "test-model" || l.InputTokens != 7 || l.CachedInputTokens != 4 || l.OutputTokens != 3 {
		t.Fatalf("line = %+v", l)
	}
	// Every malformed record is rejected; the refused call (no request id) is not.
	if got, want := resp.GetPartialSuccess().GetRejectedLogRecords(), int64(len(bad)+1); got != want {
		t.Fatalf("rejected = %d, want %d", got, want)
	}
}

func TestIngestCachedTokensDefaultToZero(t *testing.T) {
	r := &usageRecorder{}
	_, err := ingest(t, r).Export(authed("Bearer "+ingestToken), export(record(uuid.New(), func(a map[string]any) {
		delete(a, "gen_ai.usage.cache_read.input_tokens")
	})))
	if err != nil || len(r.lines) != 1 || r.lines[0].CachedInputTokens != 0 {
		t.Fatalf("lines = %+v, %v", r.lines, err)
	}
}

func TestIngestReportsAnUnrecordedBatch(t *testing.T) {
	r := &usageRecorder{err: errors.New("evidence unavailable")}
	if _, err := ingest(t, r).Export(authed("Bearer "+ingestToken), export(record(uuid.New(), nil))); status.Code(err) != codes.Unavailable {
		t.Fatalf("unrecorded batch = %v, want Unavailable", err)
	}
}

func TestIngestRequiresALongToken(t *testing.T) {
	if _, err := gateway.NewIngest(&usageRecorder{}, renderFixture(), []byte("short-fake-token"), slog.Default()); err == nil {
		t.Fatal("a short ingest token was accepted")
	}
}

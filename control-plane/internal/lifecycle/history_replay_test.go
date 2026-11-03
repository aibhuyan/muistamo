package lifecycle_test

// Replays real recorded Temporal histories of the live (Entra) workflows through today's code. A
// change that would break a workflow already running in production, one that is in its grace
// period or waiting for a review, fails here as a non-determinism error instead of in a worker.
//
// testdata/histories holds, per release, histories recorded by history_record_test.go:
//   - pre-45-*: left in flight by the release before live leaver reviews (#45): a leaver in
//     grace, a leaver rehired in grace, a joiner after its user-link step;
//   - current-*: the same from today's code, plus a leaver waiting for a kept review.
//
// When a release changes these workflows, record its histories as a new set first (they become
// the next release's in-flight state), and keep every older set.

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.temporal.io/sdk/log"
	"go.temporal.io/sdk/worker"

	"muistamo.dev/muistamo/control-plane/internal/lifecycle"
)

func TestRecordedHistoriesReplayDeterministically(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "histories", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	count := func(prefix string) int {
		n := 0
		for _, f := range files {
			if strings.HasPrefix(filepath.Base(f), prefix) {
				n++
			}
		}
		return n
	}
	if count("pre-45-") < 3 || count("current-") < 4 {
		t.Fatalf("histories = %v; want the pre-45 and current sets", files)
	}
	logger := log.NewStructuredLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			replayer := worker.NewWorkflowReplayer()
			replayer.RegisterWorkflow(lifecycle.EntraLeaver)
			replayer.RegisterWorkflow(lifecycle.EntraJoiner)
			if err := replayer.ReplayWorkflowHistoryFromJSONFile(logger, f); err != nil {
				t.Fatalf("replaying %s: %v", f, err)
			}
		})
	}
}

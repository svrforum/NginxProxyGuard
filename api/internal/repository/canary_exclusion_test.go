package repository

import (
	"os"
	"strings"
	"testing"
)

// Guards #191: PipelineCanary self-test rows must never inflate user-facing log
// lists or statistics. The exclusion lives in the shared canaryURIExclusion const
// (filter-on-read — the rows must stay in the table for CanaryRowExists). This was
// originally hand-wired into only two paths, so other aggregations silently counted
// canary traffic. This test fails if the const drifts or if a file that aggregates
// logs_partitioned for users stops referencing it — forcing new aggregations to use
// the shared guard. (go test runs with CWD = package dir, so relative paths work.)
func TestCanaryExclusionWiredIntoStatsQueries(t *testing.T) {
	if !strings.Contains(canaryURIExclusion, "/__npg_canary") {
		t.Fatalf("canaryURIExclusion must filter /__npg_canary; got %q", canaryURIExclusion)
	}
	for _, f := range []string{"log.go", "log_stats.go", "dashboard.go", "log_queries.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if !strings.Contains(string(src), "canaryURIExclusion") {
			t.Errorf("%s reads logs_partitioned for users but does not reference canaryURIExclusion (#191)", f)
		}
	}
}

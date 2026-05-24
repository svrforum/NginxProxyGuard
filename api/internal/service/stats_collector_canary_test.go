package service

import (
	"strings"
	"testing"
)

// The aggregation query must exclude canary self-test rows so they never
// inflate dashboard request counts.
func TestAggregateQueryExcludesCanary(t *testing.T) {
	if !strings.Contains(aggregateStatsQuery, "/__npg_canary") {
		t.Errorf("aggregateStatsQuery must exclude /__npg_canary; got:\n%s", aggregateStatsQuery)
	}
}

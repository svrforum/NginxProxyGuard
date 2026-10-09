package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRegisterRawLogMetricsIsIdempotent(t *testing.T) {
	RegisterRawLogMetrics()
	RegisterRawLogMetrics() // must not panic on double registration
}

func TestRawLogRotateRunsCountByModeAndResult(t *testing.T) {
	c := RawLogRotateRunsTotal.WithLabelValues("if_due", "not_due")
	before := testutil.ToFloat64(c)
	c.Inc()
	if got := testutil.ToFloat64(c); got != before+1 {
		t.Fatalf("npg_raw_log_rotate_runs_total{mode=if_due,result=not_due} = %v, want %v", got, before+1)
	}
}

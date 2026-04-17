package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestReloadCountersIncrement(t *testing.T) {
	before := testutil.ToFloat64(NginxReloadTotal.WithLabelValues("success"))
	NginxReloadTotal.WithLabelValues("success").Inc()
	after := testutil.ToFloat64(NginxReloadTotal.WithLabelValues("success"))
	if after-before != 1 {
		t.Errorf("counter delta = %v, want 1", after-before)
	}
}

func TestRollbackReasonLabels(t *testing.T) {
	reasons := []string{"test_failed", "reload_failed", "health_failed", "retry_exhausted"}
	for _, r := range reasons {
		// Ensure the label is accepted (no panic/error) and counter is reachable.
		NginxReloadRollbackTotal.WithLabelValues(r).Inc()
		got := testutil.ToFloat64(NginxReloadRollbackTotal.WithLabelValues(r))
		if got < 1 {
			t.Errorf("reason=%q counter not incremented", r)
		}
	}
}

func TestHistogramObservesDuration(t *testing.T) {
	NginxReloadDurationSeconds.Observe(0.42)
	// CollectAndCount returns the number of samples observed across all
	// buckets. We just assert the Observe call succeeded and at least one
	// sample is reachable.
	got := testutil.CollectAndCount(NginxReloadDurationSeconds)
	if got < 1 {
		t.Errorf("expected at least 1 sample collected, got %d", got)
	}
}

func TestGaugeSet(t *testing.T) {
	NginxConfigStatus.WithLabelValues("host-xyz").Set(1)
	if v := testutil.ToFloat64(NginxConfigStatus.WithLabelValues("host-xyz")); v != 1 {
		t.Errorf("gauge = %v, want 1", v)
	}
}

func TestHealthProbeFailureLabels(t *testing.T) {
	labels := []string{"workers", "http"}
	for _, l := range labels {
		NginxHealthProbeFailureTotal.WithLabelValues(l).Inc()
		if v := testutil.ToFloat64(NginxHealthProbeFailureTotal.WithLabelValues(l)); v < 1 {
			t.Errorf("probe=%q not incremented", l)
		}
	}
}

// TestRegisterIsIdempotent verifies that calling Register() multiple times is
// safe. The sync.Once guard in metrics.go means only the first call touches
// the default registry; subsequent calls are no-ops.
func TestRegisterIsIdempotent(t *testing.T) {
	// Both calls should succeed without panic (sync.Once guard).
	Register()
	Register()
}

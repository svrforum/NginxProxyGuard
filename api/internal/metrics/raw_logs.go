package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Raw nginx log file metrics: rotation runs (nginx.Manager.RotateLogs and
// RotateLogsScheduled). Kept out of metrics.go and registered by their own
// RegisterRawLogMetrics, called where the log rotation scheduler is wired.
var (
	// RawLogRotateRunsTotal counts logrotate runs by mode and result.
	//
	// mode: forced (00:00), if_due (every other hour: cuts only past the
	// size limit or on a new day), manual ("Rotate now").
	// result: rotated, not_due, empty, already_rotated, busy, no_config, error.
	RawLogRotateRunsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "npg_raw_log_rotate_runs_total",
		Help: "Raw nginx log rotation runs by mode (forced, if_due, manual) and result.",
	}, []string{"mode", "result"})
)

var registerRawLogOnce sync.Once

// RegisterRawLogMetrics adds the raw log metrics to the default registry.
// Safe to call more than once.
func RegisterRawLogMetrics() {
	registerRawLogOnce.Do(func() {
		prometheus.MustRegister(RawLogRotateRunsTotal)
	})
}

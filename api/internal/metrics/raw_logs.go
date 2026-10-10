package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Raw nginx log file metrics: rotation runs (nginx.Manager.RotateLogs and
// RotateLogsScheduled) and the archive mover (service.RawLogArchiver). Kept
// out of metrics.go and registered by their own RegisterRawLogMetrics, called
// where the log rotation scheduler is wired.
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

	// RawLogArchiveMovedFilesTotal and RawLogArchiveMovedBytesTotal count
	// rotated raw logs moved to the archive directory.
	RawLogArchiveMovedFilesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "npg_raw_log_archive_moved_files_total",
		Help: "Rotated raw log files moved to the archive directory.",
	})
	RawLogArchiveMovedBytesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "npg_raw_log_archive_moved_bytes_total",
		Help: "Bytes of rotated raw log files moved to the archive directory.",
	})

	// RawLogArchivePrunedFilesTotal counts archived files deleted past the
	// archive retention.
	RawLogArchivePrunedFilesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "npg_raw_log_archive_pruned_files_total",
		Help: "Archived raw log files deleted past the archive retention.",
	})

	// RawLogArchiveStatus is 1 for the archive's current status and 0 for
	// the others.
	RawLogArchiveStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "npg_raw_log_archive_status",
		Help: "Raw log archive status: 1 for the current one (disabled, not_mounted, not_initialized, foreign, unwritable, insufficient_space, stalled, ready, log_dir).",
	}, []string{"status"})
)

// rawLogArchiveStatuses are the values service.RawLogArchiver reports.
var rawLogArchiveStatuses = []string{
	"disabled", "not_mounted", "not_initialized", "foreign",
	"unwritable", "insufficient_space", "stalled", "ready", "log_dir",
}

// SetRawLogArchiveStatus marks status as the archive's current one.
func SetRawLogArchiveStatus(status string) {
	for _, s := range rawLogArchiveStatuses {
		v := 0.0
		if s == status {
			v = 1
		}
		RawLogArchiveStatus.WithLabelValues(s).Set(v)
	}
}

var registerRawLogOnce sync.Once

// RegisterRawLogMetrics adds the raw log metrics to the default registry.
// Safe to call more than once.
func RegisterRawLogMetrics() {
	registerRawLogOnce.Do(func() {
		prometheus.MustRegister(
			RawLogRotateRunsTotal,
			RawLogArchiveMovedFilesTotal,
			RawLogArchiveMovedBytesTotal,
			RawLogArchivePrunedFilesTotal,
			RawLogArchiveStatus,
		)
	})
}

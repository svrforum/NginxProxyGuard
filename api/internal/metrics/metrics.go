// Package metrics defines the Prometheus instruments used across the proxy
// reload, health-probe, and auto-recovery paths. Metrics are created at
// package-init time and registered with the default registry via Register(),
// which is guarded by sync.Once so duplicate calls (tests, init-order quirks)
// do not panic.
package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Counters

	// NginxReloadTotal counts reload attempts by their final status
	// ("success" or "failed").
	NginxReloadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginx_reload_total",
		Help: "Total nginx reload attempts by final status.",
	}, []string{"status"})

	// NginxReloadRetryTotal counts individual retry attempts during reload
	// (does not count the first attempt).
	NginxReloadRetryTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nginx_reload_retry_total",
		Help: "Total individual retry attempts during reload (does not count the first attempt).",
	})

	// NginxReloadRollbackTotal counts config rollbacks by reason
	// ("test_failed", "reload_failed", "health_failed", "retry_exhausted").
	NginxReloadRollbackTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginx_reload_rollback_total",
		Help: "Total config rollbacks by reason.",
	}, []string{"reason"})

	// NginxHealthProbeFailureTotal counts health probe failures by probe type
	// ("workers", "http").
	NginxHealthProbeFailureTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nginx_health_probe_failure_total",
		Help: "Total health probe failures by probe type.",
	}, []string{"probe"})

	// NginxAutoRecoveryTotal counts hosts isolated by SyncAllConfigs auto-recovery.
	NginxAutoRecoveryTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nginx_auto_recovery_total",
		Help: "Total hosts isolated by SyncAllConfigs auto-recovery.",
	})

	// Histograms

	// NginxReloadDurationSeconds tracks the end-to-end duration of
	// testAndReloadNginxWithRetry including retries and health verification.
	NginxReloadDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_reload_duration_seconds",
		Help:    "End-to-end duration of testAndReloadNginxWithRetry including retries and health verification.",
		Buckets: prometheus.ExponentialBuckets(0.05, 2, 9),
	})

	// NginxConfigGenerationDurationSeconds tracks the duration of per-host
	// config data aggregation plus template rendering.
	NginxConfigGenerationDurationSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_config_generation_duration_seconds",
		Help:    "Duration of per-host config data aggregation plus template rendering.",
		Buckets: prometheus.DefBuckets,
	})

	// NginxHealthProbeDurationSeconds tracks the duration of each health probe phase.
	NginxHealthProbeDurationSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "nginx_health_probe_duration_seconds",
		Help:    "Duration of each health probe phase.",
		Buckets: prometheus.ExponentialBuckets(0.01, 2, 8),
	}, []string{"probe"})

	// Gauges

	// NginxConfigStatus exposes per-host config status (1=ok, 0=error).
	NginxConfigStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nginx_config_status",
		Help: "Current config status per host (1=ok, 0=error).",
	}, []string{"host_id"})

	// NginxLastReloadTimestampSeconds exposes the unix timestamp of the last
	// successful nginx reload.
	NginxLastReloadTimestampSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "nginx_last_reload_timestamp_seconds",
		Help: "Unix timestamp of the last successful nginx reload.",
	})

	// LogCollector instruments

	// LogCollectorFallbackTotal counts startup fallbacks where the configured
	// NGINX_ACCESS_LOG path is unusable (ENOENT or /dev/* symlink) and
	// resolveTailPath redirects to the canonical /etc/nginx/logs/access_raw.log.
	// A non-zero value identifies upgrades that kept the legacy compose env.
	LogCollectorFallbackTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "npg_log_collector_fallback_total",
		Help: "Total times resolveTailPath fell back from the configured NGINX_ACCESS_LOG to the canonical path.",
	})

	// LogCollectorFlushedTotal counts log entries inserted to DB by log_type.
	LogCollectorFlushedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "npg_log_collector_flushed_total",
		Help: "Total log entries flushed to the DB by log_type.",
	}, []string{"log_type"})

	// LogCollectorParseErrorsTotal counts lines that failed to parse, by source.
	LogCollectorParseErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "npg_log_collector_parse_errors_total",
		Help: "Total log lines that failed to parse, by source.",
	}, []string{"source"})

	// LogCollectorBufferSize exposes the current pending entries in each
	// buffer (redis / memory). Sampled at flush time.
	LogCollectorBufferSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "npg_log_collector_buffer_size",
		Help: "Number of log entries currently buffered.",
	}, []string{"buffer"})

	// LogCollectorWatchdogRestartTotal counts docker-logs subprocess restarts
	// triggered by the watchdog. Reasons: "idle" (no data for streamIdleThreshold)
	// or "max_age" (cmd lifetime exceeded streamMaxAge).
	LogCollectorWatchdogRestartTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "npg_log_collector_watchdog_restart_total",
		Help: "Total docker-logs subprocess restarts triggered by the watchdog.",
	}, []string{"reason"})
)

// registerOnce guards Register so duplicate calls (tests, init-order quirks)
// do not trigger prometheus.MustRegister's double-register panic.
var registerOnce sync.Once

// Register adds all metrics to the default Prometheus registry. Safe to call
// multiple times — the underlying prometheus.MustRegister call is guarded by
// sync.Once so only the first call takes effect.
func Register() {
	registerOnce.Do(func() {
		prometheus.MustRegister(
			NginxReloadTotal,
			NginxReloadRetryTotal,
			NginxReloadRollbackTotal,
			NginxHealthProbeFailureTotal,
			NginxAutoRecoveryTotal,
			NginxReloadDurationSeconds,
			NginxConfigGenerationDurationSeconds,
			NginxHealthProbeDurationSeconds,
			NginxConfigStatus,
			NginxLastReloadTimestampSeconds,
			LogCollectorFallbackTotal,
			LogCollectorFlushedTotal,
			LogCollectorParseErrorsTotal,
			LogCollectorBufferSize,
			LogCollectorWatchdogRestartTotal,
		)
	})
}

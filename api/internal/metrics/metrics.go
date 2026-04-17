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
		)
	})
}

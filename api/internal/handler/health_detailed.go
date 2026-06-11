package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
	"nginx-proxy-guard/pkg/cache"
)

// HealthDetailedHandler serves /api/v1/health/detailed — an authenticated,
// read-only diagnostic snapshot used by operators to inspect storage usage,
// compression effectiveness, LogCollector fallback state, and Redis health.
// All sub-queries are bounded by a short context timeout so a stuck DB or
// Redis cannot stall the handler indefinitely.
type HealthDetailedHandler struct {
	startedAt   time.Time
	repo        *repository.HealthDetailedRepository
	logCollect  *service.LogCollector
	redis       *cache.RedisClient
	proxyRepo   *repository.ProxyHostRepository
	settingsRepo *repository.GlobalSettingsRepository
	canary      *service.PipelineCanary
	stats       *service.StatsCollector
	db          *database.DB
}

func NewHealthDetailedHandler(
	repo *repository.HealthDetailedRepository,
	logCollect *service.LogCollector,
	redis *cache.RedisClient,
	proxyRepo *repository.ProxyHostRepository,
	settingsRepo *repository.GlobalSettingsRepository,
	canary *service.PipelineCanary,
	stats *service.StatsCollector,
	db *database.DB,
) *HealthDetailedHandler {
	return &HealthDetailedHandler{
		startedAt:    time.Now(),
		repo:         repo,
		logCollect:   logCollect,
		redis:        redis,
		proxyRepo:    proxyRepo,
		settingsRepo: settingsRepo,
		canary:       canary,
		stats:        stats,
		db:           db,
	}
}

type detailedHealthResponse struct {
	Version       string                      `json:"version"`
	UptimeSeconds int64                       `json:"uptime_seconds"`
	Database      *detailedDatabaseInfo       `json:"database"`
	Cache         *detailedCacheInfo          `json:"cache"`
	LogCollector  *detailedLogCollectorInfo   `json:"log_collector"`
	Nginx         *detailedNginxInfo          `json:"nginx"`
	NginxTuning   *detailedNginxTuningInfo    `json:"nginx_tuning,omitempty"`
}

// detailedNginxTuningInfo exposes the subset of global_settings that an
// operator most commonly checks when diagnosing performance issues. Lets
// `/api/v1/health/detailed` answer "are my nginx tuning values the default
// or has someone customized them?" without psql access.
type detailedNginxTuningInfo struct {
	WorkerConnections    int  `json:"worker_connections"`
	KeepaliveTimeout     int  `json:"keepalive_timeout"`
	KeepaliveRequests    int  `json:"keepalive_requests"`
	OpenFileCacheEnabled bool `json:"open_file_cache_enabled"`
	OpenFileCacheMax     int  `json:"open_file_cache_max"`
	GzipEnabled          bool `json:"gzip_enabled"`
	BrotliEnabled        bool `json:"brotli_enabled"`
	SSLEarlyData         bool `json:"ssl_early_data_inferred"` // inferred from preset, not directly stored
}

type detailedDatabaseInfo struct {
	Connected         bool                          `json:"connected"`
	AccessLogRows     int64                         `json:"access_log_rows_estimate"`
	Hypertables       []repository.HypertableStats  `json:"hypertables"`
	HypertablesError  string                        `json:"hypertables_error,omitempty"`
	// Degraded-but-serving signal: upgrade migrations are warn-and-continue
	// (a fail-fast boot would brick existing installs), so partial-migration
	// state surfaces here instead of flipping the liveness probe.
	MigrationFailures  int    `json:"migration_failures,omitempty"`
	MigrationLastError string `json:"migration_last_error,omitempty"`
}

type detailedCacheInfo struct {
	Ready          bool  `json:"ready"`
	LogBufferSize  int64 `json:"log_buffer_size"`
}

type detailedLogCollectorInfo struct {
	AccessLogPathConfigured string `json:"access_log_path_configured"`
	AccessLogPathActual     string `json:"access_log_path_actual"`
	FallbackActive          bool   `json:"fallback_active"`
	LastFlushAt             string `json:"last_flush_at,omitempty"`
	LastFlushSecondsAgo     int64  `json:"last_flush_seconds_ago"`
	// NoFlushSinceStart is true when LogCollector has been running for more
	// than its boot probe window (60s) without flushing a single log row.
	// Surfaces silent-failure scenarios (#141/#144/#145 family) so monitors
	// and the UI can warn instead of showing an empty log table.
	NoFlushSinceStart bool `json:"no_flush_since_start"`

	AccessLastFlushSecondsAgo int64  `json:"access_last_flush_seconds_ago"`
	ModsecLastFlushSecondsAgo int64  `json:"modsec_last_flush_seconds_ago"`
	ErrorLastFlushSecondsAgo  int64  `json:"error_last_flush_seconds_ago"`
	PipelineStatus            string `json:"pipeline_status"`
	CanaryFailureStage        string `json:"canary_failure_stage,omitempty"`
	LastCanaryAt              string `json:"last_canary_at,omitempty"`
	NginxStatusReachable      bool   `json:"nginx_status_reachable"`
	AutoHealAttempts          int    `json:"auto_heal_attempts"`
	AutoHealExhausted         bool   `json:"auto_heal_exhausted"`
}

type detailedNginxInfo struct {
	HostCount int `json:"host_count"`
}

// GetDetailed handles GET /api/v1/health/detailed.
func (h *HealthDetailedHandler) GetDetailed(c echo.Context) error {
	parent := c.Request().Context()
	// All sub-queries share a short overall budget so /health/detailed cannot
	// be used to wedge the API on a stuck DB/Redis.
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	resp := detailedHealthResponse{
		Version:       config.AppVersion,
		UptimeSeconds: int64(time.Since(h.startedAt).Seconds()),
		Database:      h.dbInfo(ctx),
		Cache:         h.cacheInfo(ctx),
		LogCollector:  h.logInfo(),
		Nginx:         h.nginxInfo(ctx),
		NginxTuning:   h.tuningInfo(ctx),
	}
	return c.JSON(http.StatusOK, resp)
}

// RunCanary forces a synchronous pipeline canary run. Useful for operators
// ("test my logging now") and for deterministic e2e assertions.
func (h *HealthDetailedHandler) RunCanary(c echo.Context) error {
	if h.canary == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "canary not enabled"})
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 20*time.Second)
	defer cancel()
	ok, stage := h.canary.RunOnce(ctx)
	return c.JSON(http.StatusOK, map[string]any{"ok": ok, "stage": stage})
}

func (h *HealthDetailedHandler) tuningInfo(ctx context.Context) *detailedNginxTuningInfo {
	if h.settingsRepo == nil {
		return nil
	}
	s, err := h.settingsRepo.Get(ctx)
	if err != nil || s == nil {
		return nil
	}
	return &detailedNginxTuningInfo{
		WorkerConnections:    s.WorkerConnections,
		KeepaliveTimeout:     s.KeepaliveTimeout,
		KeepaliveRequests:    s.KeepaliveRequests,
		OpenFileCacheEnabled: s.OpenFileCacheEnabled,
		OpenFileCacheMax:     s.OpenFileCacheMax,
		GzipEnabled:          s.GzipEnabled,
		BrotliEnabled:        s.BrotliEnabled,
		SSLEarlyData:         true, // nginx.conf hardcodes ssl_early_data on
	}
}

func (h *HealthDetailedHandler) dbInfo(ctx context.Context) *detailedDatabaseInfo {
	info := &detailedDatabaseInfo{Connected: true}

	if rows, err := h.repo.GetAccessLogRowCount(ctx); err == nil {
		info.AccessLogRows = rows
	} else {
		info.Connected = false
	}

	hyper, err := h.repo.GetHypertableStats(ctx)
	if err != nil {
		info.HypertablesError = err.Error()
	} else {
		info.Hypertables = hyper
	}

	if h.db != nil {
		if count, lastErr := h.db.MigrationHealth(); count > 0 {
			info.MigrationFailures = count
			info.MigrationLastError = lastErr
		}
	}

	return info
}

func (h *HealthDetailedHandler) cacheInfo(ctx context.Context) *detailedCacheInfo {
	info := &detailedCacheInfo{}
	if h.redis == nil {
		return info
	}
	info.Ready = h.redis.IsReady()
	if info.Ready {
		if size, err := h.redis.GetLogBufferSize(ctx); err == nil {
			info.LogBufferSize = size
		}
	}
	return info
}

func (h *HealthDetailedHandler) logInfo() *detailedLogCollectorInfo {
	info := &detailedLogCollectorInfo{}
	if h.logCollect == nil {
		return info
	}
	info.AccessLogPathConfigured = h.logCollect.AccessLogPathConfigured()
	info.AccessLogPathActual = h.logCollect.AccessLogPathActual()
	info.FallbackActive = info.AccessLogPathConfigured != "" &&
		info.AccessLogPathActual != "" &&
		info.AccessLogPathConfigured != info.AccessLogPathActual
	if ts := h.logCollect.LastFlushUnix(); ts > 0 {
		t := time.Unix(ts, 0)
		info.LastFlushAt = t.Format(time.RFC3339)
		info.LastFlushSecondsAgo = int64(time.Since(t).Seconds())
	} else if h.logCollect.HasBootProbeFired() {
		// Boot probe has tripped (no flush in 60s after start) — surface it.
		info.NoFlushSinceStart = true
	}

	now := time.Now()
	if a := h.logCollect.AccessLastFlushUnix(); a > 0 {
		info.AccessLastFlushSecondsAgo = int64(now.Sub(time.Unix(a, 0)).Seconds())
	}
	if m := h.logCollect.ModsecLastFlushUnix(); m > 0 {
		info.ModsecLastFlushSecondsAgo = int64(now.Sub(time.Unix(m, 0)).Seconds())
	}
	if e := h.logCollect.ErrorLastFlushUnix(); e > 0 {
		info.ErrorLastFlushSecondsAgo = int64(now.Sub(time.Unix(e, 0)).Seconds())
	}
	if h.canary != nil {
		status, stage, lastRun, _ := h.canary.Snapshot()
		info.PipelineStatus = status
		info.CanaryFailureStage = stage
		if !lastRun.IsZero() {
			info.LastCanaryAt = lastRun.Format(time.RFC3339)
		}
		attempts, exhausted := h.canary.HealState()
		info.AutoHealAttempts = attempts
		info.AutoHealExhausted = exhausted
	} else {
		info.PipelineStatus = "unknown"
	}
	if h.stats != nil {
		info.NginxStatusReachable = h.stats.NginxStatusReachable()
	}
	return info
}

func (h *HealthDetailedHandler) nginxInfo(ctx context.Context) *detailedNginxInfo {
	info := &detailedNginxInfo{}
	if h.proxyRepo == nil {
		return info
	}
	if _, total, err := h.proxyRepo.List(ctx, 1, 1, "", "", ""); err == nil {
		info.HostCount = total
	}
	return info
}

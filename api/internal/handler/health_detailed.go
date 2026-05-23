package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
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
}

func NewHealthDetailedHandler(
	repo *repository.HealthDetailedRepository,
	logCollect *service.LogCollector,
	redis *cache.RedisClient,
	proxyRepo *repository.ProxyHostRepository,
) *HealthDetailedHandler {
	return &HealthDetailedHandler{
		startedAt:  time.Now(),
		repo:       repo,
		logCollect: logCollect,
		redis:      redis,
		proxyRepo:  proxyRepo,
	}
}

type detailedHealthResponse struct {
	Version       string                      `json:"version"`
	UptimeSeconds int64                       `json:"uptime_seconds"`
	Database      *detailedDatabaseInfo       `json:"database"`
	Cache         *detailedCacheInfo          `json:"cache"`
	LogCollector  *detailedLogCollectorInfo   `json:"log_collector"`
	Nginx         *detailedNginxInfo          `json:"nginx"`
}

type detailedDatabaseInfo struct {
	Connected         bool                          `json:"connected"`
	AccessLogRows     int64                         `json:"access_log_rows_estimate"`
	Hypertables       []repository.HypertableStats  `json:"hypertables"`
	HypertablesError  string                        `json:"hypertables_error,omitempty"`
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
	}
	return c.JSON(http.StatusOK, resp)
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

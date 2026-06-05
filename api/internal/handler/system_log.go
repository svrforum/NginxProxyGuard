package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/util"
)

type SystemLogHandler struct {
	repo *repository.SystemLogRepository
}

func NewSystemLogHandler(repo *repository.SystemLogRepository) *SystemLogHandler {
	return &SystemLogHandler{repo: repo}
}

// List returns system logs with optional filters
// GET /api/v1/system-logs
func (h *SystemLogHandler) List(c echo.Context) error {
	filter := repository.SystemLogFilter{
		ContainerName: c.QueryParam("container"),
		Component:     c.QueryParam("component"),
		Search:        c.QueryParam("search"),
	}
	// Validate enum filters; an unknown value would raise a Postgres enum error
	// (500 + noisy DB log). Drop invalid values so the filter is simply ignored.
	if s := c.QueryParam("source"); s != "" && repository.IsValidSystemLogSource(s) {
		filter.Source = repository.SystemLogSource(s)
	}
	if l := c.QueryParam("level"); l != "" && repository.IsValidSystemLogLevel(l) {
		filter.Level = repository.SystemLogLevel(l)
	}

	// Parse limit and offset using utility functions
	filter.Limit = util.ParseLimitParam(c, config.MaxPageSize)
	filter.Offset = util.ParseOffsetParam(c)

	// Parse time range
	filter.StartTime, filter.EndTime = util.ParseTimeRange(c)

	logs, total, err := h.repo.List(c.Request().Context(), filter)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"logs":   logs,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// GetStats returns statistics about system logs
// GET /api/v1/system-logs/stats
func (h *SystemLogHandler) GetStats(c echo.Context) error {
	stats, err := h.repo.GetStats(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, stats)
}

// Cleanup removes old system logs
// POST /api/v1/system-logs/cleanup
func (h *SystemLogHandler) Cleanup(c echo.Context) error {
	retentionDays := util.ParseIntParam(c, "retention_days", 7, 1, 365)

	deleted, err := h.repo.Cleanup(c.Request().Context(), retentionDays)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"deleted":        deleted,
		"retention_days": retentionDays,
	})
}

// GetSources returns available log sources
// GET /api/v1/system-logs/sources
func (h *SystemLogHandler) GetSources(c echo.Context) error {
	sources := []map[string]string{
		{"value": "docker_api", "label": "API Server"},
		{"value": "docker_nginx", "label": "Nginx Proxy"},
		{"value": "docker_db", "label": "Database"},
		{"value": "docker_ui", "label": "UI Server"},
		{"value": "health_check", "label": "Health Checks"},
		{"value": "internal", "label": "Internal Events"},
		{"value": "scheduler", "label": "Scheduler"},
		{"value": "backup", "label": "Backup/Restore"},
		{"value": "certificate", "label": "Certificates"},
	}

	return c.JSON(http.StatusOK, sources)
}

// GetLevels returns available log levels
// GET /api/v1/system-logs/levels
func (h *SystemLogHandler) GetLevels(c echo.Context) error {
	levels := []map[string]string{
		{"value": "debug", "label": "Debug", "color": "gray"},
		{"value": "info", "label": "Info", "color": "blue"},
		{"value": "warn", "label": "Warning", "color": "yellow"},
		{"value": "error", "label": "Error", "color": "red"},
		{"value": "fatal", "label": "Fatal", "color": "purple"},
	}

	return c.JSON(http.StatusOK, levels)
}

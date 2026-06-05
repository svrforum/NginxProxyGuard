package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// Dashboard Handlers

func (h *SettingsHandler) GetDashboard(c echo.Context) error {
	summary, err := h.settingsService.GetDashboard(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, summary)
}

// GetGeoIPStats returns GeoIP statistics for globe visualization
func (h *SettingsHandler) GetGeoIPStats(c echo.Context) error {
	// Default to last 24 hours
	hours := service.ParseHours(c.QueryParam("hours"), 24, 168)

	response, err := h.settingsService.GetGeoIPStats(c.Request().Context(), hours)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, response)
}

func (h *SettingsHandler) GetSystemHealth(c echo.Context) error {
	health, err := h.settingsService.GetSystemHealth(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, health)
}

// GetSystemHealthHistory returns historical system health data for charts
func (h *SettingsHandler) GetSystemHealthHistory(c echo.Context) error {
	// Default to last 1 hour
	hours := 1
	if hoursStr := c.QueryParam("hours"); hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= 168 {
			hours = h
		}
	}

	// Allow custom limit parameter (max 1000)
	limit := 100
	if limitStr := c.QueryParam("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	history, err := h.settingsService.GetSystemHealthHistory(c.Request().Context(), hours, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"data":  history,
		"total": len(history),
		"since": since,
		"limit": limit,
	})
}

func (h *SettingsHandler) GetHourlyStats(c echo.Context) error {
	startStr := c.QueryParam("start")
	endStr := c.QueryParam("end")
	proxyHostID := c.QueryParam("proxy_host_id")
	// Validate uuid; an invalid value would hit the uuid column and raise a
	// Postgres "invalid input syntax for type uuid" error (500 + DB log).
	if proxyHostID != "" {
		if _, err := uuid.Parse(proxyHostID); err != nil {
			proxyHostID = ""
		}
	}

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			start = time.Now().Add(-24 * time.Hour)
		}
	} else {
		start = time.Now().Add(-24 * time.Hour)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			end = time.Now()
		}
	} else {
		end = time.Now()
	}

	params := &model.DashboardQueryParams{
		ProxyHostID: proxyHostID,
		StartTime:   start,
		EndTime:     end,
		Granularity: "hourly",
	}

	stats, err := h.settingsService.GetHourlyStats(c.Request().Context(), params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, stats)
}

func (h *SettingsHandler) GetDockerStats(c echo.Context) error {
	summary, err := h.settingsService.GetDockerStats(c.Request().Context())
	if err != nil {
		if err.Error() == "docker stats service not available" {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Docker stats service not available"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, summary)
}

// ListDockerContainers returns all running Docker containers with their network info
func (h *SettingsHandler) ListDockerContainers(c echo.Context) error {
	containers, err := h.settingsService.ListDockerContainers(c.Request().Context())
	if err != nil {
		if err.Error() == "docker stats service not available" {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Docker stats service not available"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, containers)
}

// Test Endpoints

func (h *SettingsHandler) SelfCheck(c echo.Context) error {
	result, err := h.settingsService.SelfCheck(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":     result.Status,
		"checked_at": result.CheckedAt,
		"components": result.Components,
	})
}

func (h *SettingsHandler) TestDashboardQueries(c echo.Context) error {
	result, err := h.settingsService.TestDashboardQueries(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"test":    result.Test,
		"status":  result.Status,
		"results": result.Results,
	})
}

package handler

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"nginx-proxy-guard/internal/repository"
)

type TrafficHandler struct {
	repo *repository.DashboardRepository
}

func NewTrafficHandler(repo *repository.DashboardRepository) *TrafficHandler {
	return &TrafficHandler{repo: repo}
}

func trafficRange(c echo.Context) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	start, end := now.Add(-24*time.Hour), now
	var err error
	if raw := c.QueryParam("start"); raw != "" {
		start, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return start, end, fmt.Errorf("invalid start: expected RFC3339")
		}
	}
	if raw := c.QueryParam("end"); raw != "" {
		end, err = time.Parse(time.RFC3339, raw)
		if err != nil {
			return start, end, fmt.Errorf("invalid end: expected RFC3339")
		}
	}
	if !end.After(start) || end.Sub(start) > 90*24*time.Hour || start.Before(now.Add(-90*24*time.Hour)) || end.After(now.Add(time.Minute)) {
		return start, end, fmt.Errorf("range must be within the last 90 days and at most 90 days long")
	}
	return start.UTC(), end.UTC(), nil
}

func trafficHostID(c echo.Context) (string, error) {
	id := c.QueryParam("proxy_host_id")
	if id != "" && id != "unclassified" {
		if _, err := uuid.Parse(id); err != nil {
			return "", fmt.Errorf("invalid proxy_host_id")
		}
	}
	return id, nil
}

func (h *TrafficHandler) Summary(c echo.Context) error {
	start, end, err := trafficRange(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	summary, err := h.repo.GetTrafficSummary(c.Request().Context(), start, end)
	if err != nil {
		return directInternalError(c, err)
	}
	return c.JSON(http.StatusOK, summary)
}

func (h *TrafficHandler) Timeseries(c echo.Context) error {
	start, end, err := trafficRange(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	id, err := trafficHostID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	points, err := h.repo.GetTrafficSeries(c.Request().Context(), start, end, id, false)
	if err != nil {
		return directInternalError(c, err)
	}
	resolution := "hour"
	if repository.TrafficUsesRaw(start, end) {
		resolution = "5min"
	} else if end.Sub(start) > 14*24*time.Hour {
		resolution = "day"
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"points": points, "resolution": resolution})
}

func (h *TrafficHandler) Realtime(c echo.Context) error {
	id, err := trafficHostID(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	end := time.Now().UTC()
	start := end.Add(-3 * time.Minute)
	points, err := h.repo.GetTrafficSeries(c.Request().Context(), start, end, id, true)
	if err != nil {
		return directInternalError(c, err)
	}
	// Exact 30-second interval; chart buckets are aligned to 10s boundaries.
	recentRequests, recentBytes, err := h.repo.GetTrafficRate(c.Request().Context(), end.Add(-30*time.Second), end, id)
	if err != nil {
		return directInternalError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"points": points, "bytes_per_second": float64(recentBytes) / 30,
		"requests_per_second": float64(recentRequests) / 30,
		"interval_seconds":    30, "resolution": "10s", "updated_at": end,
	})
}

// CSV is downloaded with the browser's authorized fetch rather than a direct
// navigation, so both session and bearer-token clients can use the export.
func (h *TrafficHandler) Export(c echo.Context) error {
	start, end, err := trafficRange(c)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	summary, err := h.repo.GetTrafficSummary(c.Request().Context(), start, end)
	if err != nil {
		return directInternalError(c, err)
	}
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{"domain", "proxy_host_id", "response_bytes", "requests", "percentage"}); err != nil {
		return err
	}
	for _, host := range summary.Hosts {
		// Prevent spreadsheet applications from evaluating hostnames as formulas.
		domain := host.Domain
		trimmed := strings.TrimLeft(domain, " \t\r\n\x00")
		if strings.HasPrefix(trimmed, "=") || strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "@") {
			domain = "'" + domain
		}
		if err := writer.Write([]string{domain, host.ID, strconv.FormatInt(host.Bytes, 10), strconv.FormatInt(host.Requests, 10), strconv.FormatFloat(host.Percentage, 'f', 2, 64)}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="npg-traffic.csv"`)
	c.Response().Header().Set(echo.HeaderCacheControl, "no-store")
	return c.Blob(http.StatusOK, "text/csv; charset=utf-8", buf.Bytes())
}

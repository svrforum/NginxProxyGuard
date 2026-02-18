package handler

import (
	"context"
	"database/sql"
	"net/http"
	"os/exec"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
)

type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

type StatusResponse struct {
	API      string `json:"api"`
	Database string `json:"database"`
	Nginx    string `json:"nginx"`
	Redis    string `json:"redis,omitempty"`
}

// HealthHandler holds dependencies for health checks
type HealthHandler struct {
	db    *sql.DB
	redis interface{ Ping(context.Context) error }
}

// NewHealthHandler creates a new health handler with dependencies
func NewHealthHandler(db *sql.DB, redis interface{ Ping(context.Context) error }) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

func Health(c echo.Context) error {
	return c.JSON(http.StatusOK, HealthResponse{
		Status:    config.StatusHealthy,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   config.AppVersion,
	})
}

// Status returns detailed health status of all services
func (h *HealthHandler) Status(c echo.Context) error {
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()

	response := StatusResponse{
		API:      config.StatusOK,
		Database: h.checkDatabase(ctx),
		Nginx:    checkNginx(),
	}

	// Check Redis if available
	if h.redis != nil {
		response.Redis = h.checkRedis(ctx)
	}

	// Determine overall status
	httpStatus := http.StatusOK
	if response.Database == config.StatusError || response.Nginx == config.StatusError {
		httpStatus = http.StatusServiceUnavailable
	}

	return c.JSON(httpStatus, response)
}

// checkDatabase verifies database connectivity
func (h *HealthHandler) checkDatabase(ctx context.Context) string {
	if h.db == nil {
		return config.StatusError
	}

	if err := h.db.PingContext(ctx); err != nil {
		return config.StatusError
	}
	return config.StatusOK
}

// checkRedis verifies Redis connectivity
func (h *HealthHandler) checkRedis(ctx context.Context) string {
	if h.redis == nil {
		return config.StatusDisabled
	}

	if err := h.redis.Ping(ctx); err != nil {
		return config.StatusError
	}
	return config.StatusOK
}

// checkNginx verifies Nginx is running via docker exec
func checkNginx() string {
	cmd := exec.Command("docker", "exec", "npg-proxy", "nginx", "-t")
	if err := cmd.Run(); err != nil {
		return config.StatusError
	}
	return config.StatusOK
}

// LegacyStatus provides backward compatible status endpoint (without dependencies)
func LegacyStatus(c echo.Context) error {
	return c.JSON(http.StatusOK, StatusResponse{
		API:      config.StatusOK,
		Database: config.StatusOK,
		Nginx:    checkNginx(),
	})
}

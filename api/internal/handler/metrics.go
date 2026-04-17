// Package handler metrics.go — exposes the Prometheus default registry over an
// Echo route. No authentication; intended for scraping on the internal docker
// network only. Operators wanting external access should gate via upstream
// ACL / firewall.
package handler

import (
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler exposes the Prometheus default registry over an Echo route.
type MetricsHandler struct{}

// NewMetricsHandler constructs the handler. Stateless — a single instance
// is fine for the entire process.
func NewMetricsHandler() *MetricsHandler { return &MetricsHandler{} }

// ServeMetrics handles GET /metrics. Output is standard Prometheus text format.
func (h *MetricsHandler) ServeMetrics(c echo.Context) error {
	promhttp.Handler().ServeHTTP(c.Response().Writer, c.Request())
	return nil
}

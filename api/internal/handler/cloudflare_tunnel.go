package handler

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// CloudflareTunnelHandler exposes the tunnel settings singleton (Phase 1
// token mode). Token is never echoed back — responses carry a masked view.
type CloudflareTunnelHandler struct {
	service *service.CloudflareTunnelService
	audit   *service.AuditService
}

func NewCloudflareTunnelHandler(s *service.CloudflareTunnelService, audit *service.AuditService) *CloudflareTunnelHandler {
	return &CloudflareTunnelHandler{service: s, audit: audit}
}

// Get returns the singleton (token masked).
func (h *CloudflareTunnelHandler) Get(c echo.Context) error {
	t, err := h.service.Get(c.Request().Context())
	if err != nil {
		return databaseError(c, "get cloudflare tunnel settings", err)
	}
	return c.JSON(http.StatusOK, t)
}

// Update applies enabled/token changes and converges the connector.
func (h *CloudflareTunnelHandler) Update(c echo.Context) error {
	var req model.UpdateCloudflareTunnelRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	t, err := h.service.Update(c.Request().Context(), &req)
	if err != nil {
		if strings.Contains(err.Error(), "invalid tunnel token") {
			return badRequestError(c, err.Error())
		}
		return internalError(c, "update cloudflare tunnel settings", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogCloudflareTunnelUpdate(auditCtx)

	return c.JSON(http.StatusOK, t)
}

// Status returns the connector runtime state (15s cached).
func (h *CloudflareTunnelHandler) Status(c echo.Context) error {
	return c.JSON(http.StatusOK, h.service.Status(c.Request().Context()))
}

package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// Bot Filter handlers

func (h *SecurityHandler) GetBotFilter(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	filter, err := h.securityService.GetBotFilter(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get bot filter", err)
	}

	return c.JSON(http.StatusOK, filter)
}

func (h *SecurityHandler) UpsertBotFilter(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	skipReload := c.QueryParam("skip_reload") == "true"

	var req model.CreateBotFilterRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	filter, err := h.securityService.UpsertBotFilter(c.Request().Context(), proxyHostID, &req, skipReload)
	if err != nil {
		return internalError(c, "upsert bot filter", err)
	}

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "bot_filter", hostName, filter.Enabled, nil)

	return c.JSON(http.StatusOK, filter)
}

func (h *SecurityHandler) DeleteBotFilter(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	if err := h.securityService.DeleteBotFilter(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete bot filter", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "bot_filter", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

// GetGlobalBotFilter returns the singleton global bot-filter default (#198).
func (h *SecurityHandler) GetGlobalBotFilter(c echo.Context) error {
	g, err := h.securityService.GetGlobalBotFilter(c.Request().Context())
	if err != nil {
		return databaseError(c, "get global bot filter", err)
	}
	return c.JSON(http.StatusOK, g)
}

// UpdateGlobalBotFilter updates the global bot-filter default and regenerates
// inheriting hosts (#198).
func (h *SecurityHandler) UpdateGlobalBotFilter(c echo.Context) error {
	var req model.UpdateGlobalBotFilterRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	g, err := h.securityService.UpdateGlobalBotFilter(c.Request().Context(), &req)
	if err != nil {
		return internalError(c, "update global bot filter", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogGlobalBotFilterUpdate(auditCtx)

	return c.JSON(http.StatusOK, g)
}

func (h *SecurityHandler) GetKnownBots(c echo.Context) error {
	response := map[string]interface{}{
		"bad_bots":           model.KnownBadBots,
		"ai_bots":            model.AIBots,
		"search_engine_bots": model.SearchEngineBots,
	}

	return c.JSON(http.StatusOK, response)
}

// Security Headers handlers

func (h *SecurityHandler) GetSecurityHeaders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	headers, err := h.securityService.GetSecurityHeaders(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get security headers", err)
	}

	return c.JSON(http.StatusOK, headers)
}

func (h *SecurityHandler) UpsertSecurityHeaders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateSecurityHeadersRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	headers, err := h.securityService.UpsertSecurityHeaders(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert security headers", err)
	}

	// Audit log
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "security_headers", hostName, headers.Enabled, nil)

	return c.JSON(http.StatusOK, headers)
}

func (h *SecurityHandler) DeleteSecurityHeaders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	if err := h.securityService.DeleteSecurityHeaders(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete security headers", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "security_headers", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

// GetGlobalSecurityHeaders returns the singleton global security-headers default (#198).
func (h *SecurityHandler) GetGlobalSecurityHeaders(c echo.Context) error {
	g, err := h.securityService.GetGlobalSecurityHeaders(c.Request().Context())
	if err != nil {
		return databaseError(c, "get global security headers", err)
	}
	return c.JSON(http.StatusOK, g)
}

// UpdateGlobalSecurityHeaders updates the global security-headers default and
// regenerates inheriting hosts (#198).
func (h *SecurityHandler) UpdateGlobalSecurityHeaders(c echo.Context) error {
	var req model.UpdateGlobalSecurityHeadersRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	g, err := h.securityService.UpdateGlobalSecurityHeaders(c.Request().Context(), &req)
	if err != nil {
		return internalError(c, "update global security headers", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogGlobalSecurityHeadersUpdate(auditCtx)

	return c.JSON(http.StatusOK, g)
}

func (h *SecurityHandler) GetSecurityHeaderPresets(c echo.Context) error {
	return c.JSON(http.StatusOK, model.SecurityHeaderPresets)
}

func (h *SecurityHandler) ApplySecurityHeaderPreset(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	preset := c.Param("preset")

	headers, err := h.securityService.ApplySecurityHeaderPreset(c.Request().Context(), proxyHostID, preset)
	if err != nil {
		if err.Error() == "invalid preset: "+preset {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid preset"})
		}
		return databaseError(c, "apply security header preset", err)
	}

	// Audit log
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "security_headers", hostName, headers.Enabled, map[string]interface{}{
		"preset": preset,
	})

	return c.JSON(http.StatusOK, headers)
}

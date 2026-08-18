package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// Rate Limit handlers

func (h *SecurityHandler) GetRateLimit(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	rateLimit, err := h.securityService.GetRateLimit(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get rate limit", err)
	}

	return c.JSON(http.StatusOK, rateLimit)
}

func (h *SecurityHandler) UpsertRateLimit(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateRateLimitRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	rateLimit, err := h.securityService.UpsertRateLimit(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return internalError(c, "upsert rate limit", err)
	}

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "rate_limit", hostName, rateLimit.Enabled, nil)

	return c.JSON(http.StatusOK, rateLimit)
}

func (h *SecurityHandler) DeleteRateLimit(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	if err := h.securityService.DeleteRateLimit(c.Request().Context(), proxyHostID); err != nil {
		return internalError(c, "delete rate limit", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "rate_limit", hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

// Fail2ban handlers

func (h *SecurityHandler) GetFail2ban(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	config, err := h.securityService.GetFail2ban(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get fail2ban config", err)
	}

	return c.JSON(http.StatusOK, config)
}

func (h *SecurityHandler) UpsertFail2ban(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateFail2banRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	// BanTime is a pointer so an absent field keeps the stored duration instead of
	// being read as 0, which would silently turn a partial update into a permanent ban.
	if req.BanTime != nil && *req.BanTime < 0 {
		return badRequestError(c, "ban_time must be 0 (permanent) or a positive number of seconds")
	}

	config, err := h.securityService.UpsertFail2ban(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return databaseError(c, "upsert fail2ban config", err)
	}

	// Audit log
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFail2banUpdate(auditCtx, hostName, config.Enabled, nil)

	return c.JSON(http.StatusOK, config)
}

func (h *SecurityHandler) DeleteFail2ban(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	if err := h.securityService.DeleteFail2ban(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete fail2ban config", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFail2banUpdate(auditCtx, hostName, false, nil)

	return c.NoContent(http.StatusNoContent)
}

// Upstream handlers

func (h *SecurityHandler) GetUpstream(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	upstream, err := h.securityService.GetUpstream(c.Request().Context(), proxyHostID)
	if err != nil {
		return databaseError(c, "get upstream", err)
	}

	return c.JSON(http.StatusOK, upstream)
}

func (h *SecurityHandler) UpsertUpstream(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	var req model.CreateUpstreamRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	upstream, err := h.securityService.UpsertUpstream(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		// Service-level validation errors (invalid scheme, load_balance, server address, port) → 400
		msg := err.Error()
		if strings.Contains(msg, "invalid") || strings.Contains(msg, "is required") {
			return badRequestError(c, msg)
		}
		return databaseError(c, "upsert upstream", err)
	}

	// Audit log
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogUpstreamUpdate(auditCtx, hostName, map[string]interface{}{
		"load_balance": upstream.LoadBalance,
		"health_check": upstream.HealthCheckEnabled,
		"server_count": len(upstream.Servers),
	})

	return c.JSON(http.StatusOK, upstream)
}

func (h *SecurityHandler) DeleteUpstream(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	// Get host name for audit
	hostName := h.securityService.GetHostName(c.Request().Context(), proxyHostID)

	if err := h.securityService.DeleteUpstream(c.Request().Context(), proxyHostID); err != nil {
		return databaseError(c, "delete upstream", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogUpstreamUpdate(auditCtx, hostName, map[string]interface{}{
		"action": "deleted",
	})

	return c.NoContent(http.StatusNoContent)
}

func (h *SecurityHandler) GetUpstreamHealth(c echo.Context) error {
	id := c.Param("id")

	response, err := h.securityService.GetUpstreamHealth(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get upstream health", err)
	}

	if response == nil {
		return notFoundError(c, "Upstream")
	}

	return c.JSON(http.StatusOK, response)
}

// IP Ban History handlers

func (h *SecurityHandler) GetIPBanHistory(c echo.Context) error {
	// Parse filter parameters
	filter := &model.IPBanHistoryFilter{
		IPAddress: c.QueryParam("ip_address"),
		EventType: c.QueryParam("event_type"),
		Source:    c.QueryParam("source"),
	}
	// Validate uuid; an invalid value would hit the uuid column and raise a
	// Postgres "invalid input syntax for type uuid" error (500 + DB log).
	if phid := c.QueryParam("proxy_host_id"); phid != "" {
		if _, err := uuid.Parse(phid); err == nil {
			filter.ProxyHostID = phid
		}
	}

	// Parse pagination
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	filter.Page = page
	filter.PerPage = perPage

	// Parse date filters
	if startDate := c.QueryParam("start_date"); startDate != "" {
		if t, err := time.Parse(time.RFC3339, startDate); err == nil {
			filter.StartDate = &t
		}
	}
	if endDate := c.QueryParam("end_date"); endDate != "" {
		if t, err := time.Parse(time.RFC3339, endDate); err == nil {
			filter.EndDate = &t
		}
	}

	result, err := h.securityService.GetIPBanHistory(c.Request().Context(), filter)
	if err != nil {
		return internalError(c, "list IP ban history", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SecurityHandler) GetIPBanHistoryByIP(c echo.Context) error {
	ip := c.Param("ip")
	if ip == "" {
		return badRequestError(c, "IP address is required")
	}

	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}

	result, err := h.securityService.GetIPBanHistoryByIP(c.Request().Context(), ip, page, perPage)
	if err != nil {
		return databaseError(c, "get IP ban history", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SecurityHandler) GetIPBanHistoryStats(c echo.Context) error {
	stats, err := h.securityService.GetIPBanHistoryStats(c.Request().Context())
	if err != nil {
		return internalError(c, "get IP ban history stats", err)
	}

	return c.JSON(http.StatusOK, stats)
}

// GetBannedIPStats summarises one banned address for the ban detail view (#242).
func (h *SecurityHandler) GetBannedIPStats(c echo.Context) error {
	ip := c.Param("ip")
	if ip == "" {
		return badRequestError(c, "IP address is required")
	}

	days := model.DefaultBannedIPStatsWindowDays
	if raw := c.QueryParam("days"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return badRequestError(c, "days must be a number")
		}
		days = parsed
	}

	stats, err := h.securityService.GetBannedIPStats(c.Request().Context(), ip, days)
	if err != nil {
		// A bad address or window is the caller's mistake, not a server fault —
		// the service rejects both before they reach the ::inet cast.
		if strings.Contains(err.Error(), "invalid") {
			return badRequestError(c, err.Error())
		}
		return databaseError(c, "get banned IP stats", err)
	}

	return c.JSON(http.StatusOK, stats)
}

// GetGlobalRateLimit returns the singleton global rate-limit default (#198 slice 5).
func (h *SecurityHandler) GetGlobalRateLimit(c echo.Context) error {
	g, err := h.securityService.GetGlobalRateLimit(c.Request().Context())
	if err != nil {
		return databaseError(c, "get global rate limit", err)
	}
	return c.JSON(http.StatusOK, g)
}

// UpdateGlobalRateLimit updates the global rate-limit default and regenerates
// inheriting hosts (#198 slice 5).
func (h *SecurityHandler) UpdateGlobalRateLimit(c echo.Context) error {
	var req model.UpdateGlobalRateLimitRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	g, err := h.securityService.UpdateGlobalRateLimit(c.Request().Context(), &req)
	if err != nil {
		return internalError(c, "update global rate limit", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogGlobalRateLimitUpdate(auditCtx)

	return c.JSON(http.StatusOK, g)
}

// GetGlobalWAF returns the singleton global WAF default (#198 slice 6).
func (h *SecurityHandler) GetGlobalWAF(c echo.Context) error {
	g, err := h.securityService.GetGlobalWAF(c.Request().Context())
	if err != nil {
		return databaseError(c, "get global WAF", err)
	}
	return c.JSON(http.StatusOK, g)
}

// UpdateGlobalWAF updates the global WAF default and regenerates inheriting
// hosts (#198 slice 6). WAF changes take effect after a proxy restart.
func (h *SecurityHandler) UpdateGlobalWAF(c echo.Context) error {
	var req model.UpdateGlobalWAFRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	g, err := h.securityService.UpdateGlobalWAF(c.Request().Context(), &req)
	if err != nil {
		return internalError(c, "update global WAF", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogGlobalWAFUpdate(auditCtx)

	return c.JSON(http.StatusOK, g)
}

package handler

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/service"
)

// Banned IP handlers

func (h *SecurityHandler) ListBannedIPs(c echo.Context) error {
	proxyHostID := c.QueryParam("proxy_host_id")
	filterType := c.QueryParam("filter")
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	result, err := h.securityService.ListBannedIPs(c.Request().Context(), proxyHostID, filterType, page, perPage)
	if err != nil {
		return databaseError(c, "list banned IPs", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SecurityHandler) BanIP(c echo.Context) error {
	var req struct {
		ProxyHostID *string `json:"proxy_host_id,omitempty"`
		IPAddress   string  `json:"ip_address"`
		Reason      string  `json:"reason,omitempty"`
		BanTime     int     `json:"ban_time,omitempty"`
	}

	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.IPAddress == "" {
		return badRequestError(c, "ip_address is required")
	}

	if !ValidateIPAddress(req.IPAddress) && !ValidateCIDR(req.IPAddress) {
		return badRequestError(c, "Invalid IP address format. Must be a valid IPv4, IPv6, or CIDR notation")
	}

	// Get user info from context
	var userID *string
	var userEmail string
	if uid, ok := c.Get("user_id").(string); ok && uid != "" {
		userID = &uid
	}
	if email, ok := c.Get("username").(string); ok {
		userEmail = email
	}

	banReq := &service.BanIPRequest{
		ProxyHostID: req.ProxyHostID,
		IPAddress:   req.IPAddress,
		Reason:      req.Reason,
		BanTime:     req.BanTime,
		UserID:      userID,
		UserEmail:   userEmail,
	}

	bannedIP, err := h.securityService.BanIP(c.Request().Context(), banReq)
	if err != nil {
		return databaseError(c, "ban IP", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogIPBanned(auditCtx, req.IPAddress, req.Reason, req.BanTime)

	return c.JSON(http.StatusCreated, bannedIP)
}

func (h *SecurityHandler) UnbanIP(c echo.Context) error {
	id := c.Param("id")

	// Get user info from context
	var userID *string
	var userEmail string
	if uid, ok := c.Get("user_id").(string); ok && uid != "" {
		userID = &uid
	}
	if email, ok := c.Get("username").(string); ok {
		userEmail = email
	}

	if err := h.securityService.UnbanIP(c.Request().Context(), id, userID, userEmail); err != nil {
		return databaseError(c, "unban IP", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogIPUnbanned(auditCtx, id)

	return c.NoContent(http.StatusNoContent)
}

// UnbanIPsBulk unbans multiple banned IPs in a single request.
// Body: {"ids": ["uuid", ...]} — max MaxFilterArraySize entries.
func (h *SecurityHandler) UnbanIPsBulk(c echo.Context) error {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if len(req.IDs) == 0 {
		return badRequestError(c, "ids must contain at least one entry")
	}
	if len(req.IDs) > config.MaxFilterArraySize {
		return badRequestError(c, "ids exceeds maximum batch size")
	}
	for _, id := range req.IDs {
		if _, err := uuid.Parse(id); err != nil {
			return badRequestError(c, "ids contains invalid UUID: "+id)
		}
	}

	var userID *string
	var userEmail string
	if uid, ok := c.Get("user_id").(string); ok && uid != "" {
		userID = &uid
	}
	if email, ok := c.Get("username").(string); ok {
		userEmail = email
	}

	deleted, err := h.securityService.UnbanIPs(c.Request().Context(), req.IDs, userID, userEmail)
	if err != nil {
		return databaseError(c, "bulk unban IPs", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	_ = h.audit.LogIPsBulkUnbanned(auditCtx, deleted)

	return c.JSON(http.StatusOK, map[string]int64{"deleted": deleted})
}

func (h *SecurityHandler) UnbanIPByAddress(c echo.Context) error {
	ip := c.QueryParam("ip")
	if ip == "" {
		return badRequestError(c, "ip parameter is required")
	}

	// Get user info from context
	var userID *string
	var userEmail string
	if uid, ok := c.Get("user_id").(string); ok && uid != "" {
		userID = &uid
	}
	if email, ok := c.Get("username").(string); ok {
		userEmail = email
	}

	if err := h.securityService.UnbanIPByAddress(c.Request().Context(), ip, userID, userEmail); err != nil {
		return databaseError(c, "unban IP by address", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogIPUnbanned(auditCtx, ip)

	return c.NoContent(http.StatusNoContent)
}

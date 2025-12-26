package handler

import (
	"fmt"
	"net/http"
	"strings"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"

	"github.com/labstack/echo/v4"
)

type ProxyHostHandler struct {
	service *service.ProxyHostService
	audit   *service.AuditService
	tester  *service.ProxyHostTester
}

func NewProxyHostHandler(svc *service.ProxyHostService, audit *service.AuditService) *ProxyHostHandler {
	return &ProxyHostHandler{
		service: svc,
		audit:   audit,
		tester:  service.NewProxyHostTester(),
	}
}

func (h *ProxyHostHandler) Create(c echo.Context) error {
	var req model.CreateProxyHostRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// Basic validation
	if len(req.DomainNames) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "domain_names is required",
		})
	}
	// Validate each domain name format
	for _, domain := range req.DomainNames {
		if !ValidateDomainName(domain) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid domain format: " + domain,
			})
		}
	}
	if req.ForwardHost == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "forward_host is required",
		})
	}
	// Validate forward host (either domain or IP)
	if !ValidateHostnameOrIP(req.ForwardHost) {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid forward_host format",
		})
	}

	host, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		errMsg := err.Error()
		// Handle specific error cases with appropriate HTTP status codes
		if strings.Contains(errMsg, "already exist") {
			return conflictError(c, errMsg)
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") {
			return badRequestError(c, errMsg)
		}
		return internalError(c, "create proxy host", err)
	}

	// Log audit
	destination := fmt.Sprintf("%s://%s:%d", req.ForwardScheme, req.ForwardHost, req.ForwardPort)
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogProxyHostCreate(auditCtx, req.DomainNames, destination)

	return c.JSON(http.StatusCreated, host)
}

func (h *ProxyHostHandler) GetByID(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	host, err := h.service.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get proxy host", err)
	}

	if host == nil {
		return notFoundError(c, "Proxy host")
	}

	return c.JSON(http.StatusOK, host)
}

func (h *ProxyHostHandler) GetByDomain(c echo.Context) error {
	domain := c.Param("domain")
	if domain == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "domain is required",
		})
	}

	host, err := h.service.GetByDomain(c.Request().Context(), domain)
	if err != nil {
		return databaseError(c, "get proxy host by domain", err)
	}

	if host == nil {
		return notFoundError(c, "Proxy host")
	}

	return c.JSON(http.StatusOK, host)
}

func (h *ProxyHostHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)
	search := c.QueryParam("search")
	sortBy := c.QueryParam("sort_by")
	sortOrder := c.QueryParam("sort_order")

	response, err := h.service.List(c.Request().Context(), page, perPage, search, sortBy, sortOrder)
	if err != nil {
		return databaseError(c, "list proxy hosts", err)
	}

	return c.JSON(http.StatusOK, response)
}

func (h *ProxyHostHandler) Update(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	// Get existing host for comparison
	existingHost, _ := h.service.GetByID(c.Request().Context(), id)

	var req model.UpdateProxyHostRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	host, err := h.service.Update(c.Request().Context(), id, &req)
	if err != nil {
		errMsg := err.Error()
		// Handle specific error cases with appropriate HTTP status codes
		if strings.Contains(errMsg, "already exist") {
			return conflictError(c, errMsg)
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") {
			return badRequestError(c, errMsg)
		}
		return internalError(c, "update proxy host", err)
	}

	if host == nil {
		return notFoundError(c, "Proxy host")
	}

	// Log audit
	if existingHost != nil {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		// Check if it's just an enable/disable toggle
		if req.Enabled != nil && existingHost.Enabled != *req.Enabled {
			h.audit.LogProxyHostToggle(auditCtx, host.DomainNames, *req.Enabled)
		} else {
			changes := map[string]interface{}{
				"id": id,
			}
			h.audit.LogProxyHostUpdate(auditCtx, host.DomainNames, changes)
		}
	}

	return c.JSON(http.StatusOK, host)
}

func (h *ProxyHostHandler) Delete(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	// Get host info before deletion for audit
	host, _ := h.service.GetByID(c.Request().Context(), id)

	if err := h.service.Delete(c.Request().Context(), id); err != nil {
		return internalError(c, "delete proxy host", err)
	}

	// Log audit
	if host != nil {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		h.audit.LogProxyHostDelete(auditCtx, host.DomainNames)
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *ProxyHostHandler) SyncAll(c echo.Context) error {
	result, err := h.service.SyncAllConfigsWithDetails(c.Request().Context())
	if err != nil {
		return internalError(c, "sync all proxy configs", err)
	}

	return c.JSON(http.StatusOK, result)
}

// TestHost tests a proxy host configuration by making HTTP requests
func (h *ProxyHostHandler) TestHost(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	host, err := h.service.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get proxy host for test", err)
	}

	if host == nil {
		return notFoundError(c, "Proxy host")
	}

	// Get optional target URL from query param
	targetURL := c.QueryParam("url")

	result, err := h.tester.TestHost(c.Request().Context(), host, targetURL)
	if err != nil {
		return internalError(c, "test proxy host", err)
	}

	return c.JSON(http.StatusOK, result)
}

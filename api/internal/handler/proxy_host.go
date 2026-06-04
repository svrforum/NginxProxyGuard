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
	proxyType := model.NormalizeProxyType(req.ProxyType)
	// Validate each domain/name format
	for _, domain := range req.DomainNames {
		validName := ValidateDomainName(domain)
		if proxyType == model.ProxyTypeStream {
			validName = ValidateStreamName(domain)
		}
		if !validName {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid proxy name format: " + domain,
			})
		}
	}
	// Container-name targets resolve forward_host server-side (#150); the
	// container name lives in its own field and forward_host may be empty or a
	// placeholder pre-resolution, so skip the hostname/IP validation for them.
	isContainerTarget := req.ForwardContainerName != nil && *req.ForwardContainerName != ""
	if !isContainerTarget {
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
	}
	if proxyType == model.ProxyTypeStream {
		if !ValidatePort(req.ForwardPort) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "forward_port must be between 1 and 65535",
			})
		}
		if !ValidatePort(req.StreamListenPort) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "stream_listen_port must be between 1 and 65535",
			})
		}
	}

	host, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		errMsg := err.Error()
		// Handle specific error cases with appropriate HTTP status codes
		if strings.Contains(errMsg, "already exist") || strings.Contains(errMsg, "listener conflict") {
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

	skipNginx := c.QueryParam("skip_nginx") == "true"

	var host *model.ProxyHost
	var err error
	if skipNginx {
		host, err = h.service.UpdateDBOnly(c.Request().Context(), id, &req, true)
	} else {
		host, err = h.service.Update(c.Request().Context(), id, &req)
	}
	if err != nil {
		errMsg := err.Error()
		// Handle specific error cases with appropriate HTTP status codes
		if strings.Contains(errMsg, "already exist") || strings.Contains(errMsg, "listener conflict") {
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

func (h *ProxyHostHandler) ToggleFavorite(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	host, err := h.service.ToggleFavorite(c.Request().Context(), id)
	if err != nil {
		return internalError(c, "toggle favorite", err)
	}

	if host == nil {
		return notFoundError(c, "Proxy host")
	}

	return c.JSON(http.StatusOK, host)
}

func (h *ProxyHostHandler) SyncAll(c echo.Context) error {
	result, err := h.service.SyncAllConfigsWithDetails(c.Request().Context())
	if err != nil {
		return internalError(c, "sync all proxy configs", err)
	}

	return c.JSON(http.StatusOK, result)
}

func (h *ProxyHostHandler) Regenerate(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	if err := h.service.RegenerateConfigForHost(c.Request().Context(), id); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "not found") {
			return notFoundError(c, "Proxy host")
		}
		return internalError(c, "regenerate proxy host config", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Config regenerated successfully",
	})
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

// Clone creates a copy of an existing proxy host with new domain names
func (h *ProxyHostHandler) Clone(c echo.Context) error {
	id := c.Param("id")
	if id == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "id is required",
		})
	}

	var req model.CloneProxyHostRequest
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

	// Validate each domain/name format. Stream clones may use service labels
	// when SNI routing is disabled, so accept either domain or stream label.
	for _, domain := range req.DomainNames {
		if !ValidateDomainName(domain) && !ValidateStreamName(domain) {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "invalid proxy name format: " + domain,
			})
		}
	}

	// Get source host info for audit
	sourceHost, _ := h.service.GetByID(c.Request().Context(), id)

	host, err := h.service.Clone(c.Request().Context(), id, &req)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "already exist") || strings.Contains(errMsg, "listener conflict") {
			return conflictError(c, errMsg)
		}
		if strings.Contains(errMsg, "not found") {
			return notFoundError(c, "Source proxy host")
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") {
			return badRequestError(c, errMsg)
		}
		return internalError(c, "clone proxy host", err)
	}

	// Log audit
	if sourceHost != nil {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		h.audit.LogProxyHostClone(auditCtx, sourceHost.DomainNames, req.DomainNames)
	}

	return c.JSON(http.StatusCreated, host)
}

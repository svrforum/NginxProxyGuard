package handler

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	authMiddleware "nginx-proxy-guard/internal/middleware"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"

	"github.com/labstack/echo/v4"
)

type ProxyHostHandler struct {
	service *service.ProxyHostService
	audit   *service.AuditService
	tester  *service.ProxyHostTester
}

func NewProxyHostHandler(svc *service.ProxyHostService, audit *service.AuditService, dnsProvider *service.DNSProviderService, ddnsRepo *repository.DDNSRepository) *ProxyHostHandler {
	tester := service.NewProxyHostTester()
	tester.SetDDNSDeps(dnsProvider, ddnsRepo)
	return &ProxyHostHandler{
		service: svc,
		audit:   audit,
		tester:  tester,
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
	// "[2001:db8::1]" is URL syntax for the address 2001:db8::1; validate and
	// store the bare literal (#314).
	req.ForwardHost = model.NormalizeForwardHost(req.ForwardHost)
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
		if strings.Contains(errMsg, "already exist") || strings.Contains(errMsg, "listener conflict") || strings.Contains(errMsg, "conflict:") {
			return conflictError(c, errMsg)
		}
		if strings.Contains(errMsg, "invalid") || strings.Contains(errMsg, "required") {
			return badRequestError(c, errMsg)
		}
		return internalError(c, "create proxy host", err)
	}

	// Log audit
	destination := fmt.Sprintf("%s://%s", req.ForwardScheme, net.JoinHostPort(req.ForwardHost, strconv.Itoa(req.ForwardPort)))
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

// parseProxyHostListFilter reads the optional tag/domain/upstream/enabled
// query params. Tags go through the model rule so a malformed filter answers
// 400 instead of silently matching nothing.
func parseProxyHostListFilter(c echo.Context) (model.ProxyHostListFilter, error) {
	var f model.ProxyHostListFilter
	if raw := c.QueryParams()["tag"]; len(raw) > 0 {
		tags, err := model.NormalizeTags(raw)
		if err != nil {
			return f, err
		}
		f.Tags = tags
	}
	for _, p := range []struct {
		name string
		dst  *string
	}{{"domain", &f.Domain}, {"upstream", &f.Upstream}} {
		v := strings.TrimSpace(c.QueryParam(p.name))
		if len(v) > 253 || strings.ContainsAny(v, " \t\r\n") {
			return f, fmt.Errorf("%w: %s filter must be a single host name", model.ErrInvalidInput, p.name)
		}
		*p.dst = v
	}
	if v := c.QueryParam("enabled"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return f, fmt.Errorf("%w: enabled must be true or false", model.ErrInvalidInput)
		}
		f.Enabled = &b
	}
	return f, nil
}

// Groups answers GET /proxy-hosts/groups — the buckets the filter panel offers.
func (h *ProxyHostHandler) Groups(c echo.Context) error {
	groups, err := h.service.Groups(c.Request().Context())
	if err != nil {
		return databaseError(c, "group proxy hosts", err)
	}
	return c.JSON(http.StatusOK, groups)
}

func (h *ProxyHostHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)
	search := c.QueryParam("search")
	sortBy := c.QueryParam("sort_by")
	sortOrder := c.QueryParam("sort_order")
	filter, err := parseProxyHostListFilter(c)
	if err != nil {
		return badRequestError(c, err.Error())
	}

	response, err := h.service.List(c.Request().Context(), page, perPage, search, sortBy, sortOrder, filter)
	if err != nil {
		return databaseError(c, "list proxy hosts", err)
	}

	return c.JSON(http.StatusOK, response)
}

// ddnsRemoveProviderRequested reports whether the caller asked for the host's
// managed DDNS records to be deleted at the DNS provider too (?ddns_remove_provider=true).
//
// It defaults to false: deleting live public DNS is irreversible, so existing API
// automation that toggles DDNS off or deletes a host must keep its current
// DB-only behavior unless it opts in. The UI always sends an explicit value.
//
// Provider-side DNS deletion is settings-scoped elsewhere (DELETE /ddns-records/:id
// requires settings:write), so a caller reaching it through a proxy:write /
// proxy:delete route must hold settings:write as well — otherwise the flag is
// ignored rather than widening what the caller can destroy. (#219)
//
// The check goes through the shared authorizer so it covers session users too;
// it used to consult the API token only, which meant a role could not restrict
// it once roles existed. (#222)
func ddnsRemoveProviderRequested(c echo.Context) bool {
	if c.QueryParam("ddns_remove_provider") != "true" {
		return false
	}
	return authMiddleware.HasPermissionFromContext(c, model.PermissionSettingsWrite)
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
	ddnsRemoveProvider := ddnsRemoveProviderRequested(c)

	var host *model.ProxyHost
	var err error
	if skipNginx {
		host, err = h.service.UpdateDBOnly(c.Request().Context(), id, &req, true, ddnsRemoveProvider)
	} else {
		host, err = h.service.Update(c.Request().Context(), id, &req, ddnsRemoveProvider)
	}
	if err != nil {
		errMsg := err.Error()
		// Handle specific error cases with appropriate HTTP status codes
		if strings.Contains(errMsg, "already exist") || strings.Contains(errMsg, "listener conflict") || strings.Contains(errMsg, "conflict:") {
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

	if err := h.service.Delete(c.Request().Context(), id, ddnsRemoveProviderRequested(c)); err != nil {
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
		if strings.Contains(errMsg, "already exist") || strings.Contains(errMsg, "listener conflict") || strings.Contains(errMsg, "conflict:") {
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

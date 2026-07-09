package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

type CloudProviderHandler struct {
	repo             *repository.CloudProviderRepository
	globalRepo       *repository.GlobalCloudProvidersRepository
	proxyHostService *service.ProxyHostService
	audit            *service.AuditService
}

func NewCloudProviderHandler(
	repo *repository.CloudProviderRepository,
	globalRepo *repository.GlobalCloudProvidersRepository,
	proxyHostService *service.ProxyHostService,
	audit *service.AuditService,
) *CloudProviderHandler {
	return &CloudProviderHandler{
		repo:             repo,
		globalRepo:       globalRepo,
		proxyHostService: proxyHostService,
		audit:            audit,
	}
}

// GetGlobal returns the singleton global cloud-provider blocking default (#198).
func (h *CloudProviderHandler) GetGlobal(c echo.Context) error {
	g, err := h.globalRepo.GetGlobal(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, g)
}

// UpdateGlobal updates the global cloud-provider blocking default and
// regenerates every inheriting host (#198).
func (h *CloudProviderHandler) UpdateGlobal(c echo.Context) error {
	var req model.UpdateGlobalCloudProvidersRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	ctx := c.Request().Context()
	g, err := h.globalRepo.Upsert(ctx, &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if h.proxyHostService != nil {
		if err := h.proxyHostService.SyncAllConfigs(ctx); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate configs: " + err.Error()})
		}
	}
	auditCtx := service.ContextWithAudit(ctx, c)
	h.audit.LogGlobalCloudProvidersUpdate(auditCtx)
	return c.JSON(http.StatusOK, g)
}

// ListProviders returns all cloud providers
func (h *CloudProviderHandler) ListProviders(c echo.Context) error {
	providers, err := h.repo.List(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, providers)
}

// ListProvidersByRegion returns providers grouped by region
func (h *CloudProviderHandler) ListProvidersByRegion(c echo.Context) error {
	providers, err := h.repo.ListByRegion(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, providers)
}

// GetProvider returns a single cloud provider by slug
func (h *CloudProviderHandler) GetProvider(c echo.Context) error {
	slug := c.Param("slug")
	provider, err := h.repo.GetBySlug(c.Request().Context(), slug)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if provider == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Cloud provider not found"})
	}
	return c.JSON(http.StatusOK, provider)
}

// CreateProvider creates a new cloud provider
func (h *CloudProviderHandler) CreateProvider(c echo.Context) error {
	var req model.CreateCloudProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Name == "" || req.Slug == "" || len(req.IPRanges) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Name, slug, and at least one IP range are required"})
	}

	provider, err := h.repo.Create(c.Request().Context(), &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "Cloud Provider", map[string]interface{}{
		"action": "create",
		"slug":   req.Slug,
	})

	return c.JSON(http.StatusCreated, provider)
}

// UpdateProvider updates an existing cloud provider
func (h *CloudProviderHandler) UpdateProvider(c echo.Context) error {
	slug := c.Param("slug")

	var req model.UpdateCloudProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	provider, err := h.repo.Update(c.Request().Context(), slug, &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "Cloud Provider", map[string]interface{}{
		"action": "update",
		"slug":   slug,
	})

	return c.JSON(http.StatusOK, provider)
}

// DeleteProvider deletes a cloud provider
func (h *CloudProviderHandler) DeleteProvider(c echo.Context) error {
	slug := c.Param("slug")

	if err := h.repo.Delete(c.Request().Context(), slug); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "Cloud Provider", map[string]interface{}{
		"action": "delete",
		"slug":   slug,
	})

	return c.NoContent(http.StatusNoContent)
}

// GetBlockedProviders returns blocked cloud providers for a proxy host
func (h *CloudProviderHandler) GetBlockedProviders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")

	settings, err := h.repo.GetCloudProviderBlockingSettings(c.Request().Context(), proxyHostID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"blocked_providers":    settings.BlockedProviders,
		"challenge_mode":       settings.ChallengeMode,
		"allow_search_bots":    settings.AllowSearchBots,
		"cloud_disable_global": settings.CloudDisableGlobal,
	})
}

// SetBlockedProviders sets blocked cloud providers for a proxy host
func (h *CloudProviderHandler) SetBlockedProviders(c echo.Context) error {
	proxyHostID := c.Param("proxyHostId")
	skipReload := c.QueryParam("skip_reload") == "true"

	var req model.BlockedCloudProvidersRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	ctx := c.Request().Context()

	settings := &repository.CloudProviderBlockingSettings{
		BlockedProviders:   req.BlockedProviders,
		ChallengeMode:      req.ChallengeMode,
		AllowSearchBots:    req.AllowSearchBots,
		CloudDisableGlobal: req.CloudDisableGlobal,
	}

	if err := h.repo.SetCloudProviderBlockingSettings(ctx, proxyHostID, settings); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Regenerate nginx config (skip if requested)
	if !skipReload && h.proxyHostService != nil {
		if _, err := h.proxyHostService.Update(ctx, proxyHostID, nil); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Settings saved but failed to regenerate nginx config: " + err.Error(),
			})
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(ctx, c)
	h.audit.LogSettingsUpdate(auditCtx, "Blocked Cloud Providers", map[string]interface{}{
		"proxy_host_id":     proxyHostID,
		"providers":         req.BlockedProviders,
		"challenge_mode":    req.ChallengeMode,
		"allow_search_bots": req.AllowSearchBots,
	})

	return c.JSON(http.StatusOK, map[string]interface{}{
		"blocked_providers":  req.BlockedProviders,
		"challenge_mode":     req.ChallengeMode,
		"allow_search_bots":  req.AllowSearchBots,
		"message":            "Cloud provider blocking updated successfully",
	})
}

package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
	"nginx-proxy-guard/pkg/cache"
)

type SettingsHandler struct {
	settingsService *service.SettingsService
	audit           *service.AuditService
	// These fields are still needed for backup/restore operations
	// which involve complex file I/O that belongs in the handler layer
	backupRepo       *repository.BackupRepository
	proxyHostRepo    *repository.ProxyHostRepository
	redirectHostRepo *repository.RedirectHostRepository
	certificateRepo  *repository.CertificateRepository
	wafRepo          *repository.WAFRepository
	nginxManager     *nginx.Manager
	proxyHostService *service.ProxyHostService
	backupPath       string
	redisCache       *cache.RedisClient
	tunnelService    *service.CloudflareTunnelService
}

func NewSettingsHandler(
	settingsService *service.SettingsService,
	audit *service.AuditService,
	tunnelService *service.CloudflareTunnelService,
) *SettingsHandler {
	return &SettingsHandler{
		settingsService:  settingsService,
		audit:            audit,
		backupRepo:       settingsService.GetBackupRepo(),
		proxyHostRepo:    settingsService.GetProxyHostRepo(),
		redirectHostRepo: settingsService.GetRedirectHostRepo(),
		certificateRepo:  settingsService.GetCertificateRepo(),
		wafRepo:          settingsService.GetWAFRepo(),
		nginxManager:     settingsService.GetNginxManager(),
		proxyHostService: settingsService.GetProxyHostService(),
		backupPath:       settingsService.GetBackupPath(),
		redisCache:       settingsService.GetRedisCache(),
		tunnelService:    tunnelService,
	}
}

// Global Settings Handlers

func (h *SettingsHandler) GetGlobalSettings(c echo.Context) error {
	settings, err := h.settingsService.GetGlobalSettings(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, settings)
}

func (h *SettingsHandler) UpdateGlobalSettings(c echo.Context) error {
	var req model.UpdateGlobalSettingsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	settings, err := h.settingsService.UpdateGlobalSettings(c.Request().Context(), &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "전역 설정", map[string]interface{}{
		"action": "update",
	})

	return c.JSON(http.StatusOK, settings)
}

func (h *SettingsHandler) ResetGlobalSettings(c echo.Context) error {
	settings, err := h.settingsService.ResetGlobalSettings(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "전역 설정", map[string]interface{}{
		"action": "reset",
	})

	return c.JSON(http.StatusOK, settings)
}

func (h *SettingsHandler) GetSettingsPresets(c echo.Context) error {
	return c.JSON(http.StatusOK, model.GlobalSettingsPresets)
}

func (h *SettingsHandler) ApplySettingsPreset(c echo.Context) error {
	preset := c.Param("preset")

	settings, err := h.settingsService.ApplySettingsPreset(c.Request().Context(), preset)
	if err != nil {
		if err.Error() == "invalid preset: "+preset {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid preset"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "전역 설정", map[string]interface{}{
		"action": "apply_preset",
		"preset": preset,
	})

	return c.JSON(http.StatusOK, settings)
}

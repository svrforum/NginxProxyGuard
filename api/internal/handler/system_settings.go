package handler

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

const (
	nginxLogsPath    = "/etc/nginx/logs"
	rawLogConfigFile = "/etc/nginx/conf.d/.raw_log_config"
)

type SystemSettingsHandler struct {
	repo                 *repository.SystemSettingsRepository
	globalSettingsRepo   *repository.GlobalSettingsRepository
	historyRepo          *repository.GeoIPHistoryRepository
	nginxManager         *nginx.Manager
	audit                *service.AuditService
	dockerLogCollector   *service.DockerLogCollector
	geoipScheduler       *service.GeoIPScheduler
	cloudProviderService *service.CloudProviderService
	proxyHostService     *service.ProxyHostService
	updateChecker        *service.UpdateChecker
}

func NewSystemSettingsHandler(
	repo *repository.SystemSettingsRepository,
	globalSettingsRepo *repository.GlobalSettingsRepository,
	historyRepo *repository.GeoIPHistoryRepository,
	nginxManager *nginx.Manager,
	audit *service.AuditService,
	dockerLogCollector *service.DockerLogCollector,
	geoipScheduler *service.GeoIPScheduler,
	cloudProviderService *service.CloudProviderService,
	proxyHostService *service.ProxyHostService,
) *SystemSettingsHandler {
	h := &SystemSettingsHandler{
		repo:                 repo,
		globalSettingsRepo:   globalSettingsRepo,
		historyRepo:          historyRepo,
		nginxManager:         nginxManager,
		audit:                audit,
		dockerLogCollector:   dockerLogCollector,
		geoipScheduler:       geoipScheduler,
		cloudProviderService: cloudProviderService,
		proxyHostService:     proxyHostService,
		updateChecker:        service.NewUpdateChecker(),
	}

	// Initialize raw log settings on startup
	go h.initRawLogSettings()

	return h
}

// GetSystemSettings returns the current system settings
func (h *SystemSettingsHandler) GetSystemSettings(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return directInternalError(c, err)
	}
	return c.JSON(http.StatusOK, settings.ToResponse())
}

// GetPublicUISettings returns public UI settings (font, language, etc.) without authentication
// This is used by welcome page, 403 page, and other public pages
func (h *SystemSettingsHandler) GetPublicUISettings(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		// Return default on error
		return c.JSON(http.StatusOK, map[string]string{
			"font_family":         "system",
			"error_page_language": "auto",
		})
	}

	fontFamily := settings.UIFontFamily
	if fontFamily == "" {
		fontFamily = "system"
	}

	errorPageLanguage := settings.UIErrorPageLanguage
	if errorPageLanguage == "" {
		errorPageLanguage = "auto"
	}

	return c.JSON(http.StatusOK, map[string]string{
		"font_family":         fontFamily,
		"error_page_language": errorPageLanguage,
	})
}

// UpdateSystemSettings updates system settings
// trimInvalidInputPrefix strips the sentinel wrapper so the client sees the
// actionable sentence, not "invalid input: ...".
func trimInvalidInputPrefix(err error) string {
	return strings.TrimPrefix(err.Error(), model.ErrInvalidInput.Error()+": ")
}

func (h *SystemSettingsHandler) UpdateSystemSettings(c echo.Context) error {
	var req model.UpdateSystemSettingsRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, err.Error())
	}

	// Raw log storage is mandatory since v2.17.1 — LogCollector depends on it
	// for access log ingestion (issue #145 silent failure). Operators can still
	// tune retention/rotation/compression sub-options, but the master toggle
	// itself is force-enabled. We silently override rather than 400 so older
	// clients sending {raw_log_enabled:false} don't break.
	if req.RawLogEnabled != nil && !*req.RawLogEnabled {
		log.Printf("[SystemSettings] Ignoring raw_log_enabled=false; raw log storage is mandatory since v2.17.1.")
		t := true
		req.RawLogEnabled = &t
	}

	// Raw log files: refuse a value only when this request changes it to
	// something out of range. Stored legacy values echoed back (1825 days /
	// 9999 files on long-running installs) must never block another save.
	if req.RawLogRetentionDays != nil || req.RawLogMaxSizeMB != nil || req.RawLogRotateCount != nil {
		cur, err := h.repo.Get(c.Request().Context())
		if err != nil {
			return directInternalError(c, err)
		}
		if err := model.ValidateRawLogSettings(&req, cur); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": trimInvalidInputPrefix(err)})
		}
	}

	// Trusted proxies decide whose forwarded-address header nginx believes, so
	// a bad value is a security problem, not a cosmetic one — reject it here
	// rather than letting the render silently drop it (#278).
	if req.TrustedProxyCIDRs != nil {
		if err := model.ValidateTrustedProxyCIDRs(*req.TrustedProxyCIDRs); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": trimInvalidInputPrefix(err)})
		}
	}
	if req.TrustedProxyPreset != nil {
		normalized, err := model.NormalizeTrustedProxyPreset(*req.TrustedProxyPreset)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": trimInvalidInputPrefix(err)})
		}
		req.TrustedProxyPreset = &normalized
	}
	if req.RealIPHeader != nil {
		normalized, err := model.NormalizeRealIPHeader(*req.RealIPHeader)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": trimInvalidInputPrefix(err)})
		}
		req.RealIPHeader = &normalized
	}

	settings, err := h.repo.Update(c.Request().Context(), &req)
	if err != nil {
		return directInternalError(c, err)
	}

	// Generate raw log configuration if raw log settings changed
	if req.RawLogEnabled != nil || req.RawLogRetentionDays != nil ||
		req.RawLogMaxSizeMB != nil || req.RawLogRotateCount != nil ||
		req.RawLogCompressRotated != nil {
		if err := h.generateRawLogConfig(settings); err != nil {
			log.Printf("[SystemSettings] Warning: failed to generate raw log config: %v", err)
		}
	}

	// Regenerate all nginx configs when global trusted IPs change.
	// Two paths:
	//   1. Per-host configs (geo $trusted_ip_<id>) — handled by SyncAllConfigs.
	//   2. nginx.conf http-level limit_conn / limit_req zones — must be
	//      regenerated explicitly (issue #130: trusted IPs were only honored
	//      per-host, so global rate limits ignored the whitelist).
	// Also regenerate when only the WAF-bypass flag (#166) toggles — the
	// http-level ctl:ruleEngine=Off rule lives in nginx.conf, so a flag change
	// with unchanged trusted-IP list must still re-render the main config.
	if req.GlobalTrustedIPs != nil || req.GlobalTrustedIPsBypassWAF != nil ||
		req.TrustedProxyCIDRs != nil || req.TrustedProxyPreset != nil || req.RealIPHeader != nil {
		trustedIPs := service.ParseGlobalTrustedIPs(settings.GlobalTrustedIPs)
		bypassWAF := settings.GlobalTrustedIPsBypassWAF
		// Trusted proxies live in the same http-level block, so the same
		// ordered worker applies them (#278).
		trustedProxies := service.ResolveTrustedProxyConfig(settings)
		// One ORDERED background worker: nginx.conf first, then per-host
		// configs, then a single reload via SyncAllConfigs. The previous two
		// unsynchronized goroutines could interleave their writes/reloads, and
		// a failure in either left the trusted-IP promise silently unapplied.
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			if h.globalSettingsRepo != nil && h.nginxManager != nil {
				gs, err := h.globalSettingsRepo.Get(bgCtx)
				if err != nil {
					log.Printf("[SystemSettings] ERROR: trusted IPs change NOT fully applied — failed to load global settings for nginx.conf regen: %v (run Sync All to retry)", err)
					return
				}
				if err := h.nginxManager.GenerateMainNginxConfig(bgCtx, gs, trustedIPs, bypassWAF, trustedProxies); err != nil {
					log.Printf("[SystemSettings] ERROR: trusted IPs change NOT fully applied — nginx.conf regeneration failed: %v (run Sync All to retry)", err)
					return
				}
			}
			if h.proxyHostService != nil {
				// SyncAllConfigs regenerates every host config and performs the
				// test+reload, picking up the new nginx.conf at the same time.
				if err := h.proxyHostService.SyncAllConfigs(bgCtx); err != nil {
					log.Printf("[SystemSettings] ERROR: trusted IPs change NOT fully applied — host config sync failed: %v (run Sync All to retry)", err)
					return
				}
			} else if h.nginxManager != nil {
				if err := h.nginxManager.ReloadNginx(bgCtx); err != nil {
					log.Printf("[SystemSettings] ERROR: trusted IPs change NOT fully applied — nginx reload failed: %v", err)
					return
				}
			}
			log.Printf("[SystemSettings] Global trusted IPs change applied to nginx.conf and all host configs")
		}()
	}

	// Generate default server config if direct IP access action changed
	if req.DirectIPAccessAction != nil {
		if err := h.nginxManager.GenerateDefaultServerConfig(c.Request().Context(), settings.DirectIPAccessAction); err != nil {
			log.Printf("[SystemSettings] Warning: failed to generate default server config: %v", err)
		} else {
			// Reload nginx to apply new default server config
			if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
				log.Printf("[SystemSettings] Warning: failed to reload nginx after default server config change: %v", err)
			}
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "시스템 설정", map[string]interface{}{
		"action": "update",
	})

	return c.JSON(http.StatusOK, settings.ToResponse())
}



// TestACME tests the ACME configuration
func (h *SystemSettingsHandler) TestACME(c echo.Context) error {
	settings, err := h.repo.Get(c.Request().Context())
	if err != nil {
		return directInternalError(c, err)
	}

	result := map[string]interface{}{
		"acme_enabled": settings.ACMEEnabled,
		"acme_email":   settings.ACMEEmail,
		"acme_staging": settings.ACMEStaging,
		"status":       config.StatusOK,
		"message":      "ACME configuration is valid",
	}

	if !settings.ACMEEnabled {
		result["status"] = config.StatusDisabled
		result["message"] = "ACME is disabled"
	} else if settings.ACMEEmail == "" {
		result["status"] = config.StatusPending
		result["message"] = "ACME email is not configured. Some certificate authorities require an email."
	}

	return c.JSON(http.StatusOK, result)
}

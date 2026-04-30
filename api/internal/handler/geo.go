package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
)

type GeoHandler struct {
	geoRepo             *repository.GeoRepository
	proxyHostRepo       *repository.ProxyHostRepository
	accessListRepo      *repository.AccessListRepository
	rateLimitRepo       *repository.RateLimitRepository
	securityHeadersRepo *repository.SecurityHeadersRepository
	botFilterRepo       *repository.BotFilterRepository
	upstreamRepo        *repository.UpstreamRepository
	nginxManager        *nginx.Manager
}

func NewGeoHandler(
	geoRepo *repository.GeoRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	nginxManager *nginx.Manager,
	accessListRepo *repository.AccessListRepository,
	rateLimitRepo *repository.RateLimitRepository,
	securityHeadersRepo *repository.SecurityHeadersRepository,
	botFilterRepo *repository.BotFilterRepository,
	upstreamRepo *repository.UpstreamRepository,
) *GeoHandler {
	return &GeoHandler{
		geoRepo:             geoRepo,
		proxyHostRepo:       proxyHostRepo,
		accessListRepo:      accessListRepo,
		rateLimitRepo:       rateLimitRepo,
		securityHeadersRepo: securityHeadersRepo,
		botFilterRepo:       botFilterRepo,
		upstreamRepo:        upstreamRepo,
		nginxManager:        nginxManager,
	}
}

// GetByProxyHost returns geo restriction settings for a proxy host
func (h *GeoHandler) GetByProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")

	// Verify proxy host exists
	host, err := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if host == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Proxy host not found"})
	}

	geo, err := h.geoRepo.GetByProxyHostID(c.Request().Context(), proxyHostID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if geo == nil {
		// Return default empty response
		return c.JSON(http.StatusOK, map[string]interface{}{
			"proxy_host_id": proxyHostID,
			"mode":          "blacklist",
			"countries":     []string{},
			"enabled":       false,
		})
	}

	return c.JSON(http.StatusOK, geo)
}

// SetForProxyHost creates or updates geo restriction settings
func (h *GeoHandler) SetForProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")
	skipReload := c.QueryParam("skip_reload") == "true"

	// Verify proxy host exists
	host, err := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if host == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Proxy host not found"})
	}

	var req model.CreateGeoRestrictionRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Mode != "whitelist" && req.Mode != "blacklist" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Mode must be 'whitelist' or 'blacklist'"})
	}

	geo, err := h.geoRepo.Upsert(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Regenerate nginx config with geo restrictions (skip if requested)
	if !skipReload {
		if err := h.regenerateHostConfig(c, proxyHostID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate nginx config: " + err.Error()})
		}
	}

	return c.JSON(http.StatusOK, geo)
}

// UpdateForProxyHost updates geo restriction settings
func (h *GeoHandler) UpdateForProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")

	var req model.UpdateGeoRestrictionRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	geo, err := h.geoRepo.Update(c.Request().Context(), proxyHostID, &req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if geo == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Geo restriction not found"})
	}

	// Regenerate nginx config
	if err := h.regenerateHostConfig(c, proxyHostID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate nginx config: " + err.Error()})
	}

	return c.JSON(http.StatusOK, geo)
}

// DeleteForProxyHost removes geo restriction settings
func (h *GeoHandler) DeleteForProxyHost(c echo.Context) error {
	proxyHostID := c.Param("id")
	skipReload := c.QueryParam("skip_reload") == "true"

	if err := h.geoRepo.Delete(c.Request().Context(), proxyHostID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Regenerate nginx config without geo restrictions (skip if requested)
	if !skipReload {
		if err := h.regenerateHostConfig(c, proxyHostID); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to regenerate nginx config: " + err.Error()})
		}
	}

	return c.NoContent(http.StatusNoContent)
}

// GetCountryCodes returns the list of available country codes
func (h *GeoHandler) GetCountryCodes(c echo.Context) error {
	return c.JSON(http.StatusOK, model.CommonCountryCodes)
}

func (h *GeoHandler) regenerateHostConfig(c echo.Context, proxyHostID string) error {
	host, err := h.proxyHostRepo.GetByID(c.Request().Context(), proxyHostID)
	if err != nil || host == nil {
		return err
	}

	if host.Enabled {
		// Build full config data
		configData := h.getHostConfigData(c.Request().Context(), host)

		if err := h.nginxManager.GenerateConfigFull(c.Request().Context(), configData); err != nil {
			return err
		}
		if err := h.nginxManager.TestConfig(c.Request().Context()); err != nil {
			return err
		}
		if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
			return err
		}
	}

	return nil
}

// getHostConfigData fetches all configuration data for a host
func (h *GeoHandler) getHostConfigData(ctx context.Context, host *model.ProxyHost) nginx.ProxyHostConfigData {
	data := nginx.ProxyHostConfigData{
		Host: host,
	}

	// Fetch access list if assigned
	if host.AccessListID != nil && *host.AccessListID != "" && h.accessListRepo != nil {
		al, err := h.accessListRepo.GetByID(ctx, *host.AccessListID)
		if err == nil && al != nil {
			data.AccessList = al
		}
	}

	// Fetch geo restriction if exists
	// Load when Enabled OR when Priority Allow IPs are present, so that
	// IP-only configurations still take effect (WAF/cloud/bot bypass).
	if h.geoRepo != nil {
		geo, err := h.geoRepo.GetByProxyHostID(ctx, host.ID)
		if err == nil && geo != nil && (geo.Enabled || len(geo.AllowedIPs) > 0) {
			data.GeoRestriction = geo
		}
	}

	// Fetch rate limit if exists
	if h.rateLimitRepo != nil {
		rl, err := h.rateLimitRepo.GetByProxyHostID(ctx, host.ID)
		if err == nil && rl != nil && rl.Enabled {
			data.RateLimit = rl
		}
	}

	// Fetch security headers if exists
	if h.securityHeadersRepo != nil {
		sh, err := h.securityHeadersRepo.GetByProxyHostID(ctx, host.ID)
		if err == nil && sh != nil && sh.Enabled {
			data.SecurityHeaders = sh
		}
	}

	// Fetch bot filter if exists
	if h.botFilterRepo != nil {
		bf, err := h.botFilterRepo.GetByProxyHostID(ctx, host.ID)
		if err == nil && bf != nil && bf.Enabled {
			data.BotFilter = bf
		}
	}

	// Fetch upstream if exists
	if h.upstreamRepo != nil {
		up, err := h.upstreamRepo.GetByProxyHostID(ctx, host.ID)
		if err == nil && up != nil && len(up.Servers) > 0 {
			data.Upstream = up
		}
	}

	// Fetch banned IPs for this host
	if h.rateLimitRepo != nil {
		bannedResp, err := h.rateLimitRepo.ListBannedIPs(ctx, &host.ID, 1, 1000)
		if err == nil && bannedResp != nil {
			data.BannedIPs = bannedResp.Data
		}
	}

	return data
}

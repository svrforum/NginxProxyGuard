package handler

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

type GeoHandler struct {
	geoRepo          *repository.GeoRepository
	proxyHostRepo    *repository.ProxyHostRepository
	proxyHostService *service.ProxyHostService
}

func NewGeoHandler(
	geoRepo *repository.GeoRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	proxyHostService *service.ProxyHostService,
) *GeoHandler {
	return &GeoHandler{
		geoRepo:          geoRepo,
		proxyHostRepo:    proxyHostRepo,
		proxyHostService: proxyHostService,
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
	// Delegate to the service path: complete config data (fail-closed when a
	// security-relevant lookup errors), single-lock atomic write + nginx -t +
	// reload with rollback. The handler-local aggregation this replaced was
	// missing whole sections (URI block, cloud blocking, exploit rules,
	// global trusted IPs, filter subscriptions) and reloaded without rollback,
	// so a geo edit could silently strip those protections from the host.
	return h.proxyHostService.RegenerateConfigForHost(c.Request().Context(), proxyHostID)
}

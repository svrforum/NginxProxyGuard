package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type DNSProviderHandler struct {
	service *service.DNSProviderService
}

func NewDNSProviderHandler(service *service.DNSProviderService) *DNSProviderHandler {
	return &DNSProviderHandler{service: service}
}

// List handles GET /api/v1/dns-providers
func (h *DNSProviderHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)

	response, err := h.service.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list DNS providers", err)
	}

	return c.JSON(http.StatusOK, response)
}

// Get handles GET /api/v1/dns-providers/:id
func (h *DNSProviderHandler) Get(c echo.Context) error {
	id := c.Param("id")

	provider, err := h.service.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get DNS provider", err)
	}

	if provider == nil {
		return notFoundError(c, "DNS provider")
	}

	// Mask credentials
	masked := provider.MaskCredentials()
	return c.JSON(http.StatusOK, masked)
}

// Create handles POST /api/v1/dns-providers
func (h *DNSProviderHandler) Create(c echo.Context) error {
	var req model.CreateDNSProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
	}

	if req.Name == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "name is required",
		})
	}

	if req.ProviderType == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "provider_type is required",
		})
	}

	provider, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		return internalError(c, "create DNS provider", err)
	}

	// Mask credentials in response
	masked := provider.MaskCredentials()
	return c.JSON(http.StatusCreated, masked)
}

// Update handles PUT /api/v1/dns-providers/:id
func (h *DNSProviderHandler) Update(c echo.Context) error {
	id := c.Param("id")

	var req model.UpdateDNSProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
	}

	provider, err := h.service.Update(c.Request().Context(), id, &req)
	if err != nil {
		if err == model.ErrNotFound {
			return notFoundError(c, "DNS provider")
		}
		return internalError(c, "update DNS provider", err)
	}

	if provider == nil {
		return notFoundError(c, "DNS provider")
	}

	// Mask credentials in response
	masked := provider.MaskCredentials()
	return c.JSON(http.StatusOK, masked)
}

// Delete handles DELETE /api/v1/dns-providers/:id
func (h *DNSProviderHandler) Delete(c echo.Context) error {
	id := c.Param("id")

	err := h.service.Delete(c.Request().Context(), id)
	if err != nil {
		if err == model.ErrNotFound {
			return notFoundError(c, "DNS provider")
		}
		return internalError(c, "delete DNS provider", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// Test handles POST /api/v1/dns-providers/test
func (h *DNSProviderHandler) Test(c echo.Context) error {
	var req model.CreateDNSProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
	}

	err := h.service.TestConnection(c.Request().Context(), &req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"error":   err.Error(),
			"success": false,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "credentials are valid",
	})
}

// GetDefault handles GET /api/v1/dns-providers/default
func (h *DNSProviderHandler) GetDefault(c echo.Context) error {
	provider, err := h.service.GetDefault(c.Request().Context())
	if err != nil {
		return databaseError(c, "get default DNS provider", err)
	}

	if provider == nil {
		return notFoundError(c, "Default DNS provider")
	}

	masked := provider.MaskCredentials()
	return c.JSON(http.StatusOK, masked)
}

package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type DDNSHandler struct {
	service *service.DDNSService
}

func NewDDNSHandler(service *service.DDNSService) *DDNSHandler {
	return &DDNSHandler{service: service}
}

// List handles GET /api/v1/ddns-records
func (h *DDNSHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)

	response, err := h.service.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list DDNS records", err)
	}

	return c.JSON(http.StatusOK, response)
}

// Get handles GET /api/v1/ddns-records/:id
func (h *DDNSHandler) Get(c echo.Context) error {
	id := c.Param("id")

	rec, err := h.service.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get DDNS record", err)
	}

	if rec == nil {
		return notFoundError(c, "DDNS record")
	}

	return c.JSON(http.StatusOK, rec)
}

// Create handles POST /api/v1/ddns-records
func (h *DDNSHandler) Create(c echo.Context) error {
	var req model.CreateDDNSRecordRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "invalid request body")
	}

	if req.Hostname == "" {
		return badRequestError(c, "hostname is required")
	}

	if req.DNSProviderID == "" {
		return badRequestError(c, "dns_provider_id is required")
	}

	rec, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		return internalError(c, "create DDNS record", err)
	}

	return c.JSON(http.StatusCreated, rec)
}

// Update handles PUT /api/v1/ddns-records/:id
func (h *DDNSHandler) Update(c echo.Context) error {
	id := c.Param("id")

	var req model.UpdateDDNSRecordRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "invalid request body")
	}

	rec, err := h.service.Update(c.Request().Context(), id, &req)
	if err != nil {
		if err == model.ErrNotFound {
			return notFoundError(c, "DDNS record")
		}
		return internalError(c, "update DDNS record", err)
	}

	if rec == nil {
		return notFoundError(c, "DDNS record")
	}

	return c.JSON(http.StatusOK, rec)
}

// Delete handles DELETE /api/v1/ddns-records/:id
func (h *DDNSHandler) Delete(c echo.Context) error {
	id := c.Param("id")

	err := h.service.Delete(c.Request().Context(), id)
	if err != nil {
		if err == model.ErrNotFound {
			return notFoundError(c, "DDNS record")
		}
		return internalError(c, "delete DDNS record", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// SyncOne handles POST /api/v1/ddns-records/:id/sync
func (h *DDNSHandler) SyncOne(c echo.Context) error {
	id := c.Param("id")

	err := h.service.SyncOne(c.Request().Context(), id)
	if err != nil {
		if err == model.ErrNotFound {
			return notFoundError(c, "DDNS record")
		}
		return internalError(c, "sync DDNS record", err)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "record synced",
	})
}

// SyncAll handles POST /api/v1/ddns-records/sync
func (h *DDNSHandler) SyncAll(c echo.Context) error {
	h.service.SyncAll(c.Request().Context())

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "sync triggered",
	})
}

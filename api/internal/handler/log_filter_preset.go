package handler

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

const maxPresetNameLen = 100

// LogFilterPresetHandler exposes CRUD for saved log-viewer filter presets (#210).
type LogFilterPresetHandler struct {
	repo *repository.LogFilterPresetRepository
}

func NewLogFilterPresetHandler(repo *repository.LogFilterPresetRepository) *LogFilterPresetHandler {
	return &LogFilterPresetHandler{repo: repo}
}

// validPresetFilter requires the stored filter to be a JSON object so it can be
// re-applied by the viewer; it also stops arbitrary/oversized junk from being
// persisted as a preset.
func validPresetFilter(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var obj map[string]interface{}
	return json.Unmarshal(raw, &obj) == nil
}

// List returns saved presets, optionally scoped by ?log_type=.
func (h *LogFilterPresetHandler) List(c echo.Context) error {
	presets, err := h.repo.List(c.Request().Context(), c.QueryParam("log_type"))
	if err != nil {
		return databaseError(c, "list log filter presets", err)
	}
	return c.JSON(http.StatusOK, presets)
}

// Create saves a new preset.
func (h *LogFilterPresetHandler) Create(c echo.Context) error {
	var req model.CreateLogFilterPresetRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > maxPresetNameLen {
		return badRequestError(c, "name is required and must be 1-100 characters")
	}
	if !validPresetFilter(req.Filter) {
		return badRequestError(c, "filter must be a JSON object")
	}
	p, err := h.repo.Create(c.Request().Context(), &req)
	if err != nil {
		return databaseError(c, "create log filter preset", err)
	}
	return c.JSON(http.StatusCreated, p)
}

// Update renames a preset and/or replaces its stored filter.
func (h *LogFilterPresetHandler) Update(c echo.Context) error {
	id := c.Param("id")
	var req model.UpdateLogFilterPresetRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if req.Name == nil && req.Filter == nil {
		return badRequestError(c, "nothing to update")
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" || len(name) > maxPresetNameLen {
			return badRequestError(c, "name must be 1-100 characters")
		}
		req.Name = &name
	}
	if req.Filter != nil && !validPresetFilter(*req.Filter) {
		return badRequestError(c, "filter must be a JSON object")
	}
	p, err := h.repo.Update(c.Request().Context(), id, &req)
	if err != nil {
		if err == sql.ErrNoRows {
			return notFoundError(c, "log filter preset")
		}
		return databaseError(c, "update log filter preset", err)
	}
	return c.JSON(http.StatusOK, p)
}

// Delete removes a preset.
func (h *LogFilterPresetHandler) Delete(c echo.Context) error {
	if err := h.repo.Delete(c.Request().Context(), c.Param("id")); err != nil {
		if err == sql.ErrNoRows {
			return notFoundError(c, "log filter preset")
		}
		return databaseError(c, "delete log filter preset", err)
	}
	return c.NoContent(http.StatusNoContent)
}

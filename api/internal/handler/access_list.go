package handler

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

type AccessListHandler struct {
	repo       *repository.AccessListRepository
	proxyHosts *service.ProxyHostService
}

func NewAccessListHandler(repo *repository.AccessListRepository, proxyHosts *service.ProxyHostService) *AccessListHandler {
	return &AccessListHandler{repo: repo, proxyHosts: proxyHosts}
}

// List returns a paginated list of access lists.
// Query parameters: page (default: 1), per_page (default: 20, max: 100)
func (h *AccessListHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)

	lists, total, err := h.repo.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list access lists", err)
	}

	return c.JSON(http.StatusOK, model.AccessListListResponse{
		Data:       lists,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: CalculateTotalPages(total, perPage),
	})
}

// Create creates a new access list.
func (h *AccessListHandler) Create(c echo.Context) error {
	var req model.CreateAccessListRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	// Validate required fields
	if err := ValidateRequired(req.Name, "name"); err != nil {
		return validationError(c, "name", "is required")
	}

	// Validate field lengths
	if err := ValidateStringLength(req.Name, MaxNameLength, "name"); err != nil {
		return validationError(c, "name", err.(*ValidationError).Message)
	}

	list, err := h.repo.Create(c.Request().Context(), &req)
	if err != nil {
		return databaseError(c, "create access list", err)
	}

	return createdResponse(c, list)
}

// Get retrieves an access list by ID.
func (h *AccessListHandler) Get(c echo.Context) error {
	id := c.Param("id")
	list, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}
	return c.JSON(http.StatusOK, list)
}

// Update updates an existing access list.
func (h *AccessListHandler) Update(c echo.Context) error {
	id := c.Param("id")
	var req model.UpdateAccessListRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	// Validate field lengths if name is provided
	if req.Name != nil && *req.Name != "" {
		if err := ValidateStringLength(*req.Name, MaxNameLength, "name"); err != nil {
			return validationError(c, "name", err.(*ValidationError).Message)
		}
	}

	list, err := h.repo.Update(c.Request().Context(), id, &req)
	if err != nil {
		return databaseError(c, "update access list", err)
	}
	if list == nil {
		return notFoundError(c, "Access list")
	}

	// Access list rules are rendered statically into each dependent host's
	// nginx config, so the edit must fan out to every referencing host —
	// otherwise nginx silently keeps enforcing the stale allow/deny rules.
	if err := h.proxyHosts.RegenerateConfigsForAccessList(c.Request().Context(), id); err != nil {
		return internalError(c, "apply access list changes to nginx", err)
	}

	return c.JSON(http.StatusOK, list)
}

// Delete removes an access list by ID.
func (h *AccessListHandler) Delete(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	// Capture dependents BEFORE the delete detaches them (the repo clears
	// proxy_hosts.access_list_id in the same transaction).
	hostIDs, err := h.proxyHosts.GetHostIDsByAccessList(ctx, id)
	if err != nil {
		return databaseError(c, "list access list dependents", err)
	}

	if err := h.repo.Delete(ctx, id); err != nil {
		return databaseError(c, "delete access list", err)
	}

	// Regenerate dependent host configs so the deleted allow/deny rules stop
	// being enforced by the running nginx.
	if len(hostIDs) > 0 {
		if err := h.proxyHosts.RegenerateConfigsForHostIDs(ctx, hostIDs); err != nil {
			return internalError(c, "apply access list deletion to nginx", err)
		}
	}

	return noContentResponse(c)
}

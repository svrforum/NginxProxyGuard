package handler

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// FilterSubscriptionHandler handles filter subscription HTTP requests
type FilterSubscriptionHandler struct {
	service *service.FilterSubscriptionService
	audit   *service.AuditService
}

// NewFilterSubscriptionHandler creates a new filter subscription handler
func NewFilterSubscriptionHandler(svc *service.FilterSubscriptionService, audit *service.AuditService) *FilterSubscriptionHandler {
	return &FilterSubscriptionHandler{
		service: svc,
		audit:   audit,
	}
}

// List returns a paginated list of filter subscriptions
func (h *FilterSubscriptionHandler) List(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	result, err := h.service.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list filter subscriptions", err)
	}

	return c.JSON(http.StatusOK, result)
}

// GetByID returns a single filter subscription with entries and exclusions
func (h *FilterSubscriptionHandler) GetByID(c echo.Context) error {
	id := c.Param("id")

	detail, err := h.service.GetDetail(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get filter subscription", err)
	}
	if detail == nil {
		return notFoundError(c, "Filter subscription")
	}

	return c.JSON(http.StatusOK, detail)
}

// Create creates a new filter subscription
func (h *FilterSubscriptionHandler) Create(c echo.Context) error {
	var req model.CreateFilterSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.URL == "" {
		return badRequestError(c, "url is required")
	}

	sub, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		if isConflictError(err) {
			return conflictError(c, err.Error())
		}
		if isValidationError(err) {
			return badRequestError(c, err.Error())
		}
		return databaseError(c, "create filter subscription", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFilterSubscriptionCreated(auditCtx, sub.Name, sub.URL)

	return c.JSON(http.StatusCreated, sub)
}

// Update updates a filter subscription
func (h *FilterSubscriptionHandler) Update(c echo.Context) error {
	id := c.Param("id")

	var req model.UpdateFilterSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	sub, err := h.service.Update(c.Request().Context(), id, &req)
	if err != nil {
		return databaseError(c, "update filter subscription", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFilterSubscriptionUpdated(auditCtx, sub.Name)

	return c.JSON(http.StatusOK, sub)
}

// Delete deletes a filter subscription
func (h *FilterSubscriptionHandler) Delete(c echo.Context) error {
	id := c.Param("id")

	// Get name for audit log before deleting
	sub, err := h.service.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get filter subscription for delete", err)
	}
	if sub == nil {
		return notFoundError(c, "Filter subscription")
	}

	name := sub.Name

	if err := h.service.Delete(c.Request().Context(), id); err != nil {
		return databaseError(c, "delete filter subscription", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFilterSubscriptionDeleted(auditCtx, name)

	return c.NoContent(http.StatusNoContent)
}

// Refresh re-fetches a subscription
func (h *FilterSubscriptionHandler) Refresh(c echo.Context) error {
	id := c.Param("id")

	sub, err := h.service.Refresh(c.Request().Context(), id)
	if err != nil {
		if isValidationError(err) {
			return badRequestError(c, err.Error())
		}
		return databaseError(c, "refresh filter subscription", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFilterSubscriptionRefreshed(auditCtx, sub.Name)

	return c.JSON(http.StatusOK, sub)
}

// GetCatalog returns the filter catalog
func (h *FilterSubscriptionHandler) GetCatalog(c echo.Context) error {
	catalog, err := h.service.GetCatalog(c.Request().Context())
	if err != nil {
		return internalError(c, "get filter catalog", err)
	}

	return c.JSON(http.StatusOK, catalog)
}

// SubscribeFromCatalog subscribes to lists from the catalog
func (h *FilterSubscriptionHandler) SubscribeFromCatalog(c echo.Context) error {
	var req model.CatalogSubscribeRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if len(req.Paths) == 0 {
		return badRequestError(c, "paths is required")
	}

	subscribed, err := h.service.SubscribeFromCatalog(c.Request().Context(), &req)
	if err != nil {
		if isValidationError(err) {
			return badRequestError(c, err.Error())
		}
		return databaseError(c, "subscribe from catalog", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogFilterSubscriptionCatalogSubscribe(auditCtx, len(req.Paths))

	return c.JSON(http.StatusCreated, subscribed)
}

// ListExclusions returns host exclusions for a subscription
func (h *FilterSubscriptionHandler) ListExclusions(c echo.Context) error {
	subscriptionID := c.Param("id")

	exclusions, err := h.service.ListExclusions(c.Request().Context(), subscriptionID)
	if err != nil {
		return databaseError(c, "list filter subscription exclusions", err)
	}

	return c.JSON(http.StatusOK, exclusions)
}

// AddExclusion adds a host exclusion to a subscription
func (h *FilterSubscriptionHandler) AddExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")
	hostID := c.Param("hostId")

	if err := h.service.AddExclusion(c.Request().Context(), subscriptionID, hostID); err != nil {
		return databaseError(c, "add filter subscription exclusion", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// RemoveExclusion removes a host exclusion from a subscription
func (h *FilterSubscriptionHandler) RemoveExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")
	hostID := c.Param("hostId")

	if err := h.service.RemoveExclusion(c.Request().Context(), subscriptionID, hostID); err != nil {
		return databaseError(c, "remove filter subscription exclusion", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// ListEntryExclusions returns entry exclusions for a subscription
func (h *FilterSubscriptionHandler) ListEntryExclusions(c echo.Context) error {
	subscriptionID := c.Param("id")

	exclusions, err := h.service.ListEntryExclusions(c.Request().Context(), subscriptionID)
	if err != nil {
		return databaseError(c, "list entry exclusions", err)
	}

	return c.JSON(http.StatusOK, exclusions)
}

// AddEntryExclusion adds an entry exclusion to a subscription
func (h *FilterSubscriptionHandler) AddEntryExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")

	var req model.AddEntryExclusionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Value == "" {
		return badRequestError(c, "value is required")
	}

	// Validate format
	if net.ParseIP(req.Value) == nil {
		if _, _, err := net.ParseCIDR(req.Value); err != nil {
			return badRequestError(c, "value must be a valid IP address or CIDR")
		}
	}

	if err := h.service.AddEntryExclusion(c.Request().Context(), subscriptionID, req.Value); err != nil {
		return databaseError(c, "add entry exclusion", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// RemoveEntryExclusion removes an entry exclusion from a subscription
func (h *FilterSubscriptionHandler) RemoveEntryExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")
	value := c.QueryParam("value")

	if value == "" {
		return badRequestError(c, "value is required")
	}

	if err := h.service.RemoveEntryExclusion(c.Request().Context(), subscriptionID, value); err != nil {
		return databaseError(c, "remove entry exclusion", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// isConflictError checks if an error indicates a conflict
func isConflictError(err error) bool {
	msg := err.Error()
	return contains(msg, "already exist") || contains(msg, "already subscribed")
}

// isValidationError reports whether an error is the caller's to fix.
//
// The sentinel is authoritative — fetch failures against a caller-supplied URL
// carry it, and used to fall through to databaseError, reporting "A database
// error occurred" for a request that never touched the database (#270). The
// substring tests below remain for this package's older validators, which
// spell their own messages; they are a fallback, not the contract, because
// matching on text classified by accident (a host containing "invalid"
// answered 400 while an identical DNS failure elsewhere answered 500).
func isValidationError(err error) bool {
	if errors.Is(err, model.ErrInvalidInput) {
		return true
	}
	msg := err.Error()
	return contains(msg, "invalid") || contains(msg, "required") || contains(msg, "private") || contains(msg, "limit reached")
}

// contains checks if s contains substr (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsLower(s, substr)
}

func containsLower(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			sc := s[i+j]
			tc := substr[j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			if tc >= 'A' && tc <= 'Z' {
				tc += 32
			}
			if sc != tc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Match reports which subscriptions contain a given address or user-agent.
//
// It exists because a filter_subscription block in the access log says only
// THAT a list matched, never which one — nginx resolves every subscribed range
// through one shared radix tree. Without this the operator disables
// subscriptions one at a time until the block stops, which is what issue #230
// describes doing. (#230)
func (h *FilterSubscriptionHandler) Match(c echo.Context) error {
	ip := strings.TrimSpace(c.QueryParam("ip"))
	ua := c.QueryParam("user_agent")
	if ip == "" && strings.TrimSpace(ua) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "ip or user_agent is required"})
	}
	if ip != "" && net.ParseIP(ip) == nil {
		// Guarded rather than passed through: the query casts to inet, and an
		// unparseable value would surface as a 500 from Postgres.
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "ip is not a valid address"})
	}
	ipMatches, uaMatches, err := h.service.MatchesFor(c.Request().Context(), ip, ua)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to match against subscriptions"})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"ip_matches":         ipMatches,
		"user_agent_matches": uaMatches,
	})
}

package handler

import (
	"encoding/json"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

type RedirectHostHandler struct {
	repo         *repository.RedirectHostRepository
	nginxManager *nginx.Manager
	audit        *service.AuditService
}

func NewRedirectHostHandler(repo *repository.RedirectHostRepository, nginxManager *nginx.Manager, audit *service.AuditService) *RedirectHostHandler {
	return &RedirectHostHandler{
		repo:         repo,
		nginxManager: nginxManager,
		audit:        audit,
	}
}

func (h *RedirectHostHandler) List(c echo.Context) error {
	page, perPage := ParsePaginationParams(c)

	hosts, total, err := h.repo.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list redirect hosts", err)
	}

	return c.JSON(http.StatusOK, model.RedirectHostListResponse{
		Data:       hosts,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: CalculateTotalPages(total, perPage),
	})
}

func (h *RedirectHostHandler) Create(c echo.Context) error {
	var req model.CreateRedirectHostRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if len(req.DomainNames) == 0 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "At least one domain name is required"})
	}
	if req.ForwardDomainName == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Forward domain name is required"})
	}

	host, err := h.repo.Create(c.Request().Context(), &req)
	if err != nil {
		return databaseError(c, "create redirect host", err)
	}

	// Generate nginx config (atomic: snapshot + test + reload, rollback on failure)
	if host.Enabled {
		if err := h.nginxManager.GenerateRedirectConfigAndReload(c.Request().Context(), host); err != nil {
			return internalError(c, "apply redirect nginx config", err)
		}
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogRedirectHostCreated(auditCtx, host.DomainNames, host.ForwardDomainName)

	return c.JSON(http.StatusCreated, host)
}

func (h *RedirectHostHandler) Get(c echo.Context) error {
	id := c.Param("id")
	host, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get redirect host", err)
	}
	if host == nil {
		return notFoundError(c, "Redirect host")
	}
	return c.JSON(http.StatusOK, host)
}

func (h *RedirectHostHandler) Update(c echo.Context) error {
	id := c.Param("id")
	var req model.UpdateRedirectHostRequest
	if err := json.NewDecoder(c.Request().Body).Decode(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	host, err := h.repo.Update(c.Request().Context(), id, &req)
	if err != nil {
		return databaseError(c, "update redirect host", err)
	}
	if host == nil {
		return notFoundError(c, "Redirect host")
	}

	// Regenerate nginx config (atomic: snapshot + test + reload, rollback on
	// failure — a failed -t must not leave the invalid file on disk; handles
	// the disabled case by removing the config)
	if err := h.nginxManager.GenerateRedirectConfigAndReload(c.Request().Context(), host); err != nil {
		return internalError(c, "apply redirect nginx config", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogRedirectHostUpdated(auditCtx, host.DomainNames, nil)

	return c.JSON(http.StatusOK, host)
}

func (h *RedirectHostHandler) SyncAll(c echo.Context) error {
	hosts, _, err := h.repo.List(c.Request().Context(), 1, 10000)
	if err != nil {
		return databaseError(c, "list redirect hosts for sync", err)
	}

	if err := h.nginxManager.GenerateAllRedirectConfigs(c.Request().Context(), hosts); err != nil {
		return internalError(c, "sync all redirect configs", err)
	}

	if err := h.nginxManager.TestConfig(c.Request().Context()); err != nil {
		return internalError(c, "test nginx config", err)
	}
	if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
		return internalError(c, "reload nginx", err)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "All redirect configs synced successfully",
	})
}

func (h *RedirectHostHandler) Delete(c echo.Context) error {
	id := c.Param("id")

	// Get host first to remove config
	host, err := h.repo.GetByID(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "get redirect host for delete", err)
	}
	if host == nil {
		return notFoundError(c, "Redirect host")
	}

	// Remove nginx config
	if err := h.nginxManager.RemoveRedirectConfig(c.Request().Context(), host); err != nil {
		return internalError(c, "remove redirect nginx config", err)
	}

	// Delete from database
	if err := h.repo.Delete(c.Request().Context(), id); err != nil {
		return databaseError(c, "delete redirect host", err)
	}

	// Reload nginx
	if err := h.nginxManager.TestConfig(c.Request().Context()); err != nil {
		return internalError(c, "test nginx config", err)
	}
	if err := h.nginxManager.ReloadNginx(c.Request().Context()); err != nil {
		return internalError(c, "reload nginx", err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogRedirectHostDeleted(auditCtx, host.DomainNames)

	return c.NoContent(http.StatusNoContent)
}

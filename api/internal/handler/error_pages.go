package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// errorPageNginx applies the custom error pages (nginx.Manager).
type errorPageNginx interface {
	ApplyCustomErrorPages(ctx context.Context, pages []model.CustomErrorPage, directIPAction string) error
}

// ErrorPageHandler serves the operator's custom error pages (#335).
type ErrorPageHandler struct {
	repo           *repository.CustomErrorPageRepository
	globalSettings *repository.GlobalSettingsRepository
	nginx          errorPageNginx
	audit          *service.AuditService
}

func NewErrorPageHandler(repo *repository.CustomErrorPageRepository, globalSettings *repository.GlobalSettingsRepository, nginx errorPageNginx, audit *service.AuditService) *ErrorPageHandler {
	return &ErrorPageHandler{repo: repo, globalSettings: globalSettings, nginx: nginx, audit: audit}
}

type errorPagesResponse struct {
	Statuses []int                   `json:"statuses"`
	Pages    []model.CustomErrorPage `json:"pages"`
}

// List returns the pages that can be replaced and the custom ones.
func (h *ErrorPageHandler) List(c echo.Context) error {
	pages, err := h.repo.List(c.Request().Context())
	if err != nil {
		return databaseError(c, "list custom error pages", err)
	}
	return c.JSON(http.StatusOK, errorPagesResponse{Statuses: model.CustomErrorPageStatuses, Pages: pages})
}

// Update sets the HTML of one page and applies it.
func (h *ErrorPageHandler) Update(c echo.Context) error {
	code, ok := errorPageStatus(c)
	if !ok {
		return badRequestError(c, "status must be one of 403, 502, 503, 504")
	}
	var req struct {
		HTML string `json:"html"`
	}
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if err := model.ValidateCustomErrorPageHTML(req.HTML); err != nil {
		return badRequestError(c, strings.TrimPrefix(err.Error(), model.ErrInvalidInput.Error()+": "))
	}
	ctx := c.Request().Context()
	if err := h.repo.Upsert(ctx, code, req.HTML); err != nil {
		return databaseError(c, "save custom error page", err)
	}
	if err := h.apply(ctx); err != nil {
		return h.applyError(c, err)
	}
	h.audit.LogSettingsUpdate(service.ContextWithAudit(ctx, c), "error_pages", map[string]interface{}{
		"status_code": code, "action": "custom", "bytes": len(req.HTML),
	})
	return h.List(c)
}

// Reset puts one page back to the built-in one.
func (h *ErrorPageHandler) Reset(c echo.Context) error {
	code, ok := errorPageStatus(c)
	if !ok {
		return badRequestError(c, "status must be one of 403, 502, 503, 504")
	}
	ctx := c.Request().Context()
	if err := h.repo.Delete(ctx, code); err != nil {
		return databaseError(c, "reset custom error page", err)
	}
	if err := h.apply(ctx); err != nil {
		return h.applyError(c, err)
	}
	h.audit.LogSettingsUpdate(service.ContextWithAudit(ctx, c), "error_pages", map[string]interface{}{
		"status_code": code, "action": "reset",
	})
	return h.List(c)
}

// apply writes every page from the database and reloads nginx.
func (h *ErrorPageHandler) apply(ctx context.Context) error {
	pages, err := h.repo.List(ctx)
	if err != nil {
		return err
	}
	action := "allow"
	if s, err := h.globalSettings.Get(ctx); err == nil && s != nil {
		action = s.DirectIPAccessAction
	}
	return h.nginx.ApplyCustomErrorPages(ctx, pages, action)
}

func (h *ErrorPageHandler) applyError(c echo.Context, err error) error {
	if status, body, ok := reloadRejectedResponse(err); ok {
		return c.JSON(status, body)
	}
	return internalError(c, "apply custom error pages", err)
}

func errorPageStatus(c echo.Context) (int, bool) {
	code, err := strconv.Atoi(c.Param("status"))
	return code, err == nil && model.IsCustomErrorPageStatus(code)
}

package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// LogRulesReloader applies saved log rules to the log collector at once.
type LogRulesReloader interface {
	ReloadHostLogRules(ctx context.Context)
}

// LogRulesHandler serves the hosts' log rules (#347): the access log lines
// of a proxy host that are not stored.
type LogRulesHandler struct {
	repo  *repository.LogRulesRepository
	audit *service.AuditService
	// reloader is nil when log collection is off; the rules then apply
	// when it is on again.
	reloader LogRulesReloader
}

func NewLogRulesHandler(repo *repository.LogRulesRepository, audit *service.AuditService, reloader LogRulesReloader) *LogRulesHandler {
	return &LogRulesHandler{repo: repo, audit: audit, reloader: reloader}
}

// List returns every proxy host other than a stream host, with its rules.
func (h *LogRulesHandler) List(c echo.Context) error {
	entries, err := h.repo.List(c.Request().Context())
	if err != nil {
		return databaseError(c, "list log rules", err)
	}
	return c.JSON(http.StatusOK, entries)
}

// Get returns a proxy host with its rules.
func (h *LogRulesHandler) Get(c echo.Context) error {
	entry, err := h.repo.Get(c.Request().Context(), c.Param("proxyHostId"))
	if err != nil {
		return databaseError(c, "get log rules", err)
	}
	if entry == nil {
		return notFoundError(c, "Proxy host")
	}
	return c.JSON(http.StatusOK, entry)
}

// Update replaces a proxy host's rules. Rules that skip nothing remove them.
func (h *LogRulesHandler) Update(c echo.Context) error {
	ctx := c.Request().Context()
	var req model.UpdateHostLogRulesRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	rules, err := model.NormalizeHostLogRules(req)
	if err != nil {
		return badRequestError(c, trimInvalidInputPrefix(err))
	}
	entry, err := h.repo.Set(ctx, c.Param("proxyHostId"), rules)
	if err != nil {
		return databaseError(c, "save log rules", err)
	}
	if entry == nil {
		return notFoundError(c, "Proxy host")
	}
	if h.reloader != nil {
		h.reloader.ReloadHostLogRules(context.WithoutCancel(ctx))
	}

	auditCtx := service.ContextWithAudit(ctx, c)
	h.audit.LogSecurityFeatureUpdate(auditCtx, "log_rules", strings.Join(entry.DomainNames, ", "), !rules.IsEmpty(), map[string]interface{}{
		"skip_all":      rules.SkipAll,
		"skip_statuses": rules.SkipStatuses,
		"skip_methods":  rules.SkipMethods,
		"skip_paths":    rules.SkipPaths,
	})
	return c.JSON(http.StatusOK, entry)
}

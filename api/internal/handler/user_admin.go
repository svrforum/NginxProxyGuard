package handler

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// UserAdminHandler exposes role and user administration (#222).
type UserAdminHandler struct {
	service *service.UserAdminService
	audit   *service.AuditService
	authz   *service.AuthzService
}

func NewUserAdminHandler(svc *service.UserAdminService, audit *service.AuditService, authz *service.AuthzService) *UserAdminHandler {
	return &UserAdminHandler{service: svc, audit: audit, authz: authz}
}

// classifyAdminError maps the service's sentinel errors to status codes.
func classifyAdminError(c echo.Context, action string, err error) error {
	switch {
	case errors.Is(err, service.ErrLastSuperuser),
		errors.Is(err, service.ErrSelfMutation),
		errors.Is(err, service.ErrBuiltinRole),
		errors.Is(err, service.ErrRoleInUse):
		return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, service.ErrUnknownRole), errors.Is(err, sql.ErrNoRows):
		return c.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, service.ErrInvalidPerm),
		errors.Is(err, service.ErrInvalidRoleName),
		errors.Is(err, service.ErrInvalidUsername),
		errors.Is(err, service.ErrWeakPassword):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
	if err.Error() == "role name already exists" || err.Error() == "username already exists" {
		return c.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
	}
	return internalError(c, action, err)
}

// ─── Permission catalogue ───────────────────────────────────────────────

// GetPermissionAreas returns the area/verb matrix the role editor renders, so the
// UI never hardcodes a permission list that can drift from the server's.
func (h *UserAdminHandler) GetPermissionAreas(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"areas":       model.PermissionAreas,
		"permissions": model.AllAreaPermissions,
	})
}

// ─── Roles ──────────────────────────────────────────────────────────────

func (h *UserAdminHandler) ListRoles(c echo.Context) error {
	roles, err := h.service.ListRoles(c.Request().Context())
	if err != nil {
		return databaseError(c, "list roles", err)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"data": roles})
}

func (h *UserAdminHandler) CreateRole(c echo.Context) error {
	var req model.CreateRoleRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	role, err := h.service.CreateRole(c.Request().Context(), &req)
	if err != nil {
		return classifyAdminError(c, "create role", err)
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogRoleCreate(auditCtx, role.Name, len(role.Permissions))
	return c.JSON(http.StatusCreated, role)
}

func (h *UserAdminHandler) UpdateRole(c echo.Context) error {
	id := c.Param("id")
	var req model.UpdateRoleRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	role, err := h.service.UpdateRole(c.Request().Context(), id, &req)
	if err != nil {
		return classifyAdminError(c, "update role", err)
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogRoleUpdate(auditCtx, role.Name, len(role.Permissions))
	return c.JSON(http.StatusOK, role)
}

func (h *UserAdminHandler) DeleteRole(c echo.Context) error {
	id := c.Param("id")
	role, err := h.service.ListRoles(c.Request().Context())
	name := id
	if err == nil {
		for _, r := range role {
			if r.ID == id {
				name = r.Name
				break
			}
		}
	}
	if err := h.service.DeleteRole(c.Request().Context(), id); err != nil {
		return classifyAdminError(c, "delete role", err)
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogRoleDelete(auditCtx, name)
	return c.NoContent(http.StatusNoContent)
}

// ─── Users ──────────────────────────────────────────────────────────────

func (h *UserAdminHandler) ListUsers(c echo.Context) error {
	users, err := h.service.ListUsers(c.Request().Context())
	if err != nil {
		return databaseError(c, "list users", err)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"data": users})
}

func (h *UserAdminHandler) CreateUser(c echo.Context) error {
	var req model.CreateUserRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	// The full strength rule (length + character classes) lives here so the admin
	// path is never weaker than the self-service one.
	if err := ValidatePasswordStrength(req.Password); err != nil {
		return badRequestError(c, err.Error())
	}
	user, err := h.service.CreateUser(c.Request().Context(), &req)
	if err != nil {
		return classifyAdminError(c, "create user", err)
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogUserCreate(auditCtx, user.Username, user.RoleName)
	return c.JSON(http.StatusCreated, user)
}

func (h *UserAdminHandler) AssignRole(c echo.Context) error {
	targetID := c.Param("id")
	var req model.AssignRoleRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	actingID, _ := c.Get("user_id").(string)
	user, err := h.service.AssignRole(c.Request().Context(), actingID, targetID, req.RoleID)
	if err != nil {
		return classifyAdminError(c, "assign role", err)
	}
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogUserRoleAssign(auditCtx, user.Username, user.RoleName)
	return c.JSON(http.StatusOK, user)
}

func (h *UserAdminHandler) SetPassword(c echo.Context) error {
	targetID := c.Param("id")
	var req model.SetUserPasswordRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if err := ValidatePasswordStrength(req.Password); err != nil {
		return badRequestError(c, err.Error())
	}
	user, _ := h.service.GetUser(c.Request().Context(), targetID)
	if err := h.service.SetPassword(c.Request().Context(), targetID, req.Password); err != nil {
		return classifyAdminError(c, "set user password", err)
	}
	if user != nil {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		h.audit.LogUserPasswordReset(auditCtx, user.Username)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *UserAdminHandler) DeleteUser(c echo.Context) error {
	targetID := c.Param("id")
	actingID, _ := c.Get("user_id").(string)
	user, _ := h.service.GetUser(c.Request().Context(), targetID)
	if err := h.service.DeleteUser(c.Request().Context(), actingID, targetID); err != nil {
		return classifyAdminError(c, "delete user", err)
	}
	if user != nil {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		h.audit.LogUserDelete(auditCtx, user.Username, user.APITokenCount)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *UserAdminHandler) EndSessions(c echo.Context) error {
	targetID := c.Param("id")
	if err := h.service.EndSessions(c.Request().Context(), targetID); err != nil {
		return internalError(c, "end user sessions", err)
	}
	return c.NoContent(http.StatusNoContent)
}

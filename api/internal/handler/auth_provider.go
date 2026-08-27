package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type AuthProviderHandler struct {
	service *service.AuthProviderService
}

func NewAuthProviderHandler(svc *service.AuthProviderService) *AuthProviderHandler {
	return &AuthProviderHandler{service: svc}
}

func (h *AuthProviderHandler) List(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if perPage < 1 {
		perPage = 20
	}
	items, total, err := h.service.List(c.Request().Context(), page, perPage)
	if err != nil {
		return internalError(c, "list auth providers", err)
	}
	if items == nil {
		items = []model.AuthProvider{}
	}
	totalPages := (total + perPage - 1) / perPage
	return c.JSON(http.StatusOK, model.AuthProviderListResponse{
		Data: items, Total: total, Page: page, PerPage: perPage, TotalPages: totalPages,
	})
}

func (h *AuthProviderHandler) Get(c echo.Context) error {
	ap, err := h.service.GetByID(c.Request().Context(), c.Param("id"))
	if err != nil {
		return internalError(c, "get auth provider", err)
	}
	if ap == nil {
		return notFoundError(c, "Auth provider")
	}
	return c.JSON(http.StatusOK, ap)
}

// isAuthProviderInputError reports whether an error is the caller's to fix.
//
// It replaces a strings.Contains(err, "invalid") test that was wrong in both
// directions: the database's CHECK-constraint message for a bad `type` carries
// no "invalid", so a typo'd type answered 500 with the raw driver text (#269),
// while pq's "invalid input syntax for type uuid" DID match, turning a
// malformed :id into a 400 that echoed internals. The sentinel is authoritative;
// the prefix check only covers this package's own older validators, which spell
// their messages "invalid: ...".
func isAuthProviderInputError(err error) bool {
	if errors.Is(err, model.ErrInvalidInput) {
		return true
	}
	return strings.HasPrefix(err.Error(), "invalid: ")
}

func (h *AuthProviderHandler) Create(c echo.Context) error {
	var req model.CreateAuthProviderRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	ap, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		if isAuthProviderInputError(err) {
			return badRequestError(c, err.Error())
		}
		return internalError(c, "create auth provider", err)
	}
	return c.JSON(http.StatusCreated, ap)
}

func (h *AuthProviderHandler) Update(c echo.Context) error {
	var req model.UpdateAuthProviderRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	ap, err := h.service.Update(c.Request().Context(), c.Param("id"), &req)
	if err != nil {
		if isAuthProviderInputError(err) {
			return badRequestError(c, err.Error())
		}
		return internalError(c, "update auth provider", err)
	}
	if ap == nil {
		return notFoundError(c, "Auth provider")
	}
	return c.JSON(http.StatusOK, ap)
}

func (h *AuthProviderHandler) Delete(c echo.Context) error {
	if err := h.service.Delete(c.Request().Context(), c.Param("id")); err != nil {
		return internalError(c, "delete auth provider", err)
	}
	return c.NoContent(http.StatusNoContent)
}

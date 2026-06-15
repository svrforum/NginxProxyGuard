package handler

import (
	"net/http"
	"strconv"

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

func (h *AuthProviderHandler) Create(c echo.Context) error {
	var req model.CreateAuthProviderRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	ap, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
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

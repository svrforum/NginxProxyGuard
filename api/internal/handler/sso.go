package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// SSOHandler exposes the OIDC login flow and the provider registry. (#227)
type SSOHandler struct {
	service *service.SSOService
	audit   *service.AuditService
}

func NewSSOHandler(s *service.SSOService, audit *service.AuditService) *SSOHandler {
	return &SSOHandler{service: s, audit: audit}
}

// completePath is the SPA route that receives the session token. The token
// travels in the URL fragment, which browsers never send to a server and which
// no proxy or access log can record.
const completePath = "/sso/complete"

// ── login flow (public) ───────────────────────────────────────────────────

// ListPublicProviders backs the login screen's buttons. Unauthenticated by
// necessity, so it returns nothing but id, slug and name.
func (h *SSOHandler) ListPublicProviders(c echo.Context) error {
	providers, err := h.service.ListPublic(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to list providers"})
	}
	return c.JSON(http.StatusOK, map[string]any{"data": providers})
}

// Start redirects the browser to the identity provider.
func (h *SSOHandler) Start(c echo.Context) error {
	authURL, err := h.service.StartLogin(c.Request().Context(), c.Param("slug"), requestBase(c))
	if err != nil {
		return c.Redirect(http.StatusFound, completePath+"#error="+errorCode(err))
	}
	return c.Redirect(http.StatusFound, authURL)
}

// Callback finishes the flow and hands the SPA a session token.
//
// Every failure ends at the same SPA route with an error code rather than a JSON
// body: the browser arrived here by a redirect from the IdP, so a raw API
// response would strand the operator on a blank page.
func (h *SSOHandler) Callback(c echo.Context) error {
	slug := c.Param("slug")
	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	// The IdP reports its own refusals here — an unapproved app, a cancelled
	// consent screen — before any code exists to exchange.
	if idpErr := c.QueryParam("error"); idpErr != "" {
		return c.Redirect(http.StatusFound, completePath+"#error=provider_refused")
	}

	code := c.QueryParam("code")
	state := c.QueryParam("state")
	if code == "" || state == "" {
		return c.Redirect(http.StatusFound, completePath+"#error=invalid_response")
	}

	token, err := h.service.CompleteLogin(c.Request().Context(), slug, code, state, requestBase(c), ip, userAgent)
	if err != nil {
		if h.audit != nil {
			_ = h.audit.LogUserLoginFailed(c.Request().Context(), "sso:"+slug, ip, userAgent, errorCode(err))
		}
		return c.Redirect(http.StatusFound, completePath+"#error="+errorCode(err))
	}
	return c.Redirect(http.StatusFound, completePath+"#token="+url.QueryEscape(token))
}

// errorCode maps a service error to a stable string the UI translates. The
// operator-facing text lives in the frontend so it can be localised; nothing
// here leaks which stage of the exchange failed to an anonymous caller.
func errorCode(err error) string {
	switch {
	case errors.Is(err, service.ErrSSOUnavailable):
		return "unavailable"
	case errors.Is(err, service.ErrSSOProviderGone):
		return "unknown_provider"
	case errors.Is(err, service.ErrSSOStateInvalid):
		return "expired"
	case errors.Is(err, service.ErrSSONoAccount):
		return "no_account"
	case errors.Is(err, service.ErrSSONotAllowed):
		return "not_allowed"
	case errors.Is(err, service.ErrSSOEmailMissing):
		return "no_email"
	case errors.Is(err, service.ErrSSODiscovery):
		return "provider_unreachable"
	case errors.Is(err, service.ErrSSOTokenInvalid):
		return "verification_failed"
	default:
		return "failed"
	}
}

// requestBase reconstructs the public origin this request arrived on, used to
// build the redirect_uri when a provider has no explicit callback base. An
// install behind another proxy should set that base rather than rely on
// headers: a wrong value here simply fails the IdP's exact-match check, which
// is a configuration error, not a security hole.
func requestBase(c echo.Context) string {
	r := c.Request()
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	return scheme + "://" + host
}

// ── administration ────────────────────────────────────────────────────────

func (h *SSOHandler) ListProviders(c echo.Context) error {
	providers, err := h.service.ListProviders(c.Request().Context())
	if err != nil {
		return classifySSOError(c, err)
	}
	// The callback URL is derived, not stored; the UI shows it so the operator
	// can register the exact value at the identity provider.
	base := requestBase(c)
	for i := range providers {
		providers[i].CallbackURL = service.CallbackURL(base, &providers[i])
	}
	return c.JSON(http.StatusOK, map[string]any{"data": providers})
}

func (h *SSOHandler) CreateProvider(c echo.Context) error {
	var req model.CreateSSOProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	p, err := h.service.CreateProvider(c.Request().Context(), &req)
	if err != nil {
		return classifySSOError(c, err)
	}
	p.CallbackURL = service.CallbackURL(requestBase(c), p)
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(c.Request().Context(), c),
			"sso_provider_created", map[string]any{"slug": p.Slug, "issuer": p.IssuerURL})
	}
	return c.JSON(http.StatusCreated, p)
}

func (h *SSOHandler) UpdateProvider(c echo.Context) error {
	var req model.UpdateSSOProviderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}
	p, err := h.service.UpdateProvider(c.Request().Context(), c.Param("id"), &req)
	if err != nil {
		return classifySSOError(c, err)
	}
	p.CallbackURL = service.CallbackURL(requestBase(c), p)
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(c.Request().Context(), c),
			"sso_provider_updated", map[string]any{"slug": p.Slug, "issuer": p.IssuerURL})
	}
	return c.JSON(http.StatusOK, p)
}

func (h *SSOHandler) DeleteProvider(c echo.Context) error {
	if err := h.service.DeleteProvider(c.Request().Context(), c.Param("id")); err != nil {
		return classifySSOError(c, err)
	}
	if h.audit != nil {
		_ = h.audit.LogSettingsUpdate(service.ContextWithAudit(c.Request().Context(), c),
			"sso_provider_deleted", map[string]any{"id": c.Param("id")})
	}
	return c.NoContent(http.StatusNoContent)
}

func classifySSOError(c echo.Context, err error) error {
	switch {
	case errors.Is(err, service.ErrSSOUnavailable):
		return c.JSON(http.StatusServiceUnavailable, map[string]string{
			"error": "SSO tables are missing — check the migration log"})
	case errors.Is(err, service.ErrSSOProviderInUse):
		return c.JSON(http.StatusNotFound, map[string]string{"error": "Provider not found"})
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "already exists"):
		return c.JSON(http.StatusConflict, map[string]string{"error": msg})
	case strings.HasPrefix(msg, "invalid"), strings.Contains(msg, "does not exist"):
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}
	return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Operation failed"})
}

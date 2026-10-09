package handler

import (
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// normalizeIP strips IPv4-mapped IPv6 prefixes (::ffff:) and zone IDs
// to ensure consistent IP comparison across dual-stack environments.
// e.g. "::ffff:192.168.1.1" → "192.168.1.1", "fe80::1%eth0" → "fe80::1"
func normalizeIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

// escapeJS escapes a string for safe use in JavaScript string literals
// Prevents XSS attacks when embedding user data in JavaScript
func escapeJS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "<", "\\x3c")
	s = strings.ReplaceAll(s, ">", "\\x3e")
	s = strings.ReplaceAll(s, "&", "\\x26")
	return s
}

// escapeHTML escapes a string for safe use in HTML content
// Uses the standard html.EscapeString for proper HTML entity encoding
func escapeHTML(s string) string {
	return html.EscapeString(s)
}

// Embedded favicon data (loaded at startup)
var faviconData []byte

func init() {
	// Try to load favicon from assets directory
	paths := []string{
		"./assets/favicon.ico",
		"/app/assets/favicon.ico",
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			faviconData = data
			break
		}
	}
}

// ServeFavicon serves the favicon.ico file for challenge pages
func ServeFavicon(c echo.Context) error {
	if len(faviconData) == 0 {
		// Fallback: try to read from file
		execPath, _ := os.Executable()
		faviconPath := filepath.Join(filepath.Dir(execPath), "assets", "favicon.ico")
		data, err := os.ReadFile(faviconPath)
		if err != nil {
			return c.NoContent(http.StatusNotFound)
		}
		faviconData = data
	}
	return c.Blob(http.StatusOK, "image/x-icon", faviconData)
}

type ChallengeHandler struct {
	svc   *service.ChallengeService
	audit *service.AuditService
}

func NewChallengeHandler(svc *service.ChallengeService, audit *service.AuditService) *ChallengeHandler {
	return &ChallengeHandler{svc: svc, audit: audit}
}

// GetGlobalConfig returns global challenge config
func (h *ChallengeHandler) GetGlobalConfig(c echo.Context) error {
	config, err := h.svc.GetGlobalConfig(c.Request().Context())
	if err != nil {
		return directInternalError(c, err)
	}
	return c.JSON(http.StatusOK, config.ToResponse())
}

// UpdateGlobalConfig updates global challenge config
func (h *ChallengeHandler) UpdateGlobalConfig(c echo.Context) error {
	var req model.ChallengeConfigRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	config, err := h.svc.UpdateConfig(c.Request().Context(), nil, &req)
	if err != nil {
		return directInternalError(c, err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "CAPTCHA Challenge", map[string]interface{}{
		"scope": "global",
	})

	return c.JSON(http.StatusOK, config.ToResponse())
}

// GetProxyHostConfig returns challenge config for a proxy host
func (h *ChallengeHandler) GetProxyHostConfig(c echo.Context) error {
	proxyHostID := c.Param("id")
	config, err := h.svc.GetConfig(c.Request().Context(), &proxyHostID)
	if err != nil {
		return directInternalError(c, err)
	}
	return c.JSON(http.StatusOK, config.ToResponse())
}

// UpdateProxyHostConfig updates challenge config for a proxy host
func (h *ChallengeHandler) UpdateProxyHostConfig(c echo.Context) error {
	proxyHostID := c.Param("id")

	var req model.ChallengeConfigRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	config, err := h.svc.UpdateConfig(c.Request().Context(), &proxyHostID, &req)
	if err != nil {
		return directInternalError(c, err)
	}

	// Audit log
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogSettingsUpdate(auditCtx, "CAPTCHA Challenge", map[string]interface{}{
		"proxy_host_id": proxyHostID,
	})

	return c.JSON(http.StatusOK, config.ToResponse())
}

// DeleteProxyHostConfig deletes challenge config for a proxy host
func (h *ChallengeHandler) DeleteProxyHostConfig(c echo.Context) error {
	proxyHostID := c.Param("id")

	if err := h.svc.DeleteConfig(c.Request().Context(), &proxyHostID); err != nil {
		return directInternalError(c, err)
	}

	return c.NoContent(http.StatusNoContent)
}

// VerifyCaptcha verifies CAPTCHA and issues bypass token (public endpoint)
func (h *ChallengeHandler) VerifyCaptcha(c echo.Context) error {
	var req model.VerifyCaptchaRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request body"})
	}

	if req.Token == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "CAPTCHA token is required"})
	}

	clientIP := normalizeIP(c.RealIP())
	userAgent := c.Request().UserAgent()

	resp, err := h.svc.VerifyCaptcha(c.Request().Context(), &req, clientIP, userAgent)
	if err != nil {
		if err == service.ErrChallengeDisabled {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Challenge is not enabled"})
		}
		if err == service.ErrMissingConfig {
			return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "CAPTCHA is not configured"})
		}
		return directInternalError(c, err)
	}

	return c.JSON(http.StatusOK, resp)
}

// VerifyAndRedirect handles form-based CAPTCHA verification. Unlike the JSON
// /verify endpoint (which relies on fetch), this accepts a form POST and
// responds with Set-Cookie + 302 redirect. This bypasses browser extensions
// or ad-blockers that silently block fetch() requests to "challenge/verify".
func (h *ChallengeHandler) VerifyAndRedirect(c echo.Context) error {
	token := c.FormValue("token")
	proxyHostID := c.FormValue("proxy_host_id")
	reason := c.FormValue("challenge_reason")
	returnURL := c.FormValue("return_url")

	// Validate returnURL to prevent open redirect attacks.
	// Only allow relative paths (starting with /) or same-host URLs.
	returnURL = sanitizeReturnURL(returnURL, c.Request().Host)

	referer := c.Request().Referer()
	if referer == "" {
		referer = "/"
	}

	if token == "" {
		return c.Redirect(http.StatusFound, referer)
	}

	clientIP := normalizeIP(c.RealIP())
	userAgent := c.Request().UserAgent()

	req := &model.VerifyCaptchaRequest{
		Token:           token,
		ProxyHostID:     proxyHostID,
		ChallengeReason: reason,
	}

	resp, err := h.svc.VerifyCaptcha(c.Request().Context(), req, clientIP, userAgent)
	if err != nil {
		// Service-level error (CAPTCHA provider unreachable, config missing, etc.)
		// Return a 503 error page instead of silently redirecting back to challenge
		// page, which would cause an infinite loop.
		return c.HTML(http.StatusServiceUnavailable, `<!DOCTYPE html><html><head><title>Service Unavailable</title>
<meta http-equiv="refresh" content="5"></head><body style="font-family:sans-serif;text-align:center;padding:60px">
<h1>Service Temporarily Unavailable</h1><p>CAPTCHA verification service is currently unavailable. Retrying in 5 seconds...</p></body></html>`)
	}
	if !resp.Success {
		return c.Redirect(http.StatusFound, referer)
	}

	// Set ng_challenge cookie via Set-Cookie header
	secure := c.Scheme() == "https"
	cookie := &http.Cookie{
		Name:     "ng_challenge",
		Value:    resp.Token,
		Path:     "/",
		Expires:  resp.ExpiresAt,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		HttpOnly: true,
	}
	c.SetCookie(cookie)

	return c.Redirect(http.StatusFound, returnURL)
}

// sanitizeReturnURL validates that returnURL is safe for redirection.
// Only allows relative paths or URLs whose host matches the request host.
// Falls back to "/" for any other value to prevent open redirect attacks.
func sanitizeReturnURL(returnURL, requestHost string) string {
	if returnURL == "" {
		return "/"
	}

	// Allow relative paths
	if strings.HasPrefix(returnURL, "/") && !strings.HasPrefix(returnURL, "//") {
		return returnURL
	}

	// Allow same-host absolute URLs
	if strings.HasPrefix(returnURL, "http://") || strings.HasPrefix(returnURL, "https://") {
		// Extract host from returnURL
		afterScheme := returnURL[strings.Index(returnURL, "://")+3:]
		slashIdx := strings.Index(afterScheme, "/")
		var urlHost string
		if slashIdx >= 0 {
			urlHost = afterScheme[:slashIdx]
		} else {
			urlHost = afterScheme
		}
		// Strip port from both for comparison
		urlHostNoPort := strings.Split(urlHost, ":")[0]
		reqHostNoPort := strings.Split(requestHost, ":")[0]
		if strings.EqualFold(urlHostNoPort, reqHostNoPort) {
			return returnURL
		}
	}

	return "/"
}

// ValidateToken checks a challenge token for nginx's auth_request gate.
//
// nginx decides whether a visitor has to pass the challenge. Its
// /_challenge/validate location answers 204 itself for a visitor the host does
// not challenge ($geo_blocked is 0: an allowed country, a private, priority or
// trusted IP, or a search bot the host allows) and 401 for a challenged
// visitor without a token. It asks this endpoint only about a challenged
// visitor that carries a token, so the answer depends on the token alone.
// Nothing the client controls, such as the User-Agent, may grant access here.
func (h *ChallengeHandler) ValidateToken(c echo.Context) error {
	// Configs rendered by older versions also ask about visitors nginx does
	// not challenge, flagged X-Geo-Blocked: 0. nginx sets this header itself
	// (proxy_set_header replaces a copy sent by the client); current configs
	// always send 1. Missing or any other value: the token decides.
	if c.Request().Header.Get("X-Geo-Blocked") == "0" {
		return c.NoContent(http.StatusOK)
	}

	// Token can be from cookie or header
	token := c.Request().Header.Get("X-Challenge-Token")
	if token == "" {
		cookie, err := c.Cookie("ng_challenge")
		if err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		return c.NoContent(http.StatusUnauthorized)
	}

	clientIP := normalizeIP(c.RealIP())
	proxyHostID := c.Request().Header.Get("X-Proxy-Host-ID")

	var proxyHostPtr *string
	if proxyHostID != "" {
		proxyHostPtr = &proxyHostID
	}

	resp, err := h.svc.ValidateToken(c.Request().Context(), token, clientIP, proxyHostPtr)
	if err != nil {
		return c.NoContent(http.StatusUnauthorized)
	}

	if !resp.Valid {
		return c.NoContent(http.StatusUnauthorized)
	}

	return c.NoContent(http.StatusOK)
}

// GetStats returns challenge statistics
func (h *ChallengeHandler) GetStats(c echo.Context) error {
	proxyHostID := c.QueryParam("proxy_host_id")
	hours := 24 // Default 24 hours

	var proxyHostPtr *string
	if proxyHostID != "" {
		proxyHostPtr = &proxyHostID
	}

	stats, err := h.svc.GetStats(c.Request().Context(), proxyHostPtr, hours)
	if err != nil {
		return directInternalError(c, err)
	}

	return c.JSON(http.StatusOK, stats)
}

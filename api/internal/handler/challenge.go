package handler

import (
	"html"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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

// searchBotPattern matches known search engine bot user agents
var searchBotPattern = regexp.MustCompile(`(?i)(Googlebot|Googlebot-Mobile|Googlebot-Image|Googlebot-News|Googlebot-Video|AdsBot-Google|AdsBot-Google-Mobile|Mediapartners-Google|APIs-Google|FeedFetcher-Google|Google-Read-Aloud|DuplexWeb-Google|Storebot-Google|Google-InspectionTool|GoogleOther|bingbot|msnbot|BingPreview|Slurp|DuckDuckBot|Baiduspider|YandexBot|yandex|Sogou|Exabot|facebot|ia_archiver|applebot|naverbot|Yeti|seznambot|petalbot|360spider|qwantify)`)

// isSearchBot checks if the user agent is a known search engine bot
func isSearchBot(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	return searchBotPattern.MatchString(strings.ToLower(userAgent))
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, resp)
}

// ValidateToken validates a bypass token (internal endpoint for nginx auth_request)
func (h *ChallengeHandler) ValidateToken(c echo.Context) error {
	// Check if country is allowed (not geo-blocked) - pass through without challenge
	geoBlocked := c.Request().Header.Get("X-Geo-Blocked")
	if geoBlocked == "0" {
		return c.NoContent(http.StatusOK)
	}

	// Check if request is from a search engine bot - allow them through
	userAgent := c.Request().UserAgent()
	if isSearchBot(userAgent) {
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
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, stats)
}

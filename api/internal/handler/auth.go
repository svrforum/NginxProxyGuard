package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type AuthHandler struct {
	authService  *service.AuthService
	auditService *service.AuditService
}

func NewAuthHandler(authService *service.AuthService, auditService *service.AuditService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		auditService: auditService,
	}
}

// getUserFromContext safely extracts user from echo context
func getUserFromContext(c echo.Context) (*model.User, bool) {
	val := c.Get("user")
	if val == nil {
		return nil, false
	}
	user, ok := val.(*model.User)
	return user, ok
}

// Login handles user authentication
func (h *AuthHandler) Login(c echo.Context) error {
	var req model.LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if req.Username == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Username and password are required",
		})
	}

	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	resp, err := h.authService.Login(c.Request().Context(), &req, ip, userAgent)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			// Audit failed attempts so operators can see brute-force activity
			_ = h.auditService.LogUserLoginFailed(c.Request().Context(), req.Username, ip, userAgent, "invalid_credentials")
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid username or password",
			})
		case service.ErrTooManyAttempts:
			_ = h.auditService.LogUserLoginFailed(c.Request().Context(), req.Username, ip, userAgent, "locked_out")
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error": "Too many failed login attempts. Please try again later.",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Login failed",
			})
		}
	}

	// Log successful login if not requiring 2FA
	if !resp.Requires2FA && resp.User != nil {
		// For login, set user info directly since middleware hasn't set it yet
		ctx := c.Request().Context()
		ctx = context.WithValue(ctx, "user_id", resp.User.ID)
		ctx = context.WithValue(ctx, "username", resp.User.Username)
		ctx = context.WithValue(ctx, "client_ip", ip)
		ctx = context.WithValue(ctx, "user_agent", userAgent)
		h.auditService.LogUserLogin(ctx, req.Username, ip, userAgent)
	}

	return c.JSON(http.StatusOK, resp)
}

// Logout handles user logout
func (h *AuthHandler) Logout(c echo.Context) error {
	token := extractToken(c)
	if token == "" {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Logged out",
		})
	}

	// Get username for audit log before logout
	username := ""
	if u, ok := c.Get("username").(string); ok {
		username = u
	}

	if err := h.authService.Logout(c.Request().Context(), token); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Logout failed",
		})
	}

	// Log logout
	if username != "" {
		auditCtx := service.ContextWithAudit(c.Request().Context(), c)
		h.auditService.LogUserLogout(auditCtx, username)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// GetStatus returns the current authentication status
func (h *AuthHandler) GetStatus(c echo.Context) error {
	token := extractToken(c)

	status, err := h.authService.GetAuthStatus(c.Request().Context(), token)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to get auth status",
		})
	}

	return c.JSON(http.StatusOK, status)
}

// GetCurrentUser returns the current authenticated user
func (h *AuthHandler) GetCurrentUser(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}
	return c.JSON(http.StatusOK, user)
}

// ChangeCredentials handles initial setup credential change
func (h *AuthHandler) ChangeCredentials(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.ChangeCredentialsRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if req.CurrentPassword == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Current password is required",
		})
	}

	if req.NewUsername == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "New username is required",
		})
	}

	if len(req.NewUsername) < 3 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Username must be at least 3 characters",
		})
	}

	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	if req.NewPassword != req.NewPasswordConfirm {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Passwords do not match",
		})
	}

	err := h.authService.ChangeCredentials(c.Request().Context(), user.ID, &req)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Current password is incorrect",
			})
		case service.ErrUsernameTaken:
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "Username is already taken",
			})
		case service.ErrWeakPassword:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": service.ErrWeakPassword.Error(),
			})
		case service.ErrPasswordMismatch:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Passwords do not match",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to change credentials",
			})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Credentials changed successfully. Please login with your new credentials.",
	})
}

// ChangePassword handles password change
func (h *AuthHandler) ChangePassword(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if err := ValidatePasswordStrength(req.NewPassword); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	if req.NewPassword != req.NewPasswordConfirm {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Passwords do not match",
		})
	}

	err := h.authService.ChangePassword(c.Request().Context(), user.ID, &req)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Current password is incorrect",
			})
		case service.ErrWeakPassword:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": service.ErrWeakPassword.Error(),
			})
		case service.ErrPasswordMismatch:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Passwords do not match",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to change password",
			})
		}
	}

	// Log password change
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.auditService.LogPasswordChanged(auditCtx, user.Username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password changed successfully",
	})
}

// GetLanguage returns the current user's language setting
func (h *AuthHandler) GetLanguage(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	language := user.Language
	if language == "" {
		language = "ko" // Default language
	}

	return c.JSON(http.StatusOK, model.LanguageResponse{
		Language: language,
	})
}

// SetLanguage updates the current user's language setting
func (h *AuthHandler) SetLanguage(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.LanguageRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// Validate language
	if req.Language != "ko" && req.Language != "en" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid language. Supported languages: ko, en",
		})
	}

	err := h.authService.SetLanguage(c.Request().Context(), user.ID, req.Language)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to update language",
		})
	}

	return c.JSON(http.StatusOK, model.LanguageResponse{
		Language: req.Language,
	})
}

// SetFontFamily updates the current user's font family setting
func (h *AuthHandler) SetFontFamily(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.FontFamilyRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	// Validate font family (allow system and custom fonts)
	validFonts := []string{"system", "gowun-batang", "noto-sans-kr", "pretendard", "inter"}
	isValid := false
	for _, f := range validFonts {
		if req.FontFamily == f {
			isValid = true
			break
		}
	}
	if !isValid {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid font family",
		})
	}

	err := h.authService.SetFontFamily(c.Request().Context(), user.ID, req.FontFamily)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to update font family",
		})
	}

	return c.JSON(http.StatusOK, model.FontFamilyResponse{
		FontFamily: req.FontFamily,
	})
}

// GetFontFamily returns the current user's font family setting
func (h *AuthHandler) GetFontFamily(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	return c.JSON(http.StatusOK, model.FontFamilyResponse{
		FontFamily: user.FontFamily,
	})
}

// ChangeUsername handles username change
func (h *AuthHandler) ChangeUsername(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.ChangeUsernameRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if req.CurrentPassword == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Current password is required",
		})
	}

	if len(req.NewUsername) < 3 {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Username must be at least 3 characters",
		})
	}

	oldUsername := user.Username
	err := h.authService.ChangeUsername(c.Request().Context(), user.ID, &req)
	if err != nil {
		switch err {
		case service.ErrInvalidCredentials:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Current password is incorrect",
			})
		case service.ErrUsernameTaken:
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "Username is already taken",
			})
		default:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
		}
	}

	// Log username change
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.auditService.LogUsernameChanged(auditCtx, oldUsername, req.NewUsername)

	return c.JSON(http.StatusOK, map[string]string{
		"message":  "Username changed successfully",
		"username": req.NewUsername,
	})
}

func extractToken(c echo.Context) string {
	// Check Authorization header
	auth := c.Request().Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
	}
	return ""
}

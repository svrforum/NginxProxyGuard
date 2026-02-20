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
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid username or password",
			})
		case service.ErrTooManyAttempts:
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

// Verify2FA completes login with 2FA code
func (h *AuthHandler) Verify2FA(c echo.Context) error {
	var req model.Verify2FARequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if req.TempToken == "" || req.TOTPCode == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Temporary token and TOTP code are required",
		})
	}

	ip := c.RealIP()
	userAgent := c.Request().UserAgent()

	resp, err := h.authService.Verify2FA(c.Request().Context(), &req, ip)
	if err != nil {
		switch err {
		case service.ErrInvalidTempToken:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid or expired temporary token",
			})
		case service.ErrInvalid2FACode:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid 2FA code",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "2FA verification failed",
			})
		}
	}

	// Log successful login after 2FA verification
	if resp.User != nil {
		// For login, set user info directly since middleware hasn't set it yet
		ctx := c.Request().Context()
		ctx = context.WithValue(ctx, "user_id", resp.User.ID)
		ctx = context.WithValue(ctx, "username", resp.User.Username)
		ctx = context.WithValue(ctx, "client_ip", ip)
		ctx = context.WithValue(ctx, "user_agent", userAgent)
		h.auditService.LogUserLogin(ctx, resp.User.Username, ip, userAgent)
	}

	return c.JSON(http.StatusOK, resp)
}

// GetAccountInfo returns account information
func (h *AuthHandler) GetAccountInfo(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	info, err := h.authService.GetAccountInfo(c.Request().Context(), user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to get account info",
		})
	}

	return c.JSON(http.StatusOK, info)
}

// Setup2FA initiates 2FA setup
func (h *AuthHandler) Setup2FA(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	resp, err := h.authService.Setup2FA(c.Request().Context(), user.ID)
	if err != nil {
		switch err {
		case service.Err2FAAlreadyEnabled:
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "2FA is already enabled",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to setup 2FA",
			})
		}
	}

	return c.JSON(http.StatusOK, resp)
}

// Enable2FA enables 2FA after verifying code
func (h *AuthHandler) Enable2FA(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.Enable2FARequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if req.TOTPCode == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "TOTP code is required",
		})
	}

	err := h.authService.Enable2FA(c.Request().Context(), user.ID, &req)
	if err != nil {
		switch err {
		case service.Err2FAAlreadyEnabled:
			return c.JSON(http.StatusConflict, map[string]string{
				"error": "2FA is already enabled",
			})
		case service.ErrInvalid2FACode:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid 2FA code",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to enable 2FA",
			})
		}
	}

	// Log 2FA enabled
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.auditService.Log2FAEnabled(auditCtx, user.Username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "2FA enabled successfully",
	})
}

// Disable2FA disables 2FA
func (h *AuthHandler) Disable2FA(c echo.Context) error {
	user, ok := getUserFromContext(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "authentication required"})
	}

	var req model.Disable2FARequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if req.Password == "" || req.TOTPCode == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Password and TOTP code are required",
		})
	}

	err := h.authService.Disable2FA(c.Request().Context(), user.ID, &req)
	if err != nil {
		switch err {
		case service.Err2FANotEnabled:
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "2FA is not enabled",
			})
		case service.ErrInvalidCredentials:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid password",
			})
		case service.ErrInvalid2FACode:
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "Invalid 2FA code",
			})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "Failed to disable 2FA",
			})
		}
	}

	// Log 2FA disabled
	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.auditService.Log2FADisabled(auditCtx, user.Username)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "2FA disabled successfully",
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

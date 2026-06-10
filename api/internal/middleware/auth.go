package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// AuthMiddleware creates authentication middleware
func AuthMiddleware(authService *service.AuthService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip if already authenticated via API token
			if c.Get("user_id") != nil {
				return next(c)
			}

			token := extractToken(c)
			if token == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Authentication required",
				})
			}

			user, err := authService.ValidateToken(c.Request().Context(), token)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Invalid or expired session",
				})
			}

			// Store user in context
			c.Set("user", user)
			c.Set("token", token)
			c.Set("user_id", user.ID)
			c.Set("username", user.Username)
			c.Set("role", user.Role)

			return next(c)
		}
	}
}

// OptionalAuthMiddleware adds user to context if authenticated, but doesn't require it
func OptionalAuthMiddleware(authService *service.AuthService) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := extractToken(c)
			if token != "" {
				user, err := authService.ValidateToken(c.Request().Context(), token)
				if err == nil && user != nil {
					c.Set("user", user)
					c.Set("token", token)
					c.Set("user_id", user.ID)
					c.Set("username", user.Username)
					c.Set("role", user.Role)
				}
			}
			return next(c)
		}
	}
}

// initialSetupAllowedPaths are the only endpoints reachable while the
// logged-in user still has is_initial_setup=true. Everything else is blocked
// server-side so the default admin/admin account cannot touch protected or
// state-changing endpoints before its credentials are changed (H1).
var initialSetupAllowedPaths = map[string]struct{}{
	// The only write the user is allowed to perform: setting real credentials.
	"/api/v1/auth/change-credentials": {},
	// Read-only auth/account context so the setup screen can render.
	"/api/v1/auth/me":     {},
	"/api/v1/auth/status": {},
	// Logout must always be reachable so the user can abandon the session.
	"/api/v1/auth/logout": {},
}

// InitialSetupRequired blocks the logged-in user from every endpoint except the
// change-credentials flow while their account is still in the initial-setup
// state (default admin/admin). This is the server-side enforcement of the gate
// that was previously client-only.
//
// It is a no-op for:
//   - API-token requests (no *model.User in context — tokens are minted by an
//     already-set-up admin, so they are never in initial-setup state), and
//   - users who have already completed setup.
func InitialSetupRequired(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Only session auth puts a *model.User in context. API-token auth sets
		// user_id/username but not "user", so this gate never affects tokens.
		user, ok := c.Get("user").(*model.User)
		if !ok || user == nil {
			return next(c)
		}

		// Setup complete: nothing to gate.
		if !user.IsInitialSetup {
			return next(c)
		}

		if _, allowed := initialSetupAllowedPaths[c.Path()]; allowed {
			return next(c)
		}

		return c.JSON(http.StatusForbidden, map[string]string{
			"error": "Initial setup required: change the default credentials before using the application",
			"code":  "initial_setup_required",
		})
	}
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

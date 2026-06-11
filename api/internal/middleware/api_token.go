package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"

	"github.com/labstack/echo/v4"
)

// Rate-limited error reporting for the per-request async usage writer. A DB
// outage would otherwise either spam one line per authenticated request or
// (as before) discard every error silently. At most one summary line per
// minute, carrying the count of failures suppressed since the last report.
var (
	asyncTokenLogMu         sync.Mutex
	asyncTokenLogLastEmit   time.Time
	asyncTokenLogSuppressed int
)

func logAsyncTokenError(what string, err error) {
	asyncTokenLogMu.Lock()
	defer asyncTokenLogMu.Unlock()
	asyncTokenLogSuppressed++
	if time.Since(asyncTokenLogLastEmit) < time.Minute {
		return
	}
	log.Printf("[APIToken] %s failed: %v (%d async write failure(s) since last report)", what, err, asyncTokenLogSuppressed)
	asyncTokenLogLastEmit = time.Now()
	asyncTokenLogSuppressed = 0
}

// APITokenAuth creates a middleware that authenticates using API tokens
// This should be used in combination with the JWT auth - API tokens are an alternative auth method
func APITokenAuth(tokenRepo *repository.APITokenRepository, auditRepo *repository.AuditLogRepository) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Check if already authenticated via JWT
			if c.Get("user_id") != nil {
				return next(c)
			}

			// Check for API token in Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return next(c) // Let JWT middleware handle it
			}

			// Check for Bearer token format
			if !strings.HasPrefix(authHeader, "Bearer ") {
				return next(c)
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")

			// API tokens start with "ng_"
			if !strings.HasPrefix(tokenString, "ng_") {
				return next(c) // Not an API token, let JWT handle it
			}

			startTime := time.Now()

			// Hash the token and look it up
			tokenHash := model.HashToken(tokenString)
			token, err := tokenRepo.GetByHash(c.Request().Context(), tokenHash)
			if err != nil {
				c.Logger().Errorf("API Token auth error: %v", err)
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "authentication error"})
			}

			if token == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid API token"})
			}

			// Check if token is valid
			if !token.IsValid() {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "token expired or revoked"})
			}

			// Check IP restriction
			clientIP := c.RealIP()
			if !token.IsIPAllowed(clientIP) {
				// Log unauthorized attempt
				auditRepo.Log(c.Request().Context(), &model.AuditLogEntry{
					UserID:     token.UserID,
					Username:   token.Username,
					Action:     "api_token_ip_denied",
					Resource:   "api_token",
					ResourceID: token.ID,
					Details: map[string]interface{}{
						"token_prefix": token.TokenPrefix,
						"client_ip":    clientIP,
						"allowed_ips":  token.AllowedIPs,
					},
					IPAddress: clientIP,
					UserAgent: c.Request().UserAgent(),
				})
				return c.JSON(http.StatusForbidden, map[string]string{"error": "IP address not allowed"})
			}

			// Set context values for handlers
			c.Set("user_id", token.UserID)
			c.Set("username", token.Username)
			c.Set("role", "api_token") // Special role for API tokens
			c.Set("api_token", token)
			c.Set("api_token_id", token.ID)
			c.Set("is_api_token", true)

			// Capture values for async logging (context may be cancelled after response)
			endpoint := c.Path()
			method := c.Request().Method
			userAgent := c.Request().UserAgent()
			contentLength := c.Request().ContentLength
			tokenID := token.ID
			tokenUserID := token.UserID
			tokenUsername := token.Username
			tokenPrefix := token.TokenPrefix

			// Execute the handler
			err = next(c)

			// Capture response status after handler execution
			statusCode := c.Response().Status
			responseTime := time.Since(startTime).Milliseconds()

			// Persist usage bookkeeping (last_used, usage row, audit entry)
			// off the request path. A single goroutine per request (was two),
			// bounded by the 5s context; errors are reported via the
			// rate-limited logger above instead of silently discarded. A
			// shared worker + buffered channel would shave the per-request
			// goroutine entirely but needs lifecycle wiring through
			// bootstrap — not warranted for three small bounded writes.
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if err := tokenRepo.UpdateLastUsed(ctx, tokenID, clientIP); err != nil {
					logAsyncTokenError("update token last_used", err)
				}

				usage := &model.APITokenUsage{
					TokenID:         tokenID,
					Endpoint:        endpoint,
					Method:          method,
					StatusCode:      statusCode,
					ClientIP:        clientIP,
					UserAgent:       userAgent,
					RequestBodySize: contentLength,
					ResponseTimeMs:  int(responseTime),
				}
				if err := tokenRepo.LogUsage(ctx, usage); err != nil {
					logAsyncTokenError("record token usage", err)
				}

				// Also log to audit log for API calls
				action := "api_call"
				if statusCode >= 400 {
					action = "api_call_error"
				}
				auditErr := auditRepo.Log(ctx, &model.AuditLogEntry{
					UserID:     tokenUserID,
					Username:   tokenUsername + " (API)",
					Action:     action,
					Resource:   endpoint,
					ResourceID: tokenID,
					Details: map[string]interface{}{
						"method":        method,
						"status_code":   statusCode,
						"token_prefix":  tokenPrefix,
						"response_time": responseTime,
					},
					IPAddress: clientIP,
					UserAgent: userAgent,
				})
				if auditErr != nil {
					logAsyncTokenError("write audit log", auditErr)
				}
			}()

			return err
		}
	}
}

// RequireAPIPermission checks if the API token has the required permission
func RequireAPIPermission(permission string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// If not using API token, skip this check (regular auth will handle it)
			isAPIToken, ok := c.Get("is_api_token").(bool)
			if !ok || !isAPIToken {
				return next(c)
			}

			token, ok := c.Get("api_token").(*model.APIToken)
			if !ok || token == nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
			}

			if !token.HasPermission(permission) {
				return c.JSON(http.StatusForbidden, map[string]string{
					"error":              "insufficient permissions",
					"required":           permission,
					"token_permissions":  strings.Join(token.Permissions, ", "),
				})
			}

			return next(c)
		}
	}
}

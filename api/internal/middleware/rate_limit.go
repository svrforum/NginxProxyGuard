package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/pkg/cache"
)

// isTestEnvironment checks if running in test/development environment
func isTestEnvironment() bool {
	env := os.Getenv("ENVIRONMENT")
	return env == "test" || env == "development" || os.Getenv("RATE_LIMIT_DISABLED") == "true"
}

// APIRateLimitConfig defines the configuration for API rate limiting
type APIRateLimitConfig struct {
	// Requests per window
	Limit int64
	// Time window
	Window time.Duration
	// Key generator function
	KeyGenerator func(c echo.Context) string
	// Skip function (optional)
	Skipper func(c echo.Context) bool
}

// DefaultAPIRateLimitConfig returns default rate limit config
func DefaultAPIRateLimitConfig() APIRateLimitConfig {
	// Use much higher limits for test/development environments
	limit := int64(100)
	if isTestEnvironment() {
		limit = 10000 // 10000 requests per minute for tests
	}

	return APIRateLimitConfig{
		Limit:  limit,
		Window: time.Minute,
		KeyGenerator: func(c echo.Context) string {
			// Default: rate limit by IP
			return c.RealIP()
		},
		Skipper: func(c echo.Context) bool {
			// Skip all rate limiting in test environment
			if isTestEnvironment() {
				return true
			}
			path := c.Path()
			// Skip health check and challenge endpoints (auth_request from nginx)
			return path == "/health" ||
				strings.HasPrefix(path, "/api/v1/challenge/")
		},
	}
}

// APIRateLimit returns a rate limiting middleware
func APIRateLimit(redisCache *cache.RedisClient, config APIRateLimitConfig) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip if skipper returns true
			if config.Skipper != nil && config.Skipper(c) {
				return next(c)
			}

			// Skip if cache is not available
			if redisCache == nil || !redisCache.IsReady() {
				return next(c)
			}

			// Generate key
			key := config.KeyGenerator(c)
			if key == "" {
				return next(c)
			}

			// Check rate limit
			result, err := redisCache.CheckAPIRateLimit(c.Request().Context(), key, config.Limit, config.Window)
			if err != nil {
				// On error, allow the request
				return next(c)
			}

			// Set rate limit headers
			c.Response().Header().Set("X-RateLimit-Limit", strconv.FormatInt(result.Limit, 10))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.FormatInt(result.Remaining, 10))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt.Unix(), 10))

			// If not allowed, return 429 Too Many Requests
			if !result.Allowed {
				c.Response().Header().Set("Retry-After", strconv.FormatInt(int64(result.RetryAfter.Seconds()), 10))
				return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
					"error":       "Rate limit exceeded",
					"retry_after": int64(result.RetryAfter.Seconds()),
				})
			}

			return next(c)
		}
	}
}

// APIRateLimitByUser creates a rate limiter keyed by user ID
func APIRateLimitByUser(redisCache *cache.RedisClient, limit int64, window time.Duration) echo.MiddlewareFunc {
	config := APIRateLimitConfig{
		Limit:  limit,
		Window: window,
		KeyGenerator: func(c echo.Context) string {
			// Get user ID from context (set by auth middleware)
			if userID := c.Get("user_id"); userID != nil {
				return fmt.Sprintf("user:%v", userID)
			}
			// Fall back to IP
			return fmt.Sprintf("ip:%s", c.RealIP())
		},
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/health"
		},
	}
	return APIRateLimit(redisCache, config)
}

// APIRateLimitByToken creates a rate limiter keyed by API token
func APIRateLimitByToken(redisCache *cache.RedisClient, limit int64, window time.Duration) echo.MiddlewareFunc {
	config := APIRateLimitConfig{
		Limit:  limit,
		Window: window,
		KeyGenerator: func(c echo.Context) string {
			// Get token ID from context (set by auth middleware)
			if tokenID := c.Get("api_token_id"); tokenID != nil {
				return fmt.Sprintf("token:%v", tokenID)
			}
			// Fall back to IP
			return fmt.Sprintf("ip:%s", c.RealIP())
		},
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/health"
		},
	}
	return APIRateLimit(redisCache, config)
}

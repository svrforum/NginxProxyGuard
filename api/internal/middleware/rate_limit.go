package middleware

import (
	"fmt"
	"log"
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

const (
	// DefaultAPIRateLimit is the per-IP, per-minute budget for the general
	// /api/v1 surface.
	//
	// It used to be 100 for everything under /api/v1, which the admin panel
	// exhausts by itself: the proxy host list fires one upstream probe per row
	// and roughly thirty screens poll on 15-120s timers. An operator with a few
	// dozen hosts spent the budget just by opening the panel — and because
	// /auth/login shared it, the next thing they saw was "Rate limit exceeded"
	// on the login screen with no way back in (#258).
	DefaultAPIRateLimit = 600

	// DefaultAuthRateLimit is the budget for the unauthenticated auth
	// endpoints. They get their own bucket so panel traffic can never lock an
	// operator out of signing in, and so this stays a real brake on credential
	// stuffing even when the general limit is raised or turned off.
	DefaultAuthRateLimit = 100
)

// publicAuthPaths are the unauthenticated auth routes, by their Echo route
// pattern. They are exactly the routes registered on the auth group in
// bootstrap/routes.go — the group the auth limiter is attached to — and the
// general limiter skips exactly this set, nothing wider. The first version
// skipped the whole /api/v1/auth/ PREFIX, which also covered twelve
// session-protected routes living on other groups (change-password, 2fa/*,
// /auth/me, ...): those ended up in neither bucket, unmetered. A path prefix is
// not a group. bootstrap's TestRateLimiterBucketAssignment keeps this list and
// the route table from drifting apart.
var publicAuthPaths = map[string]struct{}{
	"/api/v1/auth/login":              {},
	"/api/v1/auth/logout":             {},
	"/api/v1/auth/status":             {},
	"/api/v1/auth/verify-2fa":         {},
	"/api/v1/auth/sso/providers":      {},
	"/api/v1/auth/sso/:slug/start":    {},
	"/api/v1/auth/sso/:slug/callback": {},
}

// IsPublicAuthPath reports whether an Echo route pattern belongs to the
// unauthenticated auth surface covered by AuthAPIRateLimitConfig.
func IsPublicAuthPath(path string) bool {
	_, ok := publicAuthPaths[path]
	return ok
}

// PublicAuthPathList returns the patterns in publicAuthPaths, for the bootstrap
// test that checks each one is still a registered route.
func PublicAuthPathList() []string {
	out := make([]string, 0, len(publicAuthPaths))
	for p := range publicAuthPaths {
		out = append(out, p)
	}
	return out
}

// rateLimitFromEnv reads a per-minute budget from the environment. A value of 0
// disables that limiter; anything unparseable falls back to the default and is
// reported, since silently ignoring the setting is how an operator ends up
// believing a limit is off when it is not.
func rateLimitFromEnv(name string, fallback int64) int64 {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || parsed < 0 {
		log.Printf("[RateLimit] Warning: invalid %s %q, using %d", name, raw, fallback)
		return fallback
	}
	return parsed
}

// DefaultAPIRateLimitConfig returns the config for the general /api/v1 surface.
// The auth endpoints are excluded here and limited separately.
func DefaultAPIRateLimitConfig() APIRateLimitConfig {
	// Use much higher limits for test/development environments
	limit := rateLimitFromEnv("API_RATE_LIMIT_PER_MINUTE", DefaultAPIRateLimit)
	if isTestEnvironment() {
		limit = 10000 // 10000 requests per minute for tests
	}

	return APIRateLimitConfig{
		Limit:  limit,
		Window: time.Minute,
		KeyGenerator: func(c echo.Context) string {
			// Default: rate limit by IP. The prefix keeps this bucket separate
			// from the auth one below — they must not share a counter.
			return "api:" + c.RealIP()
		},
		Skipper: func(c echo.Context) bool {
			// Skip all rate limiting in test environment
			if isTestEnvironment() {
				return true
			}
			path := c.Path()
			// Skip health check and challenge endpoints (auth_request from nginx),
			// and the public auth routes AuthAPIRateLimitConfig covers. The
			// session-protected /auth/* routes are NOT skipped — they live on
			// other route groups and this bucket is the only one metering them.
			return path == "/health" ||
				strings.HasPrefix(path, "/api/v1/challenge/") ||
				IsPublicAuthPath(path)
		},
	}
}

// AuthAPIRateLimitConfig returns the config for the unauthenticated auth
// endpoints (/api/v1/auth/*). Separate bucket, separate budget.
func AuthAPIRateLimitConfig() APIRateLimitConfig {
	limit := rateLimitFromEnv("AUTH_RATE_LIMIT_PER_MINUTE", DefaultAuthRateLimit)
	if isTestEnvironment() {
		limit = 10000
	}

	return APIRateLimitConfig{
		Limit:  limit,
		Window: time.Minute,
		KeyGenerator: func(c echo.Context) string {
			return "auth:" + c.RealIP()
		},
		Skipper: func(c echo.Context) bool {
			return isTestEnvironment()
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

			// A limit of 0 turns this limiter off (API_RATE_LIMIT_PER_MINUTE=0).
			if config.Limit <= 0 {
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
				// Name the limiter. A bare "Rate limit exceeded" is
				// indistinguishable from an nginx limit_req block, which sent
				// #258 looking at the Global Rate Limit settings for two rounds.
				return c.JSON(http.StatusTooManyRequests, map[string]interface{}{
					"error":       "Rate limit exceeded",
					"code":        "api_rate_limit",
					"detail":      "This is the NPG API's own per-IP limit, not a proxy host rate limit.",
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

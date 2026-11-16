package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/pkg/cache"
)

// ctxForPath builds a context whose route pattern is path, which is what the
// skippers inspect (echo.Context.Path returns the registered pattern).
func ctxForPath(t *testing.T, path string) echo.Context {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.10:54321"
	c := e.NewContext(req, httptest.NewRecorder())
	c.SetPath(path)
	return c
}

// Issue #258: /api/v1/auth/* must be excluded from the general budget, because
// it is covered by its own stricter limiter. If it stayed in both, the panel
// could still spend the login budget and the split would buy nothing.
func TestDefaultAPIRateLimitConfig_SkipsAuthAndInfraPaths(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("RATE_LIMIT_DISABLED", "")
	cfg := DefaultAPIRateLimitConfig()

	skipped := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/status",
		"/api/v1/auth/sso/providers",
		"/api/v1/challenge/validate",
		"/health",
	}
	for _, path := range skipped {
		if !cfg.Skipper(ctxForPath(t, path)) {
			t.Errorf("general limiter must skip %s", path)
		}
	}

	counted := []string{
		"/api/v1/proxy-hosts",
		"/api/v1/test/proxy-host/:id",
		"/api/v1/public/ui-settings",
		// Session-protected /auth/* routes live on other route groups, so this
		// bucket is the only one metering them. Skipping the whole /auth prefix
		// left them unmetered — brute-forceable 2FA disable, unmetered DB
		// lookups on /auth/me (caught by the first adversarial review).
		"/api/v1/auth/me",
		"/api/v1/auth/change-password",
		"/api/v1/auth/2fa/disable",
	}
	for _, path := range counted {
		if cfg.Skipper(ctxForPath(t, path)) {
			t.Errorf("general limiter must count %s", path)
		}
	}
}

// The auth limiter is the one that must actually see the login endpoints.
func TestAuthAPIRateLimitConfig_CountsAuthPaths(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("RATE_LIMIT_DISABLED", "")
	cfg := AuthAPIRateLimitConfig()

	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/sso/providers"} {
		if cfg.Skipper(ctxForPath(t, path)) {
			t.Errorf("auth limiter must count %s", path)
		}
	}
	if cfg.Limit != DefaultAuthRateLimit {
		t.Errorf("auth limit = %d, want %d", cfg.Limit, DefaultAuthRateLimit)
	}
}

// Two limiters sharing one Redis key would defeat the whole point of splitting
// them: panel traffic would still drain the login budget.
func TestRateLimitBucketsDoNotShareAKey(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("RATE_LIMIT_DISABLED", "")
	c := ctxForPath(t, "/api/v1/auth/login")

	general := DefaultAPIRateLimitConfig().KeyGenerator(c)
	auth := AuthAPIRateLimitConfig().KeyGenerator(c)

	if general == auth {
		t.Fatalf("general and auth buckets share the key %q for the same client", general)
	}
	if general == "" || auth == "" {
		t.Fatalf("empty key disables the limiter silently: general=%q auth=%q", general, auth)
	}
}

func TestRateLimitFromEnv(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  int64
	}{
		{"unset falls back", "", 600},
		{"explicit value", "1200", 1200},
		{"zero disables", "0", 0},
		{"whitespace tolerated", " 250 ", 250},
		{"garbage falls back", "lots", 600},
		{"negative falls back", "-5", 600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("API_RATE_LIMIT_PER_MINUTE", tc.value)
			if got := rateLimitFromEnv("API_RATE_LIMIT_PER_MINUTE", 600); got != tc.want {
				t.Errorf("rateLimitFromEnv(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

// Without Valkey the in-process cache counts, so the limiter (and the login
// brake built on it) still answers 429 instead of switching itself off.
func TestAPIRateLimitWorksWithoutRedis(t *testing.T) {
	rc, err := cache.NewRedisClient("", cache.NewLocalCache(4<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	mw := APIRateLimit(rc, APIRateLimitConfig{
		Limit:        2,
		Window:       time.Minute,
		KeyGenerator: func(c echo.Context) string { return "auth:" + c.RealIP() },
	})
	h := mw(func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	e := echo.New()

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
		req.RemoteAddr = "198.51.100.7:40000"
		rec := httptest.NewRecorder()
		if err := h(e.NewContext(req, rec)); err != nil {
			t.Fatal(err)
		}
		codes = append(codes, rec.Code)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusOK || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("status codes = %v, want [200 200 429]", codes)
	}
}

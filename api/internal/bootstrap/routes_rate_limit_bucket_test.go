package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/middleware"
)

// Every /api/v1 route must be metered by exactly one rate-limit bucket. The
// first version of the #258 fix skipped the whole /api/v1/auth/ PREFIX in the
// general limiter on the assumption that the auth bucket covered it — but the
// auth bucket is attached to a route GROUP, and twelve session-protected
// /auth/* routes live on other groups. Those routes ended up in neither bucket:
// unauthenticated callers could hammer /auth/me (a DB lookup per request) and a
// hijacked session could brute-force /auth/2fa/disable with no API-level meter.
// A path prefix is not a group; this test is what keeps the skip list and the
// route table from drifting apart again.
func TestRateLimiterBucketAssignment(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("RATE_LIMIT_DISABLED", "")

	e := registerAllRoutesForAudit(t)
	skipper := middleware.DefaultAPIRateLimitConfig().Skipper

	ctxFor := func(path string) echo.Context {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		c := e.NewContext(req, httptest.NewRecorder())
		c.SetPath(path)
		return c
	}

	registered := make(map[string]bool)
	var escaped []string
	for _, r := range e.Routes() {
		if isEchoCatchAll(r) {
			continue
		}
		registered[r.Path] = true
		if !strings.HasPrefix(r.Path, "/api/v1/") {
			continue
		}
		if !skipper(ctxFor(r.Path)) {
			continue // metered by the general bucket
		}
		// The general bucket skips it — something else must cover it: the
		// challenge endpoints (hit by nginx auth_request on every visitor
		// request, deliberately unmetered) or the auth bucket.
		if strings.HasPrefix(r.Path, "/api/v1/challenge/") {
			continue
		}
		if middleware.IsPublicAuthPath(r.Path) {
			continue
		}
		escaped = append(escaped, r.Method+" "+r.Path)
	}
	sort.Strings(escaped)
	if len(escaped) > 0 {
		t.Errorf("%d route(s) escape both rate-limit buckets — either register them on the "+
			"auth group and add them to middleware.publicAuthPaths, or stop skipping them "+
			"in DefaultAPIRateLimitConfig:\n%s", len(escaped), strings.Join(escaped, "\n"))
	}

	// The reverse direction: a stale entry in publicAuthPaths means a route was
	// renamed or moved off the auth group, and the skip would outlive the bucket
	// that justified it.
	var stale []string
	for _, p := range middleware.PublicAuthPathList() {
		if !registered[p] {
			stale = append(stale, p)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d entr(y/ies) in middleware.publicAuthPaths match no registered route:\n%s",
			len(stale), strings.Join(stale, "\n"))
	}
}

// nginx's geo-challenge gate calls the token check once for every request a
// challenged visitor with a token makes, from nginx's own address. Behind the
// global per-address limit all those visitors shared one bucket, and the gate
// turned visitors with valid tokens away on its 429. The token check is
// exempt; every other route stays limited.
func TestGlobalRateLimitSkipsOnlyTheChallengeTokenCheck(t *testing.T) {
	const validate = "/api/v1/challenge/validate" // what the nginx gate proxies to
	t.Setenv("RATE_LIMIT_ENABLED", "")
	t.Setenv("RATE_LIMIT_RPS", "1")
	e := echo.New()
	RegisterMiddleware(e, &config.Config{})
	ok := func(c echo.Context) error { return c.NoContent(http.StatusOK) }
	e.GET(validate, ok)
	e.GET("/api/v1/challenge/page", ok)
	status := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:40000" // every gate call comes from nginx
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 1; i <= 20; i++ {
		if got := status(validate); got != http.StatusOK {
			t.Fatalf("token check call %d answered %d, want 200: it must not be rate limited", i, got)
		}
	}
	limited := 0
	for i := 0; i < 20; i++ {
		if status("/api/v1/challenge/page") == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("other routes are no longer rate limited")
	}

	for _, r := range registerAllRoutesForAudit(t).Routes() {
		if r.Method == http.MethodGet && r.Path == validate {
			return
		}
	}
	t.Fatalf("GET %s is not a registered route, but the nginx gate calls it and the limiter exempts it", validate)
}

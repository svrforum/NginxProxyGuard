# Issue #129 — Force HTTPS + Custom Nginx Config Fix — Design

**Date:** 2026-04-27
**GitHub Issue:** [svrforum/nginxproxyguard#129](https://github.com/svrforum/nginxproxyguard/issues/129)
**Reporter:** @ydrob
**Severity:** Functional bug — silently breaks Force HTTPS for users with custom `location /` in Advanced Config

---

## 1. Problem Statement

Users who add Custom Nginx Configuration containing a `location / { ... }` block to a proxy host with `Force HTTPS` enabled experience their HTTP traffic being served as plain HTTP rather than redirected to HTTPS. The Force HTTPS toggle silently no-ops.

User-supplied workaround:
```nginx
if ($scheme = http) {
    return 301 https://$host$request_uri;
}
```
This restores the redirect, but the user notes (correctly) that the platform should handle this at a higher level.

### Root Cause

`api/internal/nginx/templates/proxy_host/waf.conf.tmpl:1-12` renders the HTTP→HTTPS redirect as a `location /` block:

```nginx
{{if .Host.SSLEnabled}}{{if .Host.SSLForceHTTPS}}
{{if not .HasCustomLocationRoot}}
    location / {
        return 301 https://$host$request_uri;
    }
{{end}}
...
```

`api/internal/nginx/manager.go:498-501` detects whether the user's Advanced Config contains a `location /` block:
```go
if data.Host.AdvancedConfig != "" {
    locationPattern := regexp.MustCompile(`(?m)^\s*location\s+/\s*\{`)
    data.HasCustomLocationRoot = locationPattern.MatchString(data.Host.AdvancedConfig)
```

When `HasCustomLocationRoot=true`, the redirect block is **omitted entirely** to avoid an nginx duplicate-location error. The user's custom `location /` then handles all HTTP traffic in plain text — Force HTTPS is broken.

### Why the User's Workaround Hides a Latent Bug

The workaround uses a server-block-level `if` that runs in nginx's rewrite phase, before location selection. This bypasses the user's custom `location /` correctly — but it **also bypasses** the `location /.well-known/acme-challenge/` handler defined in `base.conf.tmpl:47`. As a result, Let's Encrypt HTTP-01 challenge requests get redirected to HTTPS and SSL auto-renewal silently fails. The user has not yet noticed because cert renewal runs only every ~60 days.

---

## 2. Goals

1. Force HTTPS works correctly regardless of whether the user has defined `location /` in their Advanced Config.
2. ACME HTTP-01 challenge path (`/.well-known/acme-challenge/`) continues to be served over HTTP, preserving SSL auto-renewal.
3. NPG's own challenge page path (`/api/v1/challenge/`, used in geo-restriction challenge mode) is also bypassed for safety.
4. No regression for users without custom Advanced Config — current redirect behavior is functionally identical from the client's perspective.
5. Test coverage prevents future regressions of both the original bug and the ACME path bypass.

---

## 3. Non-Goals

- Fixing `HasCustomLocationRoot` detection for `location = /` (exact-match) syntax — separate latent issue, not blocking #129.
- Reworking `AdvancedConfigLocationLevel` injection in non-ForceHTTPS branches — out of scope.
- Touching `redirect_hosts` — they have no AdvancedConfig field and are unaffected.
- Touching the HTTPS server (`cache.conf.tmpl`) `HasCustomLocationRoot` handling — that path is correct and serves a different purpose (allowing the user's `location /` to take over upstream proxying for HTTPS).

---

## 4. Design

### 4.1 Template Change

**File:** `api/internal/nginx/templates/proxy_host/waf.conf.tmpl`

**Before (lines 1-12):**
```
{{if .Host.SSLEnabled}}
    # Redirect HTTP to HTTPS
    {{if .Host.SSLForceHTTPS}}
{{if not .HasCustomLocationRoot}}
    location / {
        return 301 https://$host$request_uri;
    }
{{end}}
{{if .AdvancedConfigLocationLevel}}{{if not .AdvancedConfigHasLocation}}
    # Advanced configuration (ForceHTTPS redirect server)
    {{.AdvancedConfigLocationLevel}}
{{end}}{{end}}
    {{else}}
```

**After:**
```
{{if .Host.SSLEnabled}}
    # Redirect HTTP to HTTPS
    {{if .Host.SSLForceHTTPS}}
    # Server-level redirect — survives any user-defined location block.
    # Bypass: ACME HTTP-01 (cert renewal) + NPG challenge page (geo restriction).
    if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/") {
        return 301 https://$host$request_uri;
    }
    {{else}}
```

**Removed:**
- The `{{if not .HasCustomLocationRoot}} ... location / { return 301 } ... {{end}}` branch.
- The `AdvancedConfigLocationLevel` injection within this branch (dead code in a redirect-only server with no `proxy_pass`).

**Preserved (no change):**
- `manager.go:498-501` `HasCustomLocationRoot` detection logic — still required for `cache.conf.tmpl:293` (HTTPS server location handling).
- `base.conf.tmpl:47` ACME challenge `location` block — still serves HTTP-01 validation files; the server-level `if` falls through when the URI matches the bypass regex.
- All non-ForceHTTPS branches in `waf.conf.tmpl` (i.e., the `{{else}}` blocks for SSL-without-Force-HTTPS and non-SSL).
- `AdvancedConfig` server-level injection at `waf.conf.tmpl:279-282` (separate from the ForceHTTPS branch; user's full advanced config still rendered into the HTTP server block when applicable).

### 4.2 Behavioral Matrix

| Scenario | Request | Expected response |
|----------|---------|-------------------|
| Force HTTPS, no custom location | `GET http://host/foo` | 301 → `https://host/foo` |
| Force HTTPS, no custom location | `GET http://host/.well-known/acme-challenge/abc` | 200 (ACME file) or 404 (no file) — **not** 301 |
| Force HTTPS, custom `location /` (issue #129) | `GET http://host/foo` | 301 → `https://host/foo` ✅ (currently: plain HTTP — buggy) |
| Force HTTPS, custom `location /` | `GET http://host/.well-known/acme-challenge/abc` | 200 / 404 — **not** 301 |
| Force HTTPS, custom location, GeoChallenge enabled | `GET http://host/api/v1/challenge/page?...` | 200 (challenge page) — **not** 301 |
| Force HTTPS=false, SSL enabled | `GET http://host/foo` | User's `location /` → upstream (no change) |
| User retains workaround `if ($scheme=http) { return 301 }` in Advanced Config | Any non-bypass request | Two server-level `if` blocks both yield 301 — functionally identical, redundant config |

### 4.3 nginx Semantics Notes

- `if` directives at server context are evaluated during the rewrite phase, before location selection.
- The bypass regex uses negative match (`!~`); when a request URI matches the bypass list, the `if` block is skipped entirely and the `return 301` is **not** executed. The request then proceeds to normal location matching, where the more specific `location /.well-known/acme-challenge/` (or `/api/v1/challenge/` when present) takes precedence.
- This is a "safe use of `if`" per nginx documentation: the `if` block contains only a single `return` directive and no other rewrite-phase operations.

---

## 5. Backward Compatibility

**All existing users will see their rendered nginx config change** on the next regenerate, even those without custom Advanced Config:

- Before: `location / { return 301 https://$host$request_uri; }`
- After: `if ($request_uri !~ "...") { return 301 https://$host$request_uri; }`

Functionally equivalent for non-custom users; only the rendered text differs.

**Rollout path:**
1. On API restart after upgrade, `bootstrap.SyncAllConfigs` regenerates every host's nginx config.
2. `nginx -t` validates the new config; on success, atomic reload via `nginx -s reload`.
3. On `nginx -t` failure (unlikely — change is minimal), manager's existing rollback path restores the previous config.

**No DB migration required.** Pure template/code change.

**Rollback:** `git revert` is sufficient. Next config regeneration restores the prior `location /` form.

---

## 6. Test Plan

### 6.1 Unit Tests (Go, golden file pattern)

**Location:** `api/internal/nginx/manager_test.go` (or the established golden-file test location for proxy host configs). Existing fixtures are in `api/internal/nginx/testdata/golden/`.

**Existing golden files affected:** Any fixture whose source `ProxyHost` has `SSLForceHTTPS=true` will need its expected output updated. Exact files to identify in plan stage via `grep` over fixture source data.

**New cases:**
1. **`TestForceHTTPSWithCustomLocationRoot`**
   Input: `ProxyHost{SSLEnabled:true, SSLForceHTTPS:true, AdvancedConfig:"location / { proxy_pass http://backend; }"}`
   Assertions on rendered config:
   - Contains server-level `if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/")`.
   - Contains `return 301 https://$host$request_uri;` inside that if.
   - Contains the user's `location / { proxy_pass http://backend; }` (rendered via the standard advanced config inject).
   - **Does not** contain an auto-generated `location / { return 301 ... }` block.

2. **`TestForceHTTPSWithoutCustomLocation`**
   Input: `ProxyHost{SSLEnabled:true, SSLForceHTTPS:true, AdvancedConfig:""}`
   Assertions: same `if` + `return 301` present; no `location /` block in the HTTP server portion of the output.

3. **`TestForceHTTPSACMEBypassPattern`**
   Input: same as case 2.
   Assertion: the bypass regex `^/\.well-known/acme-challenge/|^/api/v1/challenge/` appears exactly once at server context in the HTTP server block.

### 6.2 E2E Tests (Playwright)

**Location:** `test/e2e/specs/proxy/force-https-custom-config.spec.ts` (new file).

**Setup (beforeAll):**
- Create a proxy host via API helper:
  ```ts
  hostId = await createTestProxyHost(request, {
    domain: 'e2e-issue129.test.local',
    forward_host: 'httpbin-mock',
    forward_port: 80,
    ssl_enabled: true,
    ssl_force_https: true,
    advanced_config: 'location / { proxy_pass http://httpbin-mock:80; }',
  });
  ```
- Wait for nginx config regeneration (existing helper / poll).

**Test cases:**
1. `'HTTP request redirects to HTTPS (issue #129 main case)'`
   `request.get('http://e2e-issue129.test.local/anything', { maxRedirects: 0, ignoreHTTPSErrors: true })`
   Assert: status === 301; `location` header starts with `https://`.

2. `'ACME challenge path is NOT redirected (regression guard for SSL renewal)'`
   `request.get('http://e2e-issue129.test.local/.well-known/acme-challenge/test', { maxRedirects: 0, ignoreHTTPSErrors: true })`
   Assert: status !== 301 (expected 404 since no ACME file exists, but the key assertion is absence of redirect).

3. `'NPG challenge path is NOT redirected'`
   `request.get('http://e2e-issue129.test.local/api/v1/challenge/test', { maxRedirects: 0, ignoreHTTPSErrors: true })`
   Assert: status !== 301.

4. `'HTTPS request reaches the user-configured location'`
   `request.get('https://e2e-issue129.test.local/anything', { ignoreHTTPSErrors: true })`
   Assert: status === 200; body matches httpbin-mock signature (e.g., contains `"url"` JSON field).

5. `'(Regression) Force HTTPS without custom config still redirects'`
   Create a second host without `advanced_config`; HTTP request → 301.

**Cleanup (afterAll):** `deleteTestProxyHost(request, hostId)` for each created host.

---

## 7. Versioning & Release

- `api/internal/config/constants.go`: `AppVersion = "2.13.7"` → `"2.13.8"`
- `ui/package.json`: `"version": "2.13.7"` → `"2.13.8"`
- Patch level — bug fix, no schema or feature change.

---

## 8. Documentation Updates

- **`ARCHITECTURE.md`**: Optional minor note in the nginx template section — "HTTP→HTTPS redirect is implemented as a server-level `if` so user-defined `location /` blocks in Advanced Config do not break Force HTTPS." Skip if it adds noise; the architectural shape is unchanged.
- **GitHub Issue #129**: Post a comment after release describing the root cause, the fix, and a recommendation to remove the `if ($scheme = http) { return 301; }` workaround from any user's Advanced Config (it is no longer needed and slightly redundant). Close the issue.

---

## 9. Edge Cases

**Handled / non-issues:**
- Malformed Advanced Config — unchanged behavior; manager's `nginx -t` + atomic write + rollback already covers this.
- WebSocket upgrade attempted over HTTP — receives 301; client follows to HTTPS and re-handshakes (standard).
- IPv6 / various clients — redirect logic is protocol-agnostic.
- ACME bypass regex `^/\.well-known/acme-challenge/` — RFC 8555 mandates the trailing slash; production ACME clients always use it.
- User keeps the workaround `if ($scheme=http) { return 301; }` in their Advanced Config — coexists with our `if` in the same server block; both produce the same 301; functionally fine, slightly redundant. The release note will recommend removal.

**Known limitations (out of scope, separate follow-up candidates):**
- `HasCustomLocationRoot` regex (`manager.go:500`) does not match `location = /` (exact-match) syntax. With this fix in place, that limitation does **not** affect Force HTTPS at all; it only affects the HTTPS server's `cache.conf.tmpl` handling. Tracked as a separate latent issue.

---

## 10. Risk Assessment

**Risk: Low–Medium.**

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Golden file tests fail on CI | High (expected) | Update fixtures as part of the PR — explicit, intentional |
| `nginx -t` rejects new config syntax | Very Low (standard nginx idiom) | Existing manager rollback restores prior config |
| ACME renewal regression | Very Low | Explicit bypass regex + dedicated E2E test guards this |
| User's workaround creates unintended interaction | Low | Both `if` blocks issue identical 301; release note advises removal |
| Hidden dependency on `AdvancedConfigLocationLevel` rendering in ForceHTTPS branch | Very Low | This rendering is dead code in a redirect-only server (no `proxy_pass` to apply directives to); E2E tests catch any real-world breakage |

---

## 11. Implementation Sequence (handed off to writing-plans)

1. Add failing unit tests (TDD). Verify they fail against current code.
2. Add failing E2E test. Verify it fails against current code.
3. Apply template change to `waf.conf.tmpl`.
4. Update affected golden files in `api/internal/nginx/testdata/golden/`.
5. Run unit + E2E suites — confirm green.
6. Bump version (constants.go + package.json).
7. Build dev images, smoke-test in `docker-compose.dev.yml`.
8. Build E2E images, run full E2E suite for regression guard.
9. (Optional) Minor `ARCHITECTURE.md` note.
10. Commit per logical step (test, fix, e2e, release).
11. Open PR; on merge, post comment to issue #129 and close.

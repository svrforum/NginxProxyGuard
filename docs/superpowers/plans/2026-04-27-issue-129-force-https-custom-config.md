# Issue #129 — Force HTTPS + Custom Nginx Config Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix GitHub issue #129 where `Force HTTPS` silently no-ops when the user adds `location / { ... }` to Advanced Config, while preserving Let's Encrypt ACME HTTP-01 cert renewal.

**Architecture:** Replace the location-based HTTP→HTTPS redirect (`location / { return 301 ...; }`) in the proxy host's HTTP server with a server-block-level `if` that excludes ACME and NPG challenge paths via negative regex. This survives any user-defined `location /` because nginx evaluates server-level `if` during the rewrite phase before location matching, and the negative regex falls through (no `return` executed) for bypass paths so the more specific `location /.well-known/acme-challenge/` handler still runs.

**Tech Stack:** Go 1.24 (template engine + characterization tests with `-update-golden`), nginx 1.28 templates (`embed.FS`), Playwright TypeScript for E2E, Docker Compose for E2E environment.

**Spec reference:** `docs/superpowers/specs/2026-04-27-issue-129-force-https-custom-config-design.md`

---

## Phase 1 — Unit Tests + Template Fix (TDD)

### Task 1.1: Add behavioral assertion test for the redirect (failing first)

**Files:**
- Modify: `api/internal/nginx/proxy_host_template_characterization_test.go` (append new test function and helper fixture below the existing characterization test)

This is a behavioral assertion test (not a golden-file compare) so the failure mode is unambiguous: the test asserts specific strings in the rendered nginx config, not the entire byte-for-byte output.

- [ ] **Step 1: Add a new fixture function `fixtureHTTPSForceCustomLocation` near the existing fixture functions (after `fixtureUpstreamLB` around line 208)**

```go
// 7) https_force_custom_location: SSL+ForceHTTPS with user-supplied
// `location / { ... }` in AdvancedConfig. This pins the issue #129 fix —
// the HTTP→HTTPS redirect must happen at server-block level so the user's
// location does not shadow it, and ACME / NPG challenge paths must be
// excluded from the redirect.
func fixtureHTTPSForceCustomLocation() ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-000000000007", "192.168.1.70", true)
	host.DomainNames = []string{"custom.example.com"}
	host.SSLEnabled = true
	host.SSLForceHTTPS = true
	certID := "00000000-0000-0000-0000-00000000cert"
	host.CertificateID = &certID
	host.AdvancedConfig = "location / {\n    proxy_pass http://192.168.1.70:8080;\n}\n"
	return ProxyHostConfigData{
		Host:           host,
		GlobalSettings: baseGlobalSettings(),
	}
}
```

- [ ] **Step 2: Add a new behavioral test function `TestForceHTTPSCustomLocationRedirects` at the end of the file (after `itoa`)**

```go
// TestForceHTTPSCustomLocationRedirects pins issue #129: when SSLForceHTTPS
// is on and the user supplies their own `location /`, the HTTP→HTTPS
// redirect must still fire and ACME/NPG-challenge paths must be excluded.
//
// This is an assertion test (not a golden compare) because the bug is about
// specific directives appearing/missing, and a golden file would obscure the
// signal with noise from unrelated parts of the config.
func TestForceHTTPSCustomLocationRedirects(t *testing.T) {
	var buf bytes.Buffer
	if err := renderProxyHostConfig(context.Background(), &buf, fixtureHTTPSForceCustomLocation()); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	out := buf.String()

	// Split on the HTTPS server block so we only look at the HTTP server.
	// The first `server {` … first `}` (top-level) covers the HTTP server.
	httpServer := extractFirstServerBlock(t, out)

	// Server-level if with ACME + NPG challenge bypass must be present.
	if !strings.Contains(httpServer, `if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/")`) {
		t.Errorf("HTTP server is missing the server-level bypass `if`; got:\n%s", httpServer)
	}

	// Redirect must be present.
	if !strings.Contains(httpServer, "return 301 https://$host$request_uri;") {
		t.Errorf("HTTP server is missing the 301 redirect; got:\n%s", httpServer)
	}

	// The OLD pattern — auto-generated `location / { return 301 ... }` —
	// must NOT appear; only the user's `location /` should be present in
	// the HTTP server (rendered via the standard advanced-config inject).
	if strings.Contains(httpServer, "location / {\n        return 301") {
		t.Errorf("HTTP server still contains the old auto-generated location/return block; should be replaced by server-level if. Got:\n%s", httpServer)
	}

	// User's location block (proxy_pass) is rendered into HTTP server too —
	// dead code at runtime (server-level return short-circuits non-bypass
	// requests) but expected as part of the AdvancedConfig server-level inject.
	if !strings.Contains(httpServer, "proxy_pass http://192.168.1.70:8080") {
		t.Errorf("HTTP server is missing user's proxy_pass directive; got:\n%s", httpServer)
	}
}

// extractFirstServerBlock returns the substring covering the FIRST top-level
// `server { … }` block in the config (which is the HTTP server in our
// template). Uses brace counting because nginx server bodies contain nested
// `{}` (location blocks, if-blocks).
func extractFirstServerBlock(t *testing.T, full string) string {
	t.Helper()
	start := strings.Index(full, "server {")
	if start < 0 {
		t.Fatalf("no `server {` block found in rendered config")
	}
	depth := 0
	for i := start; i < len(full); i++ {
		switch full[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return full[start : i+1]
			}
		}
	}
	t.Fatalf("unterminated server block starting at offset %d", start)
	return ""
}
```

- [ ] **Step 3: Run the new test to confirm it fails on the current (buggy) template**

Run from the project root:
```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ -run TestForceHTTPSCustomLocationRedirects -v
```

Expected output: FAIL. The current template either:
- Omits the entire location/return block when `HasCustomLocationRoot=true` → "missing the 301 redirect" assertion fails, OR
- Has neither the new server-level `if` nor the bypass regex → both bypass-related assertions fail.

> If running Go directly outside Docker is preferred and works (`cd api && go test ...`), use that. The Docker form above is portable.

- [ ] **Step 4: Commit the failing test on its own**

```bash
git add api/internal/nginx/proxy_host_template_characterization_test.go
git commit -m "test(nginx): add failing assertion for force_https + custom location (#129)"
```

This commit MUST be a failing-test commit — that is the TDD record of the bug.

---

### Task 1.2: Add ACME-bypass regression assertion test (also failing first)

**Files:**
- Modify: `api/internal/nginx/proxy_host_template_characterization_test.go` (append second test function)

This complements Task 1.1 by also catching the case where someone in the future tightens or removes the ACME bypass and breaks SSL renewal.

- [ ] **Step 1: Append the new test function**

```go
// TestForceHTTPSACMEBypass guards against silent regression of
// Let's Encrypt HTTP-01 cert renewal. The server-level redirect MUST
// exclude `^/.well-known/acme-challenge/` from being redirected to HTTPS,
// otherwise the ACME server cannot fetch the validation file over HTTP and
// renewal silently fails.
func TestForceHTTPSACMEBypass(t *testing.T) {
	// Use the no-custom-location fixture too, so we cover both paths.
	cases := []struct {
		name string
		data ProxyHostConfigData
	}{
		{name: "without_custom_location", data: fixtureHTTPSForce()},
		{name: "with_custom_location", data: fixtureHTTPSForceCustomLocation()},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderProxyHostConfig(context.Background(), &buf, tc.data); err != nil {
				t.Fatalf("render failed: %v", err)
			}
			httpServer := extractFirstServerBlock(t, buf.String())

			// The bypass regex must contain BOTH ACME and NPG challenge prefixes.
			needles := []string{
				`^/\.well-known/acme-challenge/`,
				`^/api/v1/challenge/`,
			}
			for _, n := range needles {
				if !strings.Contains(httpServer, n) {
					t.Errorf("HTTP server is missing bypass needle %q; got:\n%s", n, httpServer)
				}
			}

			// Sanity: the if must use negative match (`!~`) so non-matching
			// URIs trigger the redirect and matching ones fall through.
			if !strings.Contains(httpServer, `if ($request_uri !~`) {
				t.Errorf("HTTP server is missing `if ($request_uri !~ ...)` bypass; got:\n%s", httpServer)
			}
		})
	}
}
```

- [ ] **Step 2: Run the new test — confirm it fails on the current code**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ -run TestForceHTTPSACMEBypass -v
```

Expected: FAIL on both subtests — the current template has neither the bypass regex nor the `if` form.

- [ ] **Step 3: Commit**

```bash
git add api/internal/nginx/proxy_host_template_characterization_test.go
git commit -m "test(nginx): add failing assertion for ACME bypass regression guard (#129)"
```

---

### Task 1.3: Apply the template fix

**Files:**
- Modify: `api/internal/nginx/templates/proxy_host/waf.conf.tmpl:1-12`

- [ ] **Step 1: Replace the Force HTTPS redirect branch**

Open `api/internal/nginx/templates/proxy_host/waf.conf.tmpl`. Lines 1-12 currently look like:

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

Replace with:

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

> Indentation: keep four spaces (not a tab) on every line inside the new `if` body to match the surrounding template style.

- [ ] **Step 2: Run the two failing tests — both should now pass**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ \
  -run 'TestForceHTTPSCustomLocationRedirects|TestForceHTTPSACMEBypass' -v
```

Expected: PASS on all subtests.

- [ ] **Step 3: Run the full characterization suite — `https_force` golden will mismatch**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ \
  -run TestProxyHostTemplate_Characterization -v
```

Expected: `https_force` subtest FAILS (golden mismatch — the rendered redirect changed from `location /` block to `if`). All other subtests pass (their fixtures don't have `SSLForceHTTPS=true`).

- [ ] **Step 4: Add a new characterization fixture entry for the `https_force_custom_location` case**

Edit the same test file. In the `cases` slice inside `TestProxyHostTemplate_Characterization` (around line 217-223), add the new fixture:

```go
{name: "https_force_custom_location", data: fixtureHTTPSForceCustomLocation()},
```

Place it after `https_force` so the cases stay grouped.

- [ ] **Step 5: Regenerate the affected golden files with `-update-golden`**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ \
  -run TestProxyHostTemplate_Characterization -update-golden
```

This rewrites both `proxy_host_https_force.conf` (existing — for the no-custom-config case) and creates `proxy_host_https_force_custom_location.conf` (new).

- [ ] **Step 6: Manually inspect the regenerated golden files**

```bash
grep -A4 "Redirect HTTP to HTTPS" api/internal/nginx/testdata/golden/proxy_host_https_force.conf
grep -A4 "Redirect HTTP to HTTPS" api/internal/nginx/testdata/golden/proxy_host_https_force_custom_location.conf
```

Both should now show:
```
    # Redirect HTTP to HTTPS
    # Server-level redirect — survives any user-defined location block.
    # Bypass: ACME HTTP-01 (cert renewal) + NPG challenge page (geo restriction).
    if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/") {
        return 301 https://$host$request_uri;
```

If anything looks off (wrong indentation, missing bypass, etc.), revisit Step 1 — the fix is wrong, not the goldens.

- [ ] **Step 7: Re-run the full nginx test package**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ -v
```

Expected: ALL tests pass (characterization, behavioral, plus any pre-existing tests that hit unrelated code paths).

- [ ] **Step 8: Commit the fix and golden updates together**

```bash
git add api/internal/nginx/templates/proxy_host/waf.conf.tmpl \
        api/internal/nginx/proxy_host_template_characterization_test.go \
        api/internal/nginx/testdata/golden/proxy_host_https_force.conf \
        api/internal/nginx/testdata/golden/proxy_host_https_force_custom_location.conf
git commit -m "fix(nginx): redirect HTTP→HTTPS via server-level if to survive custom location / (#129)

Force HTTPS rendered as 'location / { return 301; }' was silently dropped when the
user supplied their own 'location /' in Advanced Config (HasCustomLocationRoot
detection skipped our block to avoid duplicate-location errors). Switch to a
server-block-level 'if (\$request_uri !~ ...) { return 301; }' so it survives any
custom location, with explicit bypass for ACME HTTP-01 (cert renewal) and the NPG
challenge page (geo-restriction).

Closes #129."
```

---

## Phase 2 — E2E Regression Test

### Task 2.1: Build E2E images with the fix

- [ ] **Step 1: Rebuild the API image (template change is in Go embed.FS)**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
```

- [ ] **Step 2: Restart the E2E stack**

```bash
sudo docker compose -f docker-compose.e2e-test.yml up -d
```

- [ ] **Step 3: Wait for healthy state**

```bash
sudo docker compose -f docker-compose.e2e-test.yml ps
```

Expected: all five services (db, valkey, api, ui, nginx) report `healthy` or `running`.

If `api` doesn't come up, check logs:
```bash
sudo docker compose -f docker-compose.e2e-test.yml logs api --tail 50
```

---

### Task 2.2: Add E2E spec — failing scenario first, then verify pass

**Files:**
- Create: `test/e2e/specs/proxy-host/force-https-custom-config.spec.ts`

- [ ] **Step 1: Create the spec file with the full content below**

```typescript
import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';

const NGINX_HTTP_HOST = '127.0.0.1';
const NGINX_HTTP_PORT = 18080;

/**
 * Issue #129: Force HTTPS silently no-ops when the user adds a custom
 * `location /` to Advanced Config. The fix moves the HTTP→HTTPS redirect
 * from a `location / { return 301 }` block to a server-level
 * `if ($request_uri !~ "^/.well-known/acme-challenge/|^/api/v1/challenge/")
 * { return 301; }` so it survives any custom location AND preserves
 * Let's Encrypt HTTP-01 cert renewal.
 */

interface RawHTTPResponse {
  status: number;
  headers: Record<string, string>;
}

// Send a raw HTTP/1.1 request to nginx with an explicit Host header (so it
// routes to the test virtual host) and parse the status line + headers.
// We bypass `request.get()` because Playwright requires a resolvable host
// for the URL, and our test domain only exists inside nginx.
function rawHTTPGet(path: string, hostHeader: string): Promise<RawHTTPResponse> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: NGINX_HTTP_HOST, port: NGINX_HTTP_PORT });
    socket.setTimeout(8000);

    let buf = '';
    let settled = false;
    const done = (v: RawHTTPResponse | Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (v instanceof Error) reject(v);
      else resolve(v);
    };

    socket.on('connect', () => {
      socket.write(
        `GET ${path} HTTP/1.1\r\n` +
          `Host: ${hostHeader}\r\n` +
          `Connection: close\r\n` +
          `User-Agent: npg-e2e-issue129\r\n` +
          `Accept: */*\r\n` +
          `\r\n`,
      );
    });

    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      // We only need the head; once we have the blank line separator we can resolve.
      const headEnd = buf.indexOf('\r\n\r\n');
      if (headEnd >= 0) {
        const head = buf.slice(0, headEnd);
        const lines = head.split('\r\n');
        const m = lines[0].match(/^HTTP\/1\.[01] (\d{3})/);
        const status = m ? Number(m[1]) : 0;
        const headers: Record<string, string> = {};
        for (const line of lines.slice(1)) {
          const idx = line.indexOf(':');
          if (idx > 0) {
            headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
          }
        }
        done({ status, headers });
      }
    });

    socket.on('end', () => done(new Error('connection closed before headers')));
    socket.on('error', (err) => done(err));
    socket.on('timeout', () => done(new Error('raw HTTP request timed out')));
  });
}

test.describe('Issue #129: Force HTTPS with custom location /', () => {
  let apiHelper: APIHelper;
  let hostId: string;
  let hostIdNoCustom: string;
  const testDomain = `e2e-issue129-${Date.now()}.local`;
  const testDomainNoCustom = `e2e-issue129-nocustom-${Date.now()}.local`;

  test.beforeAll(async ({ playwright }) => {
    const apiContext = await playwright.request.newContext({
      baseURL: process.env.BASE_URL || 'https://localhost:18181',
      ignoreHTTPSErrors: true,
    });
    apiHelper = new APIHelper(apiContext);
    await apiHelper.login();

    // Host A: SSL+ForceHTTPS with custom location /
    const hostA = await apiHelper.createProxyHost({
      domain_names: [testDomain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 9, // closed port — proxying yields 502, but redirect should fire first
      enabled: true,
      ssl_enabled: true,
      ssl_force_https: true,
      advanced_config: 'location / {\n    proxy_pass http://127.0.0.1:9;\n}\n',
    });
    hostId = hostA.id;

    // Host B: SSL+ForceHTTPS without custom config (regression guard)
    const hostB = await apiHelper.createProxyHost({
      domain_names: [testDomainNoCustom],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 9,
      enabled: true,
      ssl_enabled: true,
      ssl_force_https: true,
    });
    hostIdNoCustom = hostB.id;
  });

  test.afterAll(async () => {
    if (hostId) await apiHelper.deleteProxyHost(hostId).catch(() => undefined);
    if (hostIdNoCustom) await apiHelper.deleteProxyHost(hostIdNoCustom).catch(() => undefined);
  });

  test('HTTP request to host with custom location / redirects to HTTPS (#129 main case)', async () => {
    const resp = await rawHTTPGet('/anything', testDomain);
    expect(resp.status).toBe(301);
    expect(resp.headers['location']).toMatch(/^https:\/\//);
  });

  test('ACME challenge path is NOT redirected (SSL renewal regression guard)', async () => {
    const resp = await rawHTTPGet('/.well-known/acme-challenge/test-token', testDomain);
    // 404 expected (no token file exists). Critical assertion: NOT 301.
    expect(resp.status).not.toBe(301);
  });

  test('NPG challenge path is NOT redirected', async () => {
    const resp = await rawHTTPGet('/api/v1/challenge/test', testDomain);
    expect(resp.status).not.toBe(301);
  });

  test('Force HTTPS without custom config still redirects (regression guard)', async () => {
    const resp = await rawHTTPGet('/anything', testDomainNoCustom);
    expect(resp.status).toBe(301);
    expect(resp.headers['location']).toMatch(/^https:\/\//);
  });
});
```

- [ ] **Step 2: Verify the spec is syntactically valid by listing tests (no execution)**

```bash
cd test/e2e && npx playwright test specs/proxy-host/force-https-custom-config.spec.ts --list
```

Expected: 4 tests listed, no parse errors.

- [ ] **Step 3: Run the spec against the now-fixed E2E environment**

```bash
cd test/e2e && BASE_URL=https://localhost:18181 npx playwright test specs/proxy-host/force-https-custom-config.spec.ts
```

Expected: 4/4 PASS.

- [ ] **Step 4 (optional but recommended): Confirm the test would catch a regression**

To prove the test would have caught the bug, temporarily revert the template fix:

```bash
git stash push api/internal/nginx/templates/proxy_host/waf.conf.tmpl
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
sudo docker compose -f docker-compose.e2e-test.yml up -d api
cd test/e2e && BASE_URL=https://localhost:18181 npx playwright test specs/proxy-host/force-https-custom-config.spec.ts
```

Expected: the first test (`HTTP request to host with custom location /`) should now FAIL — 502 (from upstream port 9) or 200 instead of 301. The other three tests may still pass (they don't depend on the bug).

Re-apply the fix:
```bash
git stash pop
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
sudo docker compose -f docker-compose.e2e-test.yml up -d api
cd test/e2e && BASE_URL=https://localhost:18181 npx playwright test specs/proxy-host/force-https-custom-config.spec.ts
```

Expected: all 4 PASS again.

- [ ] **Step 5: Run the broader E2E suite that touches proxy-host and security to confirm no regressions**

```bash
cd test/e2e && BASE_URL=https://localhost:18181 npx playwright test specs/proxy-host/ specs/security/
```

Expected: pre-existing tests still pass. (Some unrelated flake is acceptable; what we're guarding against is *systematic* breakage from the template change.)

- [ ] **Step 6: Commit the E2E spec**

```bash
git add test/e2e/specs/proxy-host/force-https-custom-config.spec.ts
git commit -m "test(e2e): regression coverage for force_https with custom advanced config (#129)"
```

---

## Phase 3 — Release

### Task 3.1: Bump version

**Files:**
- Modify: `api/internal/config/constants.go` (the `AppVersion` constant)
- Modify: `ui/package.json` (the `version` field)

- [ ] **Step 1: Confirm current version**

```bash
grep "AppVersion" api/internal/config/constants.go
grep '"version"' ui/package.json
```

Expected: both show `"2.13.7"`.

- [ ] **Step 2: Bump `AppVersion` in `api/internal/config/constants.go` from `"2.13.7"` to `"2.13.8"`**

Use the Edit tool or `sed -i 's/AppVersion = "2.13.7"/AppVersion = "2.13.8"/' api/internal/config/constants.go`.

- [ ] **Step 3: Bump `version` in `ui/package.json` from `"2.13.7"` to `"2.13.8"`**

Edit the line `"version": "2.13.7"` → `"version": "2.13.8"`.

- [ ] **Step 4: Verify both files updated**

```bash
grep "AppVersion" api/internal/config/constants.go
grep '"version"' ui/package.json
```

Both should now show `2.13.8`.

- [ ] **Step 5: Commit the release bump**

```bash
git add api/internal/config/constants.go ui/package.json
git commit -m "release: v2.13.8"
```

---

### Task 3.2: Final smoke test in dev environment

- [ ] **Step 1: Build and restart dev stack with the new code**

```bash
sudo docker compose -f docker-compose.dev.yml build --no-cache api
sudo docker compose -f docker-compose.dev.yml up -d api
```

- [ ] **Step 2: Confirm API reports new version**

```bash
docker compose -f docker-compose.dev.yml exec api wget -qO- http://localhost:8080/api/v1/health
```

Expected: JSON contains `"version":"2.13.8"`.

- [ ] **Step 3: Run unit tests one last time on the full nginx package**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/ -v
```

Expected: all PASS.

---

### Task 3.3: Open the PR and link the fix to issue #129

- [ ] **Step 1: Push the branch (or stay on main if working directly there per maintainer's preference)**

```bash
git push origin HEAD
```

- [ ] **Step 2: Open the PR**

```bash
gh pr create --title "fix(nginx): force HTTPS works with custom location / config (#129)" --body "$(cat <<'EOF'
## Summary
- Replaces the `location / { return 301 ...; }` HTTP→HTTPS redirect with a server-block-level `if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/") { return 301; }` so it survives any user-defined `location /` in Advanced Config.
- Preserves Let's Encrypt HTTP-01 cert renewal via the explicit ACME bypass in the negative regex, and bypasses NPG's own challenge page for safety.
- Adds Go behavioral assertion tests + Playwright E2E regression coverage; updates affected golden fixtures.
- Bumps version to v2.13.8.

Closes #129.

## Test plan
- [x] Unit: `TestForceHTTPSCustomLocationRedirects` and `TestForceHTTPSACMEBypass` pass in `api/internal/nginx/`
- [x] Unit: `TestProxyHostTemplate_Characterization/https_force` and `…/https_force_custom_location` pass with updated goldens
- [x] E2E: `test/e2e/specs/proxy-host/force-https-custom-config.spec.ts` 4/4 pass against the e2e-test stack
- [x] E2E (broader): no regressions in `specs/proxy-host/` and `specs/security/`
- [x] Smoke: dev API `/api/v1/health` reports v2.13.8
EOF
)"
```

- [ ] **Step 3: Comment on issue #129 with a summary and resolution note**

```bash
gh issue comment 129 --repo svrforum/nginxproxyguard --body "$(cat <<'EOF'
Hi @ydrob — thanks for the detailed report and for proposing the right shape of the fix.

**Root cause:** the auto-generated HTTP→HTTPS redirect was a `location / { return 301; }` block, and the template detected when your Advanced Config also defined `location /` and **omitted** our redirect entirely (to avoid an nginx duplicate-location error). The result was that `Force HTTPS` silently no-opped.

**Fix (released in v2.13.8):** the redirect is now a server-block-level `if`:
```nginx
if ($request_uri !~ "^/\.well-known/acme-challenge/|^/api/v1/challenge/") {
    return 301 https://$host$request_uri;
}
```
This evaluates during nginx's rewrite phase, before any location matching, so your custom `location /` no longer shadows it. The negative regex falls through (no `return` executed) for ACME and NPG-challenge paths so Let's Encrypt cert renewal continues to work.

**Recommendation:** once you upgrade to v2.13.8 you can remove the workaround `if ($scheme = http) { return 301 https://$host$request_uri; }` from your Advanced Config — it is no longer needed, and (worth noting) that workaround would actually break SSL auto-renewal because it does **not** bypass `/.well-known/acme-challenge/`, so requests from Let's Encrypt would have gotten redirected to HTTPS instead of being served the validation token.

Closing — please reopen if you see the issue persist after upgrading.
EOF
)"

gh issue close 129 --repo svrforum/nginxproxyguard
```

> Steps 1-3 should run as separate commands (the first push must succeed before `gh pr create`, and the comment is only posted once the PR exists).

---

## Phase 4 — Post-merge cleanup

### Task 4.1: Tag and let CI publish the release

- [ ] **Step 1: After PR is merged to main, tag**

```bash
git checkout main && git pull
git tag v2.13.8
git push origin v2.13.8
```

- [ ] **Step 2: Watch the CI release workflow**

```bash
gh run list --workflow release --limit 3
```

Expected: a new run is queued / running for tag `v2.13.8`. CI builds multi-arch Docker images for `api`, `ui`, `nginx`.

---

## Self-Review Checklist (engineer or reviewer can run last)

- [ ] All four golden files referenced in this plan exist in `api/internal/nginx/testdata/golden/`:
  - `proxy_host_https_force.conf` (updated content)
  - `proxy_host_https_force_custom_location.conf` (new)
- [ ] `git grep "location / {"` against the merged code does NOT show the redirect-only `location / { return 301 ...` form anywhere — only user-supplied advanced config can introduce one.
- [ ] `git grep "if (\\$request_uri !~"` shows the new bypass `if` exactly once (in `waf.conf.tmpl`).
- [ ] Issue #129 is closed with the resolution comment posted.
- [ ] Version `2.13.8` is reflected in both `api/internal/config/constants.go` and `ui/package.json`.

---

## Notes for the executor

- **Frequent commits:** every Task ends in a commit. If a step turns out wrong, prefer a `git revert` of a single commit over a destructive reset.
- **No skipping steps:** especially the "Run test, confirm it FAILS" steps — those are the TDD record of the bug. Skipping them turns the unit tests into rubber stamps.
- **Indentation in templates matters:** nginx itself doesn't care, but the golden file diff is byte-exact. Use four spaces (matches surrounding template), not tabs.
- **If `go test` cannot resolve the package path:** the project root is `/opt/stacks/nginxproxyguard`. The Go module is rooted in `api/`. From repo root, use `docker compose -f docker-compose.dev.yml run --rm api go test ./internal/nginx/`. From inside `api/`, use `go test ./internal/nginx/`.
- **If the E2E API request to create a host fails with `ssl_force_https not allowed`:** the API may require a `certificate_id`. The fixture in this plan deliberately omits it because nginx's `nginx -t` accepts the rendered config even without a cert (the server block just references a path that doesn't exist; in test env nginx may emit a warning but still load). If host creation rejects the request, attach a self-signed cert via `apiHelper.createCertificate(...)` and pass `certificate_id` to `createProxyHost`. Adapt to whatever the API helper exposes — do not bypass API validation.

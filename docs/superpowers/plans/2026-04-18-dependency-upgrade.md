# Dependency Upgrade Implementation Plan (v2.12.0 & v2.13.0)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the entire stack (frontend, backend, infra) to current stable versions across two minor releases — v2.12.0 (low-risk bundle) and v2.13.0 (major breaking changes) — while maintaining Node.js on LTS and guaranteeing stable operation via Playwright E2E at every step.

**Architecture:** Risk-based 2-phase execution. Phase 1 packages low-risk patch/minor/security updates into a single branch, committed in logical chunks for bisect. Phase 2 groups mature-major upgrades on a separate branch, one breaking change per commit, with full E2E regression after each. Each phase culminates in a single tagged release (v-tag pushed → GitHub Actions multi-arch build).

**Tech Stack:** Go 1.25, Echo v4.15, Nginx 1.30, ModSecurity 3.0.14, OWASP CRS 4.25, Valkey 9, TimescaleDB 17 (pg17), Alpine 3.23, Node 22 LTS, React 19, Vite 7, TailwindCSS 4, TypeScript 5.9, Playwright (E2E), Docker Compose.

**Reference spec:** [`docs/superpowers/specs/2026-04-18-dependency-upgrade-design.md`](../specs/2026-04-18-dependency-upgrade-design.md)

---

## Execution Preliminaries

### Why no new tests are written

This plan performs **pure version upgrades** — no new feature code, no behavior change. The existing Playwright regression suite at `test/e2e/specs/` is the acceptance test for every task. Classical Red-Green-Refactor TDD does not apply. Each task follows: **make change → rebuild → run E2E → commit**.

### Host lacks Go and Node.js — all builds run in Docker

Per `CLAUDE.md`: "호스트에 Go/Node.js 미설치. 반드시 Docker로 빌드!" Every dependency-manifest modification uses a one-shot Docker container to refresh lockfiles (`go.sum`, `package-lock.json`) so they stay in sync with manifests.

### Standard verification block

Every upgrade task ends with this block (referred to as **"Run standard verification"**):

```bash
# 1. Build dev images
sudo docker compose -f docker-compose.dev.yml build api ui nginx

# 2. Rebuild E2E test environment with new images
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache
sudo docker compose -f docker-compose.e2e-test.yml up -d

# 3. Run full Playwright suite
cd test/e2e && npx playwright test
```

**Expected result:** `docker compose build` exits 0; Playwright reports "X passed" with zero failures.

**If failure:** Fix within the **same commit** (don't add a follow-up commit). If the root cause is the dependency upgrade itself and cannot be fixed without pinning an older version, stop the task and surface to the user.

### Commit style (CLAUDE.md enforced)

- Format: `type(scope): description`
- No `Generated with Claude Code` / `Co-Authored-By: Claude` trailer
- Stage explicit files only, never `git add -A`

### Worktree / branch convention

Two branches off `main`:

- `phase1/low-risk-upgrades` → merges into main as v2.12.0
- `phase2/major-upgrades` → branches from v2.12.0, merges into main as v2.13.0

---

## Phase 1 — v2.12.0 (Low-Risk Bundle)

### Task 1: Create Phase 1 branch

**Files:** (none)

- [ ] **Step 1: Verify clean main**

```bash
git checkout main
git status --short
```
Expected: only untracked test artifacts (`.playwright-mcp/`, `test-results/`). No modified tracked files.

- [ ] **Step 2: Pull latest**

```bash
git fetch origin
git pull --ff-only origin main
```

- [ ] **Step 3: Create branch**

```bash
git checkout -b phase1/low-risk-upgrades
```

---

### Task 2: Bump Go toolchain to 1.25

**Files:**
- Modify: `api/go.mod` (lines 3–5)
- Modify: `api/Dockerfile` (line with `FROM golang:...`)
- Regenerate: `api/go.sum`

- [ ] **Step 1: Edit `api/go.mod`**

Replace:
```
go 1.22.0

toolchain go1.22.12
```
With:
```
go 1.22.0

toolchain go1.25.0
```

(Keep `go 1.22.0` as the module minimum — only the toolchain changes.)

- [ ] **Step 2: Edit `api/Dockerfile`**

Replace:
```
FROM golang:1.24-alpine AS builder
```
With:
```
FROM golang:1.25-alpine AS builder
```

- [ ] **Step 3: Regenerate `go.sum` in Docker**

```bash
sudo docker run --rm -v "$(pwd)/api":/app -w /app golang:1.25-alpine sh -c 'go mod tidy'
```

- [ ] **Step 4: Run standard verification**

- [ ] **Step 5: Commit**

```bash
git add api/go.mod api/go.sum api/Dockerfile
git commit -m "chore(api): bump Go toolchain to 1.25"
```

---

### Task 3: Bump Echo to v4.15.0

**Files:**
- Modify: `api/go.mod`, `api/go.sum`

- [ ] **Step 1: Update Echo dependency via Docker**

```bash
sudo docker run --rm -v "$(pwd)/api":/app -w /app golang:1.25-alpine sh -c \
  'go get github.com/labstack/echo/v4@v4.15.0 && go mod tidy'
```

- [ ] **Step 2: Verify `api/go.mod` line changed**

```bash
grep 'labstack/echo/v4' api/go.mod
```
Expected: `github.com/labstack/echo/v4 v4.15.0`

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Commit**

```bash
git add api/go.mod api/go.sum
git commit -m "chore(api): bump Echo to v4.15.0"
```

---

### Task 4: Patch-level update of all other Go deps

**Files:**
- Modify: `api/go.mod`, `api/go.sum`

- [ ] **Step 1: Run patch-level update**

```bash
sudo docker run --rm -v "$(pwd)/api":/app -w /app golang:1.25-alpine sh -c \
  'go get -u=patch ./... && go mod tidy'
```

This applies only patch-level (x.y.Z) updates to direct and indirect dependencies, avoiding any minor-version surprises on libraries like `lego`, `prometheus-client`, `go-redis`, `geoip2-golang`.

- [ ] **Step 2: Review the diff**

```bash
git diff api/go.mod
```
Confirm only patch-level bumps. If any minor version bumped, reset that specific dep via `go get pkg@prev-minor-version`.

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Commit**

```bash
git add api/go.mod api/go.sum
git commit -m "chore(api): patch-level update of Go dependencies"
```

---

### Task 5: Bump Nginx to 1.30.0

**Files:**
- Modify: `nginx/Dockerfile` (ARG line + header comment)

- [ ] **Step 1: Edit `nginx/Dockerfile`**

Replace:
```
# - nginx: 1.28.0 (stable with HTTP/3 QUIC support)
```
With:
```
# - nginx: 1.30.0 (stable with HTTP/3 QUIC support)
```

Replace:
```
ARG NGINX_VERSION=1.28.0
```
With:
```
ARG NGINX_VERSION=1.30.0
```

- [ ] **Step 2: Run standard verification**

Nginx rebuild is slow (~5–10 min) because it compiles from source. The E2E environment's `npg-proxy` image must be rebuilt fresh — that's what `--no-cache` in the standard block handles.

- [ ] **Step 3: Commit**

```bash
git add nginx/Dockerfile
git commit -m "chore(nginx): bump Nginx to 1.30.0"
```

---

### Task 6: Bump OWASP CRS to 4.25.0

**Files:**
- Modify: `nginx/Dockerfile` (ARG line + header comment)

- [ ] **Step 1: Edit `nginx/Dockerfile`**

Replace:
```
# - OWASP CRS: 4.20.0
```
With:
```
# - OWASP CRS: 4.25.0
```

Replace:
```
ARG OWASP_CRS_VERSION=4.21.0
```
With:
```
ARG OWASP_CRS_VERSION=4.25.0
```

- [ ] **Step 2: Run standard verification**

Pay extra attention to:
- `test/e2e/specs/security/waf.spec.ts`
- `test/e2e/specs/security/exploit-blocks.spec.ts`

These validate WAF blocking/detection behavior. CRS 4.21 → 4.25 may adjust some rule IDs and severity levels; false-positive regressions (legitimate requests now blocked) would show as test failures here.

- [ ] **Step 3: Commit**

```bash
git add nginx/Dockerfile
git commit -m "chore(nginx): bump OWASP CRS to 4.25.0"
```

---

### Task 7: Bump TypeScript to 5.9

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Update TypeScript via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install --save-dev typescript@^5.9'
```

- [ ] **Step 2: Verify version**

```bash
grep '"typescript"' ui/package.json
```
Expected: `"typescript": "^5.9.x"` (where x is latest patch)

- [ ] **Step 3: Typecheck inside Docker** (sanity check before full rebuild)

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install && npx tsc -b --noEmit'
```
Expected: exit 0, no type errors.

- [ ] **Step 4: Run standard verification**

- [ ] **Step 5: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): bump TypeScript to 5.9"
```

---

### Task 8: Patch-level update of Vite on the 6.x line

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Pin latest 6.x via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install --save-dev vite@^6'
```

- [ ] **Step 2: Verify `ui/package.json` stays within 6.x**

```bash
grep '"vite"' ui/package.json
```
Expected: `"vite": "^6.x.x"` — must NOT jump to 7.x (that's Phase 2).

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): patch-level update of Vite 6.x"
```

---

### Task 9: Bump @tanstack/react-query to 5.99

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Update via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install @tanstack/react-query@^5.99'
```

- [ ] **Step 2: Run standard verification**

- [ ] **Step 3: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): bump @tanstack/react-query to 5.99"
```

---

### Task 10: Bump react-router-dom to 7.14

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Update via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install react-router-dom@^7.14'
```

- [ ] **Step 2: Run standard verification**

Router traversal is tested across `test/e2e/specs/` — Dashboard, ProxyHost list navigation, Settings pages all exercise client-side routing.

- [ ] **Step 3: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): bump react-router-dom to 7.14"
```

---

### Task 11: Bump recharts to 3.8

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Update via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install recharts@^3.8'
```

- [ ] **Step 2: Run standard verification**

Charts render on the Dashboard (`Dashboard.tsx`). Any E2E specs that screenshot/assert dashboard content will exercise recharts.

- [ ] **Step 3: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): bump recharts to 3.8"
```

---

### Task 12: Patch-level update of i18next on the 25.x line

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Update via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install i18next@^25'
```

- [ ] **Step 2: Verify stays within 25.x**

```bash
grep '"i18next"' ui/package.json
```
Expected: `"i18next": "^25.x.x"` — must NOT jump to 26.x (Phase 2).

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): patch-level update of i18next 25.x"
```

---

### Task 13: Patch-level update of remaining UI dependencies

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Bulk patch update via Docker**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npx npm-check-updates -t patch -u && npm install'
```

`npm-check-updates -t patch -u` bumps only the patch segment of every direct dependency in `package.json`. No minor or major bumps.

- [ ] **Step 2: Review diff**

```bash
git diff ui/package.json
```
Confirm all changes are patch-level (e.g., `^4.3.3` → `^4.3.7`). If any bump to a minor, revert that single line manually.

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): patch-level update of remaining dependencies"
```

---

### Task 14: Bump project version to 2.12.0

**Files:**
- Modify: `api/internal/config/constants.go`
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Update API version**

Edit `api/internal/config/constants.go`. Change:
```go
const AppVersion = "2.11.0"
```
To:
```go
const AppVersion = "2.12.0"
```

- [ ] **Step 2: Update UI version**

Edit `ui/package.json`. Change:
```json
"version": "2.11.0",
```
To:
```json
"version": "2.12.0",
```

- [ ] **Step 3: Refresh `ui/package-lock.json`**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c 'npm install'
```

- [ ] **Step 4: Commit**

```bash
git add api/internal/config/constants.go ui/package.json ui/package-lock.json
git commit -m "release: v2.12.0"
```

---

### Task 15: Final Phase 1 verification

**Files:** (none — verification only)

- [ ] **Step 1: Run standard verification once more**

All prior tasks verified in isolation. Rerun to confirm the full accumulated diff still passes.

- [ ] **Step 2: Verify version endpoint**

```bash
sudo docker compose -f docker-compose.e2e-test.yml exec api wget -qO- http://localhost:8080/health
```
Expected: JSON with `"version":"2.12.0"`.

- [ ] **Step 3: Tear down E2E env**

```bash
sudo docker compose -f docker-compose.e2e-test.yml down
```

---

### Task 16: Merge Phase 1 and tag v2.12.0

**Files:** (none — git operations)

- [ ] **Step 1: Push phase1 branch for review visibility**

```bash
git push -u origin phase1/low-risk-upgrades
```

- [ ] **Step 2: Fast-forward-or-merge into main**

```bash
git checkout main
git merge --no-ff phase1/low-risk-upgrades -m "release: merge phase1 low-risk upgrades for v2.12.0"
```

- [ ] **Step 3: Tag**

```bash
git tag v2.12.0
```

- [ ] **Step 4: Push main and tag**

```bash
git push origin main
git push origin v2.12.0
```

GitHub Actions triggers multi-arch Docker builds on `v*` tag push. Do not proceed to Phase 2 until the Actions workflow completes successfully.

- [ ] **Step 5: Verify Actions workflow green**

Check the Actions tab on GitHub for the v2.12.0 build. Wait for all three images (api, ui, nginx) to publish.

---

## Phase 2 — v2.13.0 (Major Bundle)

### Task 17: Create Phase 2 branch

**Files:** (none)

- [ ] **Step 1: Verify on clean main at v2.12.0**

```bash
git checkout main
git pull --ff-only
git log -1 --oneline
```
Expected: top commit is the v2.12.0 merge.

- [ ] **Step 2: Create branch**

```bash
git checkout -b phase2/major-upgrades
```

---

### Task 18: Valkey 8 → 9

**Files:**
- Modify: `docker-compose.yml` (line 29)
- Modify: `docker-compose.dev.yml` (line 35)
- Modify: `docker-compose.e2e-test.yml` (line 41)

- [ ] **Step 1: Edit all three compose files**

In each file, replace:
```
image: valkey/valkey:8-alpine
```
With:
```
image: valkey/valkey:9-alpine
```

- [ ] **Step 2: Run standard verification**

If E2E setup shows Valkey startup issues (likely RDB format incompatibility), wipe the volume:

```bash
sudo docker compose -f docker-compose.e2e-test.yml down -v
sudo docker compose -f docker-compose.e2e-test.yml up -d
```

Per `pkg/cache/redis.go` (cache-only usage) and CLAUDE.md principle #5 (Graceful Degradation), wiping the volume is safe — the cache will be repopulated from DB state.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml docker-compose.dev.yml docker-compose.e2e-test.yml
git commit -m "chore(infra): bump Valkey to 9-alpine"
```

---

### Task 19: Tailwind CSS 3.4 → 4.x

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`
- Modify: `ui/src/index.css`
- Modify: `ui/postcss.config.js`
- Modify: `ui/vite.config.ts`
- (Possibly modify or remove) `ui/tailwind.config.js`

- [ ] **Step 1: Install Tailwind v4 + Vite plugin, remove v3 PostCSS plugin**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm uninstall tailwindcss autoprefixer postcss && npm install --save-dev tailwindcss@^4 @tailwindcss/vite@^4'
```

- [ ] **Step 2: Replace `@tailwind` directives in `ui/src/index.css`**

In `ui/src/index.css`, replace the three directive lines:
```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```
With the single import line:
```css
@import "tailwindcss";
```

Keep the other `@import` lines (react-datepicker.css, Google Fonts, Pretendard) above it untouched.

- [ ] **Step 3: Update `ui/vite.config.ts`**

Add the Tailwind v4 Vite plugin. Read the file, then add `import tailwindcss from '@tailwindcss/vite'` at the top imports and include `tailwindcss()` in the `plugins` array. Example:

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // ...existing config
})
```

- [ ] **Step 4: Delete `ui/postcss.config.js`**

```bash
rm ui/postcss.config.js
```

Tailwind v4 uses the Vite plugin directly, not PostCSS.

- [ ] **Step 5: Run Tailwind v4 migration tool for the config**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npx @tailwindcss/upgrade@latest'
```

This converts `tailwind.config.js` custom theme tokens (like the `primary` color scale) into CSS `@theme` blocks in `index.css`. Review the changes; migration may or may not keep `tailwind.config.js` — whatever the tool leaves.

- [ ] **Step 6: Review migration diff**

```bash
git diff ui/src/index.css ui/tailwind.config.js ui/vite.config.ts ui/postcss.config.js
```

Confirm:
- `@tailwind` directives replaced with `@import "tailwindcss"`
- Custom `primary` color scale preserved (in either `tailwind.config.js` or inline `@theme` in CSS)

- [ ] **Step 7: Run standard verification**

**Extra scrutiny** for this task: Tailwind v4 renames or changes defaults for some utilities (e.g., `shadow-sm` → `shadow-xs`, `rounded-md` default radius). E2E may still pass visually, but any screenshot assertions in `test/e2e/specs/` would catch regressions. After E2E passes, manually browse the dev UI (`sudo docker compose -f docker-compose.dev.yml up -d && open https://localhost`) to confirm dark mode, dashboard cards, buttons render as before.

- [ ] **Step 8: Commit**

```bash
git add ui/package.json ui/package-lock.json ui/src/index.css ui/vite.config.ts ui/tailwind.config.js
git rm ui/postcss.config.js 2>/dev/null || true
git commit -m "chore(ui): bump TailwindCSS to 4.x"
```

---

### Task 20: Vite 6 → 7

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`
- Possibly modify: `ui/vite.config.ts` (if config options deprecated)

- [ ] **Step 1: Upgrade Vite and plugin-react**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install --save-dev vite@^7 @vitejs/plugin-react@^5'
```

- [ ] **Step 2: Check for Vite 7 config warnings**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install && npx vite build'
```

If stderr contains warnings about deprecated config options, update `ui/vite.config.ts` accordingly. Common Vite 7 changes: default `target` raised to `baseline-widely-available`, removal of legacy CommonJS optimizer flags.

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Commit**

```bash
git add ui/package.json ui/package-lock.json ui/vite.config.ts
git commit -m "chore(ui): bump Vite to 7 and plugin-react to 5"
```

---

### Task 21: ESLint 9 → 10 + typescript-eslint latest

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`
- Possibly modify: `ui/eslint.config.js`

- [ ] **Step 1: Upgrade eslint and its TS plugin**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install --save-dev eslint@^10 typescript-eslint@latest @eslint/js@latest eslint-plugin-react-hooks@latest eslint-plugin-react-refresh@latest'
```

- [ ] **Step 2: Run lint to surface breaking rule changes**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install && npx eslint . 2>&1 | head -80'
```

If lint errors are reported, fix the code. If lint configuration errors are reported (e.g., rule removed/renamed), update `ui/eslint.config.js`.

- [ ] **Step 3: Run standard verification**

Build must still pass — lint is not part of the Docker build by default, but E2E covers runtime behavior.

- [ ] **Step 4: Commit**

```bash
git add ui/package.json ui/package-lock.json ui/eslint.config.js
git commit -m "chore(ui): bump ESLint to 10 and typescript-eslint"
```

---

### Task 22: React 18 → 19

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`

- [ ] **Step 1: Upgrade React and its type definitions**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install react@^19 react-dom@^19 && npm install --save-dev @types/react@^19 @types/react-dom@^19'
```

- [ ] **Step 2: Bump peer-dep-bound libraries if npm reports peer conflicts**

Check npm output for `npm WARN ERESOLVE` around `react-datepicker`, `recharts`, `react-router-dom`, `react-i18next`. If any warn about React 19 incompatibility, update them:

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install react-datepicker@latest recharts@latest react-simple-maps@latest'
```

`react-simple-maps@3.0.0` has been React 19 compatible since 2024; `react-datepicker` v8 supports React 19; `recharts` v3 already supports it.

- [ ] **Step 3: Typecheck**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install && npx tsc -b --noEmit'
```

Expected: zero type errors. If any type errors appear from React 19's stricter JSX namespace (`JSX.Element` removed in favor of `React.JSX.Element`), fix the affected files inline.

- [ ] **Step 4: Run standard verification**

React 19 Strict Mode double-invokes effects on mount in dev; E2E runs against the built (prod) bundle so this should not manifest, but watch for console errors in the browser devtools during manual smoke.

- [ ] **Step 5: Manual smoke (UI-visible change)**

```bash
sudo docker compose -f docker-compose.dev.yml up -d ui api
```
Open `https://localhost`. Exercise:
- Login form
- Dashboard charts
- Proxy host create modal (tabs render)
- Dark mode toggle
- Language switch (ko/en)

Confirm no console errors about `findDOMNode`, `ReactDOM.render`, or legacy APIs.

- [ ] **Step 6: Commit**

```bash
git add ui/package.json ui/package-lock.json
git commit -m "chore(ui): bump React to 19"
```

---

### Task 23: i18next 25 → 26 + react-i18next latest

**Files:**
- Modify: `ui/package.json`, `ui/package-lock.json`
- Possibly modify: `ui/src/i18n/index.ts` (if init options changed)

- [ ] **Step 1: Upgrade both packages**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install i18next@^26 react-i18next@latest i18next-browser-languagedetector@latest'
```

- [ ] **Step 2: Run typecheck**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c \
  'npm install && npx tsc -b --noEmit'
```

If type errors appear in `ui/src/i18n/index.ts` because init option shape changed, fix that file. Likely-stable props: `fallbackLng`, `defaultNS`, `resources`, `interpolation`, `detection`.

- [ ] **Step 3: Run standard verification**

- [ ] **Step 4: Manual i18n smoke**

Switch language between Korean and English on any page with translated strings (Settings is a good target — has many keys). Confirm all visible strings swap correctly and no `{key}` raw strings leak through.

- [ ] **Step 5: Commit**

```bash
git add ui/package.json ui/package-lock.json ui/src/i18n/index.ts
git commit -m "chore(ui): bump i18next to 26 and react-i18next"
```

---

### Task 24: Bump project version to 2.13.0 and add CHANGELOG

**Files:**
- Modify: `api/internal/config/constants.go`
- Modify: `ui/package.json`, `ui/package-lock.json`
- Create or modify: `CHANGELOG.md`

- [ ] **Step 1: Update API version**

Edit `api/internal/config/constants.go`. Change:
```go
const AppVersion = "2.12.0"
```
To:
```go
const AppVersion = "2.13.0"
```

- [ ] **Step 2: Update UI version**

Edit `ui/package.json`. Change:
```json
"version": "2.12.0",
```
To:
```json
"version": "2.13.0",
```

- [ ] **Step 3: Refresh lockfile**

```bash
sudo docker run --rm -v "$(pwd)/ui":/app -w /app node:22-alpine sh -c 'npm install'
```

- [ ] **Step 4: Add or update CHANGELOG.md**

Check if `CHANGELOG.md` exists in repo root. If not, create it. Prepend the following entry:

```markdown
# Changelog

## v2.13.0 (2026-04-XX)

### Breaking Changes

- **TailwindCSS v4**: Custom themes now declared in CSS `@theme` blocks. Users with custom utility plugins must migrate (see Tailwind v4 upgrade guide).
- **React 19**: Strict Mode double-invokes effects in development mode. Components relying on effect-once-per-mount in dev must be audited.
- **i18next 26**: Some init options renamed; verify custom interpolation/detection config if you fork-maintain this project.
- **Valkey 9**: Cache data volume may need flush on first start after upgrade (`docker volume rm npg_valkey_data`). Cache-only usage makes this safe.

### Upgrades

- React 18.3 → 19.2
- TailwindCSS 3.4 → 4.x
- Vite 6 → 7
- ESLint 9 → 10
- i18next 25 → 26
- Valkey 8 → 9

## v2.12.0 (2026-04-XX)

### Upgrades

- Go toolchain 1.22 → 1.25
- Echo v4.12 → v4.15
- Nginx 1.28 → 1.30
- OWASP CRS 4.21 → 4.25
- TypeScript 5.6 → 5.9
- React Query 5.60 → 5.99, react-router-dom 7.9 → 7.14, recharts 3.5 → 3.8
- Patch-level updates across Go and npm dependencies
```

Replace `2026-04-XX` dates with actual release dates when tagging.

- [ ] **Step 5: Commit**

```bash
git add api/internal/config/constants.go ui/package.json ui/package-lock.json CHANGELOG.md
git commit -m "release: v2.13.0"
```

---

### Task 25: Final Phase 2 verification

**Files:** (none — verification only)

- [ ] **Step 1: Run standard verification on accumulated Phase 2 diff**

- [ ] **Step 2: Verify version endpoint returns 2.13.0**

```bash
sudo docker compose -f docker-compose.e2e-test.yml exec api wget -qO- http://localhost:8080/health
```
Expected: JSON with `"version":"2.13.0"`.

- [ ] **Step 3: Manual UI smoke (final sweep)**

```bash
sudo docker compose -f docker-compose.dev.yml up -d
```

Open `https://localhost` and walk:
- Login → Dashboard (charts render, no console errors)
- Proxy hosts list → create modal (all tabs navigate)
- Certificates list
- Settings → Global Settings (i18n strings load)
- Logs viewer
- Dark mode toggle
- Language toggle (ko ↔ en)

- [ ] **Step 4: Tear down envs**

```bash
sudo docker compose -f docker-compose.e2e-test.yml down
sudo docker compose -f docker-compose.dev.yml down
```

---

### Task 26: Merge Phase 2 and tag v2.13.0

**Files:** (none — git operations)

- [ ] **Step 1: Push phase2 branch**

```bash
git push -u origin phase2/major-upgrades
```

- [ ] **Step 2: Merge into main**

```bash
git checkout main
git pull --ff-only
git merge --no-ff phase2/major-upgrades -m "release: merge phase2 major upgrades for v2.13.0"
```

- [ ] **Step 3: Update CHANGELOG date**

Edit `CHANGELOG.md` and replace both `2026-04-XX` dates with today's actual date.

```bash
git add CHANGELOG.md
git commit -m "docs: set v2.13.0 release date in CHANGELOG"
```

- [ ] **Step 4: Tag**

```bash
git tag v2.13.0
```

- [ ] **Step 5: Push main and tag**

```bash
git push origin main
git push origin v2.13.0
```

- [ ] **Step 6: Verify Actions workflow green**

Check the Actions tab for the v2.13.0 build. Wait for all three images (api, ui, nginx) to publish.

---

## Post-Completion

After v2.13.0 is tagged and published:

- Deploy to the production box (`docker-compose.yml`) and verify `/health` returns 2.13.0
- Monitor logs for 24 hours for unexpected errors (new React 19 console warnings, WAF CRS 4.25 false positives, Valkey 9 client connection issues)
- If any regression surfaces, follow the rollback matrix in the spec (§6.2)

Deferred items (out of scope, evaluate 1–2 quarters later):
- TypeScript 6.0, Echo v5, Go 1.26, Vite 8

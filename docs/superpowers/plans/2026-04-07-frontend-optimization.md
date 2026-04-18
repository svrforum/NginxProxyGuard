# Frontend Resource Optimization Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce initial JS bundle from 2.1MB to ~800KB, cut API polling by 50-60%, and remove unnecessary asset weight — all without changing any user-facing functionality.

**Architecture:** Convert 36 synchronous route imports in App.tsx to React.lazy() with per-route code splitting. Adjust React Query global config and per-component refetchInterval values. Replace 240KB favicon.ico with existing shield.svg. Disable production sourcemaps.

**Tech Stack:** React 18, React Router, React Query (TanStack), Vite 6, TypeScript

---

### Task 1: Replace favicon.ico with shield.svg

**Files:**
- Modify: `ui/index.html` (line with `<link rel="icon">`)
- Delete: `ui/public/favicon.ico`

- [ ] **Step 1: Update index.html favicon reference**

In `ui/index.html`, change:
```html
<link rel="icon" type="image/x-icon" href="/favicon.ico" />
```
to:
```html
<link rel="icon" type="image/svg+xml" href="/shield.svg" />
```

- [ ] **Step 2: Delete the oversized favicon.ico**

```bash
rm ui/public/favicon.ico
```

- [ ] **Step 3: Verify shield.svg exists and is small**

```bash
ls -lh ui/public/shield.svg
```
Expected: File exists, under 5KB.

- [ ] **Step 4: Commit**

```bash
git add ui/index.html ui/public/favicon.ico
git commit -m "perf: replace 240KB favicon.ico with shield.svg"
```

---

### Task 2: Disable production sourcemaps

**Files:**
- Modify: `ui/vite.config.ts` (line 22)

- [ ] **Step 1: Update vite.config.ts build config**

In `ui/vite.config.ts`, change:
```typescript
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
```
to:
```typescript
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
```

- [ ] **Step 2: Commit**

```bash
git add ui/vite.config.ts
git commit -m "perf: disable production sourcemaps (saves 6.4MB)"
```

---

### Task 3: Increase React Query global staleTime

**Files:**
- Modify: `ui/src/main.tsx` (lines 8-15)

- [ ] **Step 1: Update QueryClient default options**

In `ui/src/main.tsx`, change:
```typescript
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5000,
      retry: 1,
    },
  },
})
```
to:
```typescript
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30000,
      gcTime: 5 * 60 * 1000,
      retry: 1,
    },
  },
})
```

- [ ] **Step 2: Commit**

```bash
git add ui/src/main.tsx
git commit -m "perf: increase React Query staleTime to 30s, add gcTime 5min"
```

---

### Task 4: Reduce polling intervals across all components

**Files:**
- Modify: `ui/src/App.tsx` (line 94)
- Modify: `ui/src/components/Dashboard.tsx` (lines 28, 40, 46)
- Modify: `ui/src/components/dashboard/HostResourcesSection.tsx`
- Modify: `ui/src/components/CertificateList.tsx`
- Modify: `ui/src/components/BackupManager.tsx`
- Modify: `ui/src/components/BotFilterLogs.tsx`
- Modify: `ui/src/components/ExploitBlockLogs.tsx`
- Modify: `ui/src/components/LogViewer.tsx`
- Modify: `ui/src/components/SystemLogViewer.tsx`
- Modify: `ui/src/components/BannedIPList.tsx`
- Modify: `ui/src/components/banned-ip/BanHistoryTab.tsx`
- Modify: `ui/src/components/URIBlockManager.tsx`
- Modify: `ui/src/components/GeoIPSettings.tsx`
- Modify: `ui/src/components/ChallengeSettings.tsx`
- Modify: `ui/src/components/UpstreamPanel.tsx`

Interval changes (all values in milliseconds):

| File | Current | New | Reason |
|------|---------|-----|--------|
| App.tsx health | 10000 | 30000 | Health check doesn't need 10s |
| Dashboard main | 30000 | 60000 | 1min is sufficient for dashboard |
| Dashboard containers | 30000 | 60000 | Container stats are stable |
| Dashboard geoIP | 60000 | 120000 | Geo data changes slowly |
| HostResourcesSection | 30000 | 60000 | Align with dashboard |
| CertificateList | 15000 | 120000 | Certs rarely change |
| BackupManager | 15000 | 60000 | Backup status doesn't need 15s |
| BotFilterLogs (15s ones) | 15000 | 30000 | Halve frequency |
| BotFilterLogs (30s ones) | 30000 | 60000 | Halve frequency |
| ExploitBlockLogs (15s) | 15000 | 30000 | Halve frequency |
| ExploitBlockLogs (30s) | 30000 | 60000 | Halve frequency |
| LogViewer auto-refresh | keep 15000 | keep | User explicitly enables auto-refresh |
| LogViewer stats | 30000 | 60000 | Stats are cached 2min server-side |
| SystemLogViewer stats | 30000 | 60000 | Same as LogViewer |
| BannedIPList | 30000 | 60000 | Bans don't change rapidly |
| BanHistoryTab (30s) | 30000 | 60000 | History is stable |
| BanHistoryTab (60s) | 60000 | 120000 | Even more stable |
| URIBlockManager (3x 30s) | 30000 | 60000 | All three queries |
| GeoIPSettings | 30000 | 60000 | Geo restrictions rarely change |
| ChallengeSettings | 30000 | 60000 | Challenge config is stable |
| UpstreamPanel | 30000 | 60000 | Upstream status is stable |

- [ ] **Step 1: Update App.tsx health interval**

In `ui/src/App.tsx` line 94, change:
```typescript
const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth, refetchInterval: 10000 })
```
to:
```typescript
const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth, refetchInterval: 30000 })
```

- [ ] **Step 2: Update Dashboard.tsx intervals**

In `ui/src/components/Dashboard.tsx`:

Line 28 — change `refetchInterval: 30000` to `refetchInterval: 60000`
Line 40 — change `refetchInterval: 30000` to `refetchInterval: 60000`
Line 46 — change `refetchInterval: 60000` to `refetchInterval: 120000`

- [ ] **Step 3: Update HostResourcesSection.tsx**

Change `refetchInterval: 30000` to `refetchInterval: 60000`

- [ ] **Step 4: Update CertificateList.tsx**

Change `refetchInterval: 15000` to `refetchInterval: 120000`

- [ ] **Step 5: Update BackupManager.tsx**

Change `refetchInterval: 15000` to `refetchInterval: 60000`

- [ ] **Step 6: Update BotFilterLogs.tsx**

Change all `refetchInterval: 15000` to `refetchInterval: 30000`
Change all `refetchInterval: 30000` to `refetchInterval: 60000`

- [ ] **Step 7: Update ExploitBlockLogs.tsx**

Change `refetchInterval: 15000` to `refetchInterval: 30000`
Change `refetchInterval: 30000` to `refetchInterval: 60000`

- [ ] **Step 8: Update LogViewer.tsx and SystemLogViewer.tsx**

In both files, change the stats query `refetchInterval: 30000` to `refetchInterval: 60000`.
Keep the auto-refresh log query interval unchanged (user-controlled).

- [ ] **Step 9: Update BannedIPList.tsx**

Change `refetchInterval: 30000` to `refetchInterval: 60000`

- [ ] **Step 10: Update BanHistoryTab.tsx**

Change `refetchInterval: 30000` to `refetchInterval: 60000`
Change `refetchInterval: 60000` to `refetchInterval: 120000`

- [ ] **Step 11: Update URIBlockManager.tsx**

Change all three `refetchInterval: 30000` to `refetchInterval: 60000`

- [ ] **Step 12: Update GeoIPSettings.tsx and ChallengeSettings.tsx**

Change `refetchInterval: 30000` to `refetchInterval: 60000` in both files.

- [ ] **Step 13: Update UpstreamPanel.tsx**

Change `refetchInterval: 30000` to `refetchInterval: 60000`

- [ ] **Step 14: Commit**

```bash
git add ui/src/App.tsx ui/src/components/
git commit -m "perf: reduce polling intervals across all components (~50% API call reduction)"
```

---

### Task 5: Implement route-level code splitting in App.tsx

**Files:**
- Modify: `ui/src/App.tsx` (lines 1-44 imports, lines 353-388 routes, lines 459-789 page wrappers)
- Create: `ui/src/pages/CertificatesPage.tsx`
- Create: `ui/src/pages/WAFPage.tsx`
- Create: `ui/src/pages/LogsPage.tsx`
- Create: `ui/src/pages/SettingsPage.tsx`

The strategy:
1. Extract the 4 Page wrapper components (CertificatesPage, WAFPage, LogsPage, SettingsPage) from App.tsx into separate files under `ui/src/pages/`
2. Each Page wrapper imports its own heavy components — these naturally become separate chunks
3. Convert remaining direct component imports in App.tsx to React.lazy()
4. The shell (navigation, auth) stays in App.tsx and loads instantly

Components that stay synchronous (needed for app shell):
- Login, InitialSetup, ErrorBoundary (auth flow)
- Dashboard (default landing page — loads on first navigation)

Components that become lazy:
- ProxyHostList, ProxyHostForm (proxy tab)
- RedirectHostManager (redirects tab)
- AccessListManager (access tab)
- CertificatesPage (certificates tab — already wraps 3 sub-components)
- WAFPage (WAF tab — wraps 6 sub-components)
- LogsPage (logs tab — wraps 7 sub-components)
- SettingsPage (settings tab — wraps 10 sub-components)
- AccountSettings, SyncProgressModal (modals, infrequent)

- [ ] **Step 1: Create ui/src/pages/ directory**

```bash
mkdir -p ui/src/pages
```

- [ ] **Step 2: Extract CertificatesPage to its own file**

Create `ui/src/pages/CertificatesPage.tsx` with the full content of the CertificatesPage function from App.tsx (lines 459-504), including its own imports:

```typescript
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import CertificateList from '../components/CertificateList'
import CertificateHistoryList from '../components/CertificateHistory'
import DNSProviderList from '../components/DNSProviderList'

export default function CertificatesPage({ subTab }: { subTab: 'certificates' | 'history' | 'dns-providers' }) {
  // ... exact copy of the function body from App.tsx lines 460-504
}
```

- [ ] **Step 3: Extract WAFPage to its own file**

Create `ui/src/pages/WAFPage.tsx` — copy the WAFPage function from App.tsx (lines 506-581) with its own imports:

```typescript
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { WAFSettings } from '../components/WAFSettings'
import { ExploitBlockRules } from '../components/ExploitBlockRules'
import { Fail2banManagement } from '../components/Fail2banManagement'
import { BannedIPList } from '../components/BannedIPList'
import { URIBlockManager } from '../components/URIBlockManager'
import { WAFTester } from '../components/WAFTester'

export default function WAFPage({ subTab }: { subTab: 'settings' | 'tester' | 'banned-ips' | 'uri-blocks' | 'exploit-rules' | 'fail2ban' }) {
  // ... exact copy of function body from App.tsx lines 507-581
}
```

- [ ] **Step 4: Extract LogsPage to its own file**

Create `ui/src/pages/LogsPage.tsx` — copy the LogsPage function from App.tsx (lines 583-674) with its own imports:

```typescript
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { LogViewer } from '../components/LogViewer'
import { SystemLogViewer } from '../components/SystemLogViewer'
import AuditLog from '../components/AuditLog'
import BotFilterLogs from '../components/BotFilterLogs'
import ExploitBlockLogs from '../components/ExploitBlockLogs'
import RawLogFiles from '../components/RawLogFiles'

export default function LogsPage({ subTab }: { subTab: 'access' | 'waf-events' | 'bot-filter' | 'exploit-blocks' | 'system' | 'audit' | 'raw-files' }) {
  // ... exact copy of function body from App.tsx lines 584-674
}
```

- [ ] **Step 5: Extract SettingsPage to its own file**

Create `ui/src/pages/SettingsPage.tsx` — copy the SettingsPage function from App.tsx (lines 676-789) with its own imports:

```typescript
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import GlobalSettings from '../components/GlobalSettings'
import ChallengeSettings from '../components/ChallengeSettings'
import GeoIPSettings from '../components/GeoIPSettings'
import SSLACMESettings from '../components/SSLACMESettings'
import MaintenanceSettings from '../components/MaintenanceSettings'
import BackupManager from '../components/BackupManager'
import BotFilterSettings from '../components/BotFilterSettings'
import WAFAutoBanSettings from '../components/WAFAutoBanSettings'
import SystemLogSettings from '../components/SystemLogSettings'
import FilterSubscriptionList from '../components/FilterSubscriptionList'

export default function SettingsPage({ subTab }: { subTab: 'global' | 'captcha' | 'geoip' | 'ssl' | 'maintenance' | 'backups' | 'botfilter' | 'waf-auto-ban' | 'system-logs' | 'filter-subscriptions' }) {
  // ... exact copy of function body from App.tsx lines 677-789
}
```

- [ ] **Step 6: Rewrite App.tsx imports — remove synchronous imports, add React.lazy**

Replace the entire import block (lines 1-44) of App.tsx. Remove all component imports that are now lazy-loaded. The new imports section:

```typescript
import { useState, useEffect, lazy, Suspense } from 'react'
import { useTranslation } from 'react-i18next'
import { BrowserRouter, Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import ErrorBoundary from './components/ErrorBoundary'
import { Login } from './components/Login'
import { InitialSetup } from './components/InitialSetup'
import { getAuthStatus, logout, getToken, User } from './api/auth'
import { apiPost } from './api/client'
import type { ProxyHost } from './types/proxy-host'
import { useDarkMode } from './hooks/useDarkMode'
import { SyncProgressModal, SyncAllResult } from './components/SyncProgressModal'

// Lazy-loaded route components
const Dashboard = lazy(() => import('./components/Dashboard'))
const ProxyHostList = lazy(() => import('./components/ProxyHostList').then(m => ({ default: m.ProxyHostList })))
const ProxyHostForm = lazy(() => import('./components/ProxyHostForm').then(m => ({ default: m.ProxyHostForm })))
const RedirectHostManager = lazy(() => import('./components/RedirectHostManager'))
const AccessListManager = lazy(() => import('./components/AccessListManager'))
const AccountSettings = lazy(() => import('./components/AccountSettings'))
const CertificatesPage = lazy(() => import('./pages/CertificatesPage'))
const WAFPage = lazy(() => import('./pages/WAFPage'))
const LogsPage = lazy(() => import('./pages/LogsPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
```

Note: ProxyHostList and ProxyHostForm use named exports, so we need `.then(m => ({ default: m.X }))` to make them compatible with React.lazy.

- [ ] **Step 7: Remove the 4 Page wrapper functions from App.tsx**

Delete lines 459-789 (CertificatesPage, WAFPage, LogsPage, SettingsPage function bodies) since they're now in separate files.

- [ ] **Step 8: Wrap Routes content in Suspense**

In the AppContent function, wrap the `<Routes>` block with a Suspense boundary:

```typescript
<main className="flex-1 max-w-7xl mx-auto px-4 py-8 w-full">
  <Suspense fallback={
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
    </div>
  }>
    <Routes>
      {/* ... all routes unchanged ... */}
    </Routes>
  </Suspense>
</main>
```

- [ ] **Step 9: Verify named exports compatibility**

Check that these components have default exports (required for simple React.lazy):
```bash
grep "export default" ui/src/components/Dashboard.tsx ui/src/components/RedirectHostManager.tsx ui/src/components/AccessListManager.tsx ui/src/components/AccountSettings.tsx
```

For any that use named exports only (like ProxyHostList), the `.then()` wrapper in Step 6 handles it.

- [ ] **Step 10: Build and verify chunk splitting**

```bash
cd ui && npx vite build 2>&1
ls -lh dist/assets/
```
Expected: Multiple JS chunks instead of single 2.1MB file. Main chunk should be ~800KB or less.

- [ ] **Step 11: Commit**

```bash
git add ui/src/App.tsx ui/src/pages/
git commit -m "perf: implement route-level code splitting with React.lazy"
```

---

### Task 6: Build, deploy to E2E, and run full test suite

- [ ] **Step 1: Build both API and UI for E2E environment**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api ui
```

- [ ] **Step 2: Restart E2E environment**

```bash
sudo docker compose -f docker-compose.e2e-test.yml up -d
```

Wait for all containers to be healthy.

- [ ] **Step 3: Run full E2E test suite**

```bash
cd test/e2e && npx playwright test
```

Expected: 447+ tests pass (same as before optimization). Any new failures must be investigated — they indicate a regression from the changes.

- [ ] **Step 4: Verify bundle size reduction**

```bash
ls -lh ui/dist/assets/*.js | head -10
du -sh ui/dist/
```

Expected:
- Main JS chunk: ~600-900KB (down from 2.1MB)
- Multiple lazy chunks (100-400KB each)
- No .map files in dist/
- Total dist size significantly reduced

- [ ] **Step 5: Take screenshot of the app for visual verification**

```bash
NODE_PATH=/usr/lib/node_modules node -e "
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  await page.goto('https://localhost:18181', { waitUntil: 'networkidle', timeout: 30000, ignoreHTTPSErrors: true });
  await page.screenshot({ path: '/tmp/optimized-app.png' });
  await browser.close();
})();
"
```

Verify the screenshot shows the app loading correctly (no blank page, no errors).

- [ ] **Step 6: Commit all changes and push to PR**

```bash
git push
```

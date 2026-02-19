# NginxProxyGuard - Architecture Specification

> **Version**: 2.1.0 | **Last Updated**: 2026-02-19
> 이 문서는 Claude Code가 개발 시 참조하는 프로젝트 아키텍처 명세서입니다.
> 새 기능 추가, 버그 수정, 리팩토링 시 이 문서를 기준으로 작업합니다.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Backend Architecture (Go)](#2-backend-architecture-go)
3. [Frontend Architecture (React)](#3-frontend-architecture-react)
4. [Infrastructure](#4-infrastructure)
5. [Database Schema](#5-database-schema)
6. [API Endpoint Catalog](#6-api-endpoint-catalog)
7. [Data Models](#7-data-models)
8. [Feature Specifications](#8-feature-specifications)
9. [Security Architecture](#9-security-architecture)
10. [Development Guide](#10-development-guide)

---

## 1. System Overview

### 1.1 Tech Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Proxy | Nginx + ModSecurity v3 + OWASP CRS | 1.28.0 / 3.0.14 / 4.21.0 |
| Backend | Go (Echo v4) | 1.24 / v4.12.0 |
| Frontend | React + TypeScript + Vite + TailwindCSS | 18.3 / 5.6 / 6.0 / 3.4 |
| Database | TimescaleDB (PostgreSQL 17) | 17-pg17 |
| Cache | Valkey (Redis-compatible) | 8-alpine |

### 1.2 Data Flow

```
[Browser] → [UI (React/Nginx:443)] → [API (Go Echo:8080)] → [PostgreSQL]
                                              ↓
                                    [Nginx Config 생성]
                                              ↓
                                    [nginx -t 테스트]
                                              ↓
                                    [nginx -s reload]
                                              ↓
                                    [Nginx Proxy (ModSecurity)]
```

### 1.3 Core Principles

1. **DB = Nginx State** — DB 변경 → config 생성 → nginx -t → reload
2. **Fail-Safe** — `nginx -t` 실패 시 reload 절대 금지, 이전 config 유지
3. **Atomic File Write** — temp file → fsync → rename (중간 상태 없음)
4. **Global Mutex** — 모든 nginx 작업은 `globalNginxMutex`로 직렬화
5. **Graceful Degradation** — Redis 없이도 동작 (캐시만 비활성)

### 1.4 Docker Services

| Service | Container | Port | Image | Network |
|---------|-----------|------|-------|---------|
| db | npg-db | 5432 (내부) | timescale/timescaledb:latest-pg17 | bridge |
| valkey | npg-valkey | 6379 (내부) | valkey/valkey:8-alpine | bridge |
| api | npg-api | 127.0.0.1:9080→8080 | svrforum/nginxproxyguard-api | bridge |
| ui | npg-ui | 81→443 | svrforum/nginxproxyguard-ui | bridge |
| nginx | npg-proxy | 80, 443 | svrforum/nginxproxyguard-nginx | **host** |

### 1.5 Volume Sharing (Critical)

```
npg_nginx_data (/etc/nginx)
  ← API: config 파일 쓰기 (.conf, WAF, certs)
  → Nginx: config 파일 읽기

생성 파일:
  /etc/nginx/conf.d/{domain}.conf       ← proxy host config
  /etc/nginx/modsec/host_{id}.conf      ← per-host WAF config
  /etc/nginx/conf.d/zzz_default.conf    ← catch-all server
  /etc/nginx/conf.d/banned_ips.conf     ← IP ban list
  /etc/nginx/certs/{certID}/            ← SSL certificates
```

---

## 2. Backend Architecture (Go)

### 2.1 Directory Structure

```
api/
├── cmd/server/main.go              # DI 조립, 라우트 등록, 서버 시작
├── internal/
│   ├── config/
│   │   ├── config.go               # Config struct, Load() from env
│   │   └── constants.go            # AppVersion, 모든 상수
│   ├── database/
│   │   ├── database.go             # DB 풀 (25 open, 5 idle, 5min lifetime)
│   │   ├── migration.go            # 마이그레이션 실행기
│   │   └── migrations/             # SQL 파일 (001_init.sql + 보조)
│   ├── handler/                    # 18 핸들러 파일
│   ├── middleware/                  # auth.go, api_token.go, rate_limit.go
│   ├── model/                      # 22 모델 파일
│   ├── nginx/                      # 7 파일: config 생성 엔진
│   ├── repository/                 # 28 레포지토리 파일
│   ├── scheduler/                  # 4 스케줄러 파일
│   ├── service/                    # 19 서비스 파일
│   └── util/query.go              # SQL 유틸리티
├── pkg/
│   ├── acme/acme.go               # Let's Encrypt ACME (lego v4)
│   └── cache/redis.go             # Valkey/Redis 래퍼
└── tests/integration/
```

### 2.2 Layer Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Handler Layer (18 files)                                │ ← 요청 파싱, 응답, 에러 분류
│  Echo Context → Bind → Service call → classifyError     │
├─────────────────────────────────────────────────────────┤
│  Service Layer (19 files)                                │ ← 비즈니스 로직, 다중 repo 조합
│  Data Aggregation → Config Generation → Test → Reload   │
├─────────────────────────────────────────────────────────┤
│  Repository Layer (28 files)                             │ ← SQL, pq.Array, sql.Null*
│  DB + Optional Redis cache via SetCache()               │
├─────────────────────────────────────────────────────────┤
│  Nginx Manager (7 files)                                 │ ← 템플릿 렌더링, atomic write
│  globalNginxMutex → writeFileAtomic → nginx -t → reload │
├─────────────────────────────────────────────────────────┤
│  Database (TimescaleDB) + Cache (Valkey)                 │
└─────────────────────────────────────────────────────────┘
```

### 2.3 Dependency Injection (main.go 조립 순서)

```
config.Load()
  → database.New() + cache.NewRedisClient()
    → nginx.NewManager()
      → 28 Repositories 생성 (db 주입)
        → Cache 주입 (proxyHostRepo, globalSettingsRepo, systemSettingsRepo, exploitBlockRuleRepo)
          → Services 생성 (repos + nginxManager 주입)
            → Cross-service Callback 연결
              → Startup: SyncAllConfigs() + GenerateDefaultServerConfig()
                → Background Services: logCollector, wafAutoBan, fail2ban, statsCollector, dockerLogCollector, cloudProvider, geoIP
                  → Handlers 생성 (services 주입)
                    → Schedulers: renewal(6h), partition, logRotate, backup
                      → Echo 라우트 등록 + 미들웨어
                        → Graceful Shutdown (SIGINT/SIGTERM)
```

### 2.4 Handler Pattern

```go
// 구조체: service 주입
type ProxyHostHandler struct {
    service *service.ProxyHostService
    audit   *service.AuditService
}

func (h *ProxyHostHandler) Create(c echo.Context) error {
    var req model.CreateProxyHostRequest
    if err := c.Bind(&req); err != nil {
        return badRequestError(c, "Invalid request body")
    }
    host, err := h.service.Create(c.Request().Context(), &req)
    if err != nil {
        return classifyError(c, "create proxy host", err)
    }
    auditCtx := service.ContextWithAudit(c.Request().Context(), c)
    h.audit.LogProxyHostCreate(auditCtx, req.DomainNames, destination)
    return createdResponse(c, host)
}
```

**Error Classification:**

| Function | HTTP Status | Usage |
|----------|-------------|-------|
| `badRequestError(c, msg)` | 400 | 잘못된 입력 |
| `unauthorizedError(c)` | 401 | 인증 실패 |
| `forbiddenError(c)` | 403 | 권한 없음 |
| `notFoundError(c, resource)` | 404 | 리소스 없음 |
| `conflictError(c, msg)` | 409 | 중복 |
| `internalError(c, op, err)` | 500 | 내부 오류 |
| `createdResponse(c, data)` | 201 | 생성 성공 |
| `noContentResponse(c)` | 204 | 삭제 성공 |

### 2.5 Service Pattern (ProxyHostService 핵심)

```go
type ProxyHostService struct {
    repo                 *repository.ProxyHostRepository
    wafRepo              *repository.WAFRepository
    accessListRepo       *repository.AccessListRepository
    geoRepo              *repository.GeoRepository
    rateLimitRepo        *repository.RateLimitRepository
    securityHeadersRepo  *repository.SecurityHeadersRepository
    botFilterRepo        *repository.BotFilterRepository
    upstreamRepo         *repository.UpstreamRepository
    systemSettingsRepo   *repository.SystemSettingsRepository
    cloudProviderRepo    *repository.CloudProviderRepository
    globalSettingsRepo   *repository.GlobalSettingsRepository
    uriBlockRepo         *repository.URIBlockRepository
    exploitBlockRuleRepo *repository.ExploitBlockRuleRepository
    certificateRepo      *repository.CertificateRepository
    nginx                NginxManager     // 인터페이스 (순환참조 방지)
    certService          CertificateCreator
}

// 핵심 흐름: DB Update → Data Aggregation → Config Gen → Test → Reload
func (s *ProxyHostService) Update(ctx, id, req) (*model.ProxyHost, error) {
    host, _ := s.repo.Update(ctx, id, req)
    configData, _ := s.getHostConfigData(ctx, host)       // 12개 repo에서 데이터 조합
    wafExcl, _ := s.getMergedWAFExclusions(ctx, id)        // Global + Host WAF 병합
    s.nginx.GenerateConfigAndReload(ctx, *configData, wafExcl)
    return host, nil
}
```

**Cross-Service Callback (순환참조 방지):**
```go
// main.go에서 연결
certService.SetCertificateReadyCallback(func(ctx, certID) error {
    return proxyHostService.RegenerateConfigsForCertificate(ctx, certID)
})
cloudProviderService.SetIPRangesUpdatedCallback(func(ctx, providers) error {
    return proxyHostService.RegenerateConfigsForCloudProviders(ctx, providers)
})
```

### 2.6 Repository Pattern

```go
type ProxyHostRepository struct {
    db    *database.DB
    cache *cache.RedisClient  // 선택적, SetCache()로 주입
}

// SQL Null 처리 헬퍼
FromNullString(sql.NullString) *string
ToNullString(s *string) sql.NullString

// PostgreSQL 배열
pq.Array(req.DomainNames)         // 쓰기
var domainNames pq.StringArray    // 읽기
```

**Cache 지원 Repos:** ProxyHostRepository, GlobalSettingsRepository, SystemSettingsRepository, ExploitBlockRuleRepository

### 2.7 Repository Inventory

| File | Repository | Key Methods |
|------|-----------|-------------|
| `proxy_host.go` | ProxyHostRepository | Create, GetByID, GetByDomain, List, Update, Delete, GetByCertificateID, ToggleFavorite |
| `certificate.go` | CertificateRepository | Create, GetByID, List, Update, Delete, GetExpiringSoon, GetByDomainNames |
| `waf.go` | WAFRepository | GetHostConfig, GetGlobalExclusions, CreateExclusion, DeleteExclusion |
| `access_list.go` | AccessListRepository | Create, GetByID, List, Update, Delete |
| `geo.go` | GeoRepository | GetByProxyHost, Create, Update, Delete |
| `rate_limit.go` | RateLimitRepository | Get, Upsert, Delete, GetFail2ban, UpsertFail2ban, ListBannedIPs, BanIP, UnbanIP |
| `bot_filter.go` | BotFilterRepository | Get, Upsert, Delete, GetKnownBots |
| `security_headers.go` | SecurityHeadersRepository | Get, Upsert, Delete |
| `upstream.go` | UpstreamRepository | Get, Upsert, Delete, GetHealthStatus |
| `log.go` | LogRepository | Create, List, GetStats, GetSettings, Cleanup, GetDistinct* (6) |
| `redirect_host.go` | RedirectHostRepository | Create, GetByID, List, Update, Delete |
| `dns_provider.go` | DNSProviderRepository | Create, GetByID, GetDefault, List, Update, Delete |
| `global_settings.go` | GlobalSettingsRepository | Get, Update, Reset |
| `system_settings.go` | SystemSettingsRepository | Get, Update |
| `dashboard.go` | DashboardRepository | GetSummary, GetHourlyStats, GetGeoIPStats, GetSystemHealth |
| `auth.go` | AuthRepository | GetUserByUsername, CreateSession, ValidateToken, 2FA methods |
| `api_token.go` | APITokenRepository | Create, GetByHash, ListByUser, Revoke, LogUsage |
| `audit_log.go` | AuditLogRepository | Create, List |
| `challenge.go` | ChallengeRepository | GetConfig, CreateToken, ValidateToken |
| `cloud_provider.go` | CloudProviderRepository | GetBySlug, List, UpdateIPRanges, GetBlockedForHost |
| `uri_block.go` | URIBlockRepository | Get, Upsert, GetGlobal, UpdateGlobal |
| `exploit_block_rule.go` | ExploitBlockRuleRepository | List, Create, Update, Delete, Toggle, Exclusions |
| `system_log.go` | SystemLogRepository | Create, List, GetStats, Cleanup |
| `backup.go` | BackupRepository | Create, GetByID, List, Delete |
| `backup_export.go` | - | ExportAllData (full DB export) |
| `backup_import.go` | - | ImportAllData (full DB import) |
| `ip_ban_history.go` | IPBanHistoryRepository | Create, List, GetByIP, GetStats |

### 2.8 Nginx Manager

```go
type Manager struct {
    configPath     string   // /etc/nginx/conf.d
    certsPath      string   // /etc/nginx/certs
    modsecPath     string   // /etc/nginx/modsec
    nginxContainer string   // docker container name
    httpPort       string   // default "80"
    httpsPort      string   // default "443"
}
var globalNginxMutex sync.Mutex

// Config 생성 흐름
GenerateConfigAndReload(ctx, data, wafExclusions):
  Lock(globalNginxMutex)
  → GenerateConfigFull(ctx, data)           // domain.conf 생성
  → GenerateHostWAFConfig(ctx, host, excl)  // modsec/host_{id}.conf 생성
  → testAndReloadNginx(ctx)                 // nginx -t → nginx -s reload
  Unlock()

// Atomic File Write
writeFileAtomic(path, data, perm):
  MkdirAll → CreateTemp → Write → Sync → Chmod → Rename
```

**생성 파일:**

| File | Path | Trigger |
|------|------|---------|
| `{domain}.conf` | conf.d/ | ProxyHost create/update |
| `host_{id}.conf` | modsec/ | WAF enabled |
| `zzz_default.conf` | conf.d/ | Default server config |
| `banned_ips.conf` | conf.d/ | IP ban/unban |
| `redirect_{domain}.conf` | conf.d/ | RedirectHost create/update |

### 2.9 Middleware Chain

```
Global: Logger → Recover → CORS → Secure → RateLimiter(100 req/s)
API v1: APIRateLimit(100 req/min)
Protected: APITokenAuth → AuthMiddleware → Handler
```

- **AuthMiddleware**: Bearer 토큰 → authService.ValidateToken() → user context
- **APITokenAuth**: X-API-Token 헤더 → hash 검증 → IP 검증 → permission 검증
- **OptionalAuthMiddleware**: 인증 선택적 (공개 엔드포인트)

### 2.10 Schedulers

| Scheduler | Interval | Role |
|-----------|----------|------|
| RenewalScheduler | 6시간 | SSL 만료 30일 전 자동 갱신 |
| PartitionScheduler | 월별 | 로그 파티션 생성/삭제 |
| LogRotateScheduler | 일간 | nginx raw 로그 회전 |
| BackupScheduler | cron | 자동 백업 (DB + config + certs) |
| StatsCollector | 30초 | 대시보드 통계 수집 |
| LogCollector | 실시간 | nginx 로그 수집/파싱/GeoIP 보강 |
| WAFAutoBanService | 실시간 | WAF 이벤트 기반 IP 자동 차단 |
| Fail2banService | 실시간 | HTTP 에러 코드 기반 IP 차단 |
| CloudProviderService | 주기적 | 클라우드 IP 범위 업데이트 |
| GeoIPScheduler | 설정 | MaxMind DB 자동 업데이트 |
| DockerLogCollector | 실시간 | Docker 컨테이너 로그 수집 |

### 2.11 Key Constants

```go
const AppVersion = "2.1.0"

// Timeouts
HTTPClientTimeout       = 30s
NginxReloaderDebounce   = 2s
ContextTimeout          = 30s

// Security
WAFAutoBanWindowSeconds = 300
MaxWAFRulesLimit        = 10000
DefaultRPS              = 10
DefaultBurstSize        = 20
MinParanoiaLevel        = 1
MaxParanoiaLevel        = 4
DefaultAnomalyThreshold = 5
HSTSMaxAge              = 31536000

// Auth
maxFailedAttempts       = 5
lockoutWindow           = 15min
sessionDuration         = 24h

// Cache
RedisMaxRetries         = 5
LogBatchSize            = 100
DefaultPageSize         = 20
MaxPageSize             = 100
```

### 2.12 Go Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| labstack/echo/v4 | v4.12.0 | HTTP framework |
| lib/pq | v1.10.9 | PostgreSQL driver |
| go-acme/lego/v4 | v4.20.4 | ACME client |
| redis/go-redis/v9 | v9.7.0 | Redis client |
| oschwald/geoip2-golang | v1.11.0 | GeoIP2 reader |
| google/uuid | v1.6.0 | UUID generation |
| shirou/gopsutil/v3 | v3.24.5 | System stats |
| robfig/cron/v3 | v3.0.1 | Cron scheduler |
| cloudflare/cloudflare-go | v0.108.0 | DNS provider |

---

## 3. Frontend Architecture (React)

### 3.1 Directory Structure

```
ui/src/
├── main.tsx                        # React 18 root + QueryClient + Suspense
├── App.tsx                         # Auth 상태머신 + Router + Routes
├── api/                            # API 클라이언트 (15개 모듈)
│   ├── client.ts                   # apiGet/Post/Put/Delete + ApiError
│   ├── auth.ts                     # 인증, 2FA, 토큰
│   ├── proxy-hosts.ts              # 프록시 호스트 CRUD
│   ├── certificates.ts             # 인증서 관리
│   ├── security.ts                 # 보안 기능 (rate limit, fail2ban, bot filter, etc.)
│   ├── waf.ts                      # WAF 규칙
│   ├── waf-test.ts                 # WAF 테스트
│   ├── logs.ts                     # 로그 조회
│   ├── system-logs.ts              # 시스템 로그
│   ├── settings.ts                 # 설정 + 대시보드 + 백업
│   ├── access.ts                   # 접근 목록 + 리다이렉트 + GeoIP
│   ├── dns-providers.ts            # DNS 프로바이더
│   ├── challenge.ts                # CAPTCHA
│   ├── exploit-rules.ts            # 익스플로잇 규칙
│   ├── api-tokens.ts               # API 토큰
│   └── docker.ts                   # Docker 컨테이너 조회
├── types/                          # TypeScript 타입 (8개)
│   ├── proxy-host.ts, waf.ts, log.ts, security.ts
│   ├── certificate.ts, settings.ts, access.ts, exploit-rules.ts
├── components/                     # 170+ 컴포넌트 파일
│   ├── common/HelpTip.tsx          # 포털 기반 툴팁
│   ├── proxy-host/                 # 프록시 호스트 폼 (탭 기반)
│   │   ├── ProxyHostForm.tsx       # 메인 모달 (374줄)
│   │   ├── hooks/useProxyHostForm.ts # 폼 로직 (665줄)
│   │   ├── tabs/                   # Basic, SSL, Security, Protection, Performance, Advanced
│   │   └── tabs/security/          # WAF, BotFilter, GeoIP, URIBlock, CloudProvider
│   ├── log-viewer/                 # 로그 뷰어 (badges, charts, filters, modals)
│   ├── exploit-rules/              # 익스플로잇 규칙
│   └── ...                         # 50+ top-level 컴포넌트
├── hooks/
│   ├── useDarkMode.ts              # 다크모드 (localStorage 'theme')
│   └── useEscapeKey.ts             # ESC 키 이벤트
└── i18n/
    ├── index.ts                    # i18next 설정
    ├── hooks/useLanguage.ts        # 언어 전환 훅
    └── locales/{ko,en}/            # 각 16개 JSON
```

### 3.2 Auth State Machine

```
AuthState: 'loading' | 'unauthenticated' | 'authenticated' | 'initial-setup'

App mount → getToken() → if none → 'unauthenticated' → <Login />
                        → if token → getAuthStatus() API call
                          → is_initial_setup → <InitialSetup />
                          → authenticated → <AppContent /> (BrowserRouter)
                          → error → 'unauthenticated'
```

### 3.3 Route Map

| Path | Component | Tab Color |
|------|-----------|-----------|
| `/dashboard` | Dashboard | primary |
| `/proxy-hosts` | ProxyHostList | primary |
| `/redirects` | RedirectHostManager | primary |
| `/certificates/list` | CertificatesPage | primary |
| `/certificates/history` | CertificatesPage | primary |
| `/certificates/dns-providers` | CertificatesPage | primary |
| `/waf/settings` | WAFPage | orange |
| `/waf/banned-ips` | WAFPage | red |
| `/waf/uri-blocks` | WAFPage | rose |
| `/waf/tester` | WAFPage | purple |
| `/waf/exploit-rules` | WAFPage | amber |
| `/waf/fail2ban` | WAFPage | red |
| `/access/lists` | AccessListManager | purple |
| `/logs/access` | LogsPage | primary |
| `/logs/waf-events` | LogsPage | orange |
| `/logs/bot-filter` | LogsPage | purple |
| `/logs/exploit-blocks` | LogsPage | red |
| `/logs/system` | LogsPage | indigo |
| `/logs/audit` | LogsPage | emerald |
| `/logs/raw-files` | LogsPage | amber |
| `/settings/global` | SettingsPage | teal |
| `/settings/captcha` | SettingsPage | blue |
| `/settings/geoip` | SettingsPage | emerald |
| `/settings/ssl` | SettingsPage | amber |
| `/settings/maintenance` | SettingsPage | purple |
| `/settings/backups` | SettingsPage | indigo |
| `/settings/botfilter` | SettingsPage | orange |
| `/settings/waf-auto-ban` | SettingsPage | red |
| `/settings/system-logs` | SettingsPage | indigo |

### 3.4 State Management

| Area | Technology | Usage |
|------|-----------|-------|
| Server Data | React Query | API 데이터, 캐싱, 자동 갱신 |
| Form State | useState | 입력값, 유효성 에러 |
| UI State | useState | 모달, 탭, 로딩 |
| Auth | localStorage + React Query | 토큰 (`npg_token`) |
| Theme | localStorage (`theme`) + useDarkMode | dark/light |
| Language | localStorage (`npg_language`) + useLanguage | ko/en |

**React Query Config:**
```ts
const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5000, retry: 1 } }
})
// Dashboard: refetchInterval: 30000 (30초)
// Container stats: refetchInterval: 15000 (15초)
// Health: refetchInterval: 10000 (10초)
```

### 3.5 API Client

```ts
class ApiError extends Error { status: number; details?: string }

apiGet<T>(url): Promise<T>
apiPost<T>(url, data?): Promise<T>
apiPut<T>(url, data): Promise<T>
apiDelete(url): Promise<void>

// 자동 처리:
// - Bearer 토큰 (localStorage 'npg_token')
// - 401 → clearToken() + reload (세션 만료)
// - 502/503/504 → 서버 불가 메시지
```

### 3.6 ProxyHost Form Architecture

```
ProxyHostForm.tsx (374줄, 모달)
  → useProxyHostForm.ts (665줄, 로직 훅)
  → tabs/BasicTab.tsx      ← 도메인, 포워드, WebSocket, Docker selector
  → tabs/SSLTab.tsx         ← 인증서 선택/생성, SSL 옵션
  → tabs/SecurityTab.tsx    ← WAF, Access List, 보안 서브컴포넌트
  → tabs/ProtectionTab.tsx  ← Rate Limit, Fail2ban, URI Block (편집 모드만)
  → tabs/PerformanceTab.tsx ← 캐시, 프록시 버퍼 설정
  → tabs/AdvancedTab.tsx    ← Raw nginx config
  → SaveProgressModal.tsx   ← 저장 진행 상태
```

**Submit Flow (Create):**
1. Validate form → show errors
2. SSL + cert create → create cert → poll (2s intervals, 120s timeout)
3. POST /proxy-hosts (host + nginx config + reload)
4. Save additional settings (bot filter, geo, cloud) with skip_reload=true
5. syncAllConfigs() → regenerate with all settings
6. Complete → invalidate queries → close after 800ms

### 3.7 i18n

- **Library:** i18next + react-i18next
- **Fallback:** Korean (`'ko'`)
- **Storage:** localStorage `'npg_language'`
- **Namespaces (16):** common, navigation, auth, dashboard, proxyHost, waf, logs, settings, certificates, accessControl, redirectHost, errors, exploitRules, exploitExceptions, exploitLogs, fail2ban

```tsx
const { t } = useTranslation('proxyHost')
t('form.tabs.basic')
t('common:buttons.save')  // cross-namespace
```

### 3.8 UI Patterns

**Dark Mode:** `dark:` prefix, `useDarkMode()` hook
**Modal:** `fixed inset-0 bg-black/50 backdrop-blur-sm z-50`, ESC to close
**Card:** `bg-white dark:bg-slate-800 rounded-lg shadow p-6`
**Button:** `px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50`
**Input:** `px-4 py-2.5 border border-slate-300 dark:border-slate-600 rounded-lg focus:ring-2 focus:ring-primary-500`
**Responsive:** `grid-cols-1 md:grid-cols-2 lg:grid-cols-4`
**Tooltip:** `<HelpTip contentKey="..." ns="..." />` (portal-based, smart positioning)

### 3.9 localStorage Keys

| Key | Purpose |
|-----|---------|
| `npg_token` | Auth session token |
| `npg_language` | UI 언어 (`ko` / `en`) |
| `theme` | 다크모드 (`dark` / `light`) |
| `npg_font_family` | 폰트 설정 |

---

## 4. Infrastructure

### 4.1 Environment Variables

**API Container:**

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | API listen port |
| `DATABASE_URL` | postgres://...db:5432/nginx_proxy_guard | PostgreSQL DSN |
| `REDIS_URL` | redis://valkey:6379/0 | Valkey URL |
| `JWT_SECRET` | (required) | JWT 서명 시크릿 |
| `ENVIRONMENT` | production | 환경 |
| `NGINX_CONTAINER` | npg-proxy | Nginx 컨테이너명 |
| `NGINX_SKIP_TEST` | false | nginx -t 스킵 (dev only) |
| `NGINX_HTTP_PORT` | 80 | 커스텀 HTTP 포트 |
| `NGINX_HTTPS_PORT` | 443 | 커스텀 HTTPS 포트 |
| `API_HOST_PORT` | 9080 | API 호스트 포트 |
| `BACKUP_PATH` | /app/data/backups | 백업 경로 |
| `ACME_EMAIL` | (empty) | Let's Encrypt 이메일 |
| `ACME_STAGING` | false | ACME 스테이징 |

**Nginx Container:**

| Variable | Description |
|----------|-------------|
| `MAXMIND_LICENSE_KEY` | MaxMind GeoIP 라이센스 키 |
| `MAXMIND_ACCOUNT_ID` | MaxMind 계정 ID |

### 4.2 Nginx Config Structure

```
nginx/
├── nginx.conf                  # 메인 (worker, epoll, modules, SSL, gzip, brotli)
├── conf.d/
│   ├── {domain}.conf           # API 생성: proxy host configs
│   ├── banned_ips.conf         # API 생성: IP ban list
│   └── zzz_default.conf        # API 생성: catch-all, /health, nginx_status
├── includes/
│   ├── proxy_params.conf       # 프록시 헤더 (Host, X-Real-IP, X-Forwarded-*)
│   └── block_exploits.conf     # 익스플로잇 차단 규칙 (SQLI, RFI, XSS, etc.)
├── modsec/
│   ├── main.conf               # ModSecurity blocking 모드
│   ├── detection-only.conf     # ModSecurity detection 모드
│   ├── modsec-base.conf        # 기본 설정 (body limits, audit, PCRE)
│   └── host_{id}.conf          # API 생성: per-host WAF exclusions
├── geoip/
│   └── geoip-active.conf       # symlink → enabled or disabled
└── owasp-crs/                  # OWASP CRS 4.21.0 rules
```

**Key nginx.conf Settings:**
- `worker_processes auto`, `worker_rlimit_nofile 65535`
- Dynamic modules: modsecurity, brotli, headers_more, geoip2
- Real IP: trusted RFC 1918 ranges, `X-Forwarded-For` header
- SSL: TLSv1.2 + TLSv1.3, ECDHE ciphers, OCSP stapling
- HTTP/3: `ssl_early_data on`, `quic_retry on`
- Gzip level 6 + Brotli level 6
- Proxy cache: 100m keys zone, 10g max, 60m inactive

### 4.3 Docker Build

**Nginx (multi-stage):**
- Stage 1: Alpine 3.23 → compile ModSecurity 3.0.14 + Nginx 1.28.0 + modules (brotli, headers_more, geoip2)
- Stage 2: Alpine 3.23 + runtime libs + geoipupdate + logrotate
- Entrypoint: volume init → GeoIP update → log config → nginx -t → nginx start

**API (multi-stage):**
- Stage 1: golang:1.24-alpine → `CGO_ENABLED=0` static build
- Stage 2: alpine:3.23 + ca-certs + docker-cli + geoipupdate

**UI (multi-stage):**
- Stage 1: node:22-alpine → `npm run build` (Vite)
- Stage 2: nginx:alpine → serves SPA + self-signed SSL

### 4.4 CI/CD

```
Tag push (v*) → detect changes (SHA256 per component)
  → parallel build (amd64 + arm64 native runners)
    → E2E tests (bridge mode + host mode)
      → push final images + multi-arch manifest
        → GitHub release
```

---

## 5. Database Schema

### 5.1 Extensions

- `uuid-ossp` (UUID), `pg_trgm` (trigram search), `timescaledb` (time-series)

### 5.2 Core Tables

**`proxy_hosts`** — 리버스 프록시 설정 (PK: uuid)
| Column | Type | Default | Notes |
|--------|------|---------|-------|
| domain_names | text[] | NOT NULL | GIN 인덱스 |
| forward_scheme | varchar(10) | 'http' | |
| forward_host | varchar(255) | NOT NULL | |
| forward_port | integer | 80 | |
| ssl_enabled | boolean | false | |
| ssl_force_https | boolean | false | |
| ssl_http2 | boolean | true | |
| ssl_http3 | boolean | false | |
| certificate_id | uuid | NULL | FK → certificates |
| allow_websocket_upgrade | boolean | true | |
| cache_enabled | boolean | false | |
| block_exploits | boolean | true | |
| block_exploits_exceptions | text | '' | |
| advanced_config | text | '' | |
| waf_enabled | boolean | false | |
| waf_mode | varchar(20) | 'detection' | blocking/detection |
| waf_paranoia_level | integer | 1 | CHECK 1-4 |
| waf_anomaly_threshold | integer | 5 | CHECK 1-100 |
| access_list_id | uuid | NULL | FK → access_lists |
| proxy_connect/send/read_timeout | integer | 0 | 0=global |
| client_max_body_size | varchar(20) | '' | |
| is_favorite | boolean | false | UI 즐겨찾기 (상단 고정) |
| enabled | boolean | true | |
| meta | jsonb | '{}' | |

**`certificates`** — SSL/TLS 인증서
| Column | Type | Notes |
|--------|------|-------|
| domain_names | text[] | |
| status | varchar(20) | pending/issued/expired/error/renewing |
| provider | varchar(50) | letsencrypt/custom/selfsigned |
| certificate_pem | text | Full PEM chain |
| private_key_pem | text | PEM |
| acme_account | jsonb | ACME registration |
| auto_renew | boolean | |
| expires_at | timestamptz | |

**`logs_partitioned`** — 접근 로그 (월별 파티션)
| Column | Type | Notes |
|--------|------|-------|
| log_type | log_type enum | access/error/modsec |
| host | text | 도메인 |
| client_ip | inet | |
| status_code | integer | |
| request_time | double precision | |
| geo_country_code | varchar | GeoIP |
| block_reason | block_reason enum | none/waf/bot_filter/rate_limit/... |
| bot_category | text | |
| rule_id | bigint | WAF rule ID |
| proxy_host_id | uuid | FK (SET NULL) |

### 5.3 Security Tables

| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `banned_ips` | IP 차단 | ip_address, proxy_host_id, expires_at, is_permanent |
| `access_lists` / `access_list_items` | IP 허용/차단 | directive (allow/deny), address |
| `geo_restrictions` | GeoIP 차단 | mode (whitelist/blacklist), countries[] |
| `bot_filters` | 봇 필터 | block_bad_bots, block_ai_bots, allow_search_engines |
| `rate_limits` | 속도 제한 | requests_per_second, burst_size, limit_by |
| `fail2ban_configs` | Fail2ban | max_retries, find_time, ban_time, fail_codes |
| `security_headers` | 보안 헤더 | HSTS, X-Frame-Options, CSP, etc. |
| `uri_blocks` / `global_uri_blocks` | URI 차단 | rules (JSONB), exception_ips |
| `waf_rule_exclusions` / `global_waf_rule_exclusions` | WAF 규칙 제외 | rule_id |
| `exploit_block_rules` | 익스플로잇 차단 | pattern, pattern_type, category |
| `challenge_configs` | CAPTCHA 설정 | challenge_type, site_key, secret_key |
| `cloud_providers` | 클라우드 IP 차단 | slug, ip_ranges[], ip_ranges_url |

### 5.4 Auth/Settings Tables

| Table | Purpose |
|-------|---------|
| `users` | 사용자 (bcrypt, TOTP, language, font) |
| `auth_sessions` | 세션 (token_hash, expires_at) |
| `api_tokens` | API 토큰 (hash, permissions, allowed_ips) |
| `audit_logs` | 감사 로그 |
| `global_settings` | Nginx 글로벌 설정 (단일 행) |
| `system_settings` | 시스템 설정 (단일 행) |
| `backups` | 백업 메타데이터 |

### 5.5 ENUM Types

```sql
block_reason: 'none','waf','bot_filter','rate_limit','geo_block','exploit_block',
              'banned_ip','uri_block','cloud_provider_challenge','cloud_provider_block','access_denied'
log_type: 'access','error','modsec'
system_log_level: 'debug','info','warn','error','fatal'
```

### 5.6 Migration Strategy

- 단일 파일 `001_init.sql` + Go 코드 내 보조 마이그레이션
- `schema_migrations` 테이블로 버전 추적
- 멱등성: `CREATE TABLE IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`
- TimescaleDB: 로그 테이블 hypertable 변환, 7일 압축 정책

### 5.7 Key FK Cascade Rules

| Child | Parent | On Delete |
|-------|--------|-----------|
| banned_ips, bot_filters, rate_limits, fail2ban_configs, security_headers, geo_restrictions, uri_blocks, upstreams, waf_rule_exclusions, challenge_configs | proxy_hosts | CASCADE |
| logs, ip_ban_history | proxy_hosts | SET NULL |
| proxy_hosts | certificates | SET NULL |
| proxy_hosts | access_lists | SET NULL |
| auth_sessions, api_tokens | users | CASCADE |
| certificate_history | certificates | CASCADE |

---

## 6. API Endpoint Catalog

### 6.1 Public (인증 불필요)

| Method | Path | Handler |
|--------|------|---------|
| GET | `/health` | Health check (db + cache) |
| POST | `/api/v1/auth/login` | AuthHandler.Login |
| POST | `/api/v1/auth/logout` | AuthHandler.Logout |
| GET | `/api/v1/auth/status` | AuthHandler.GetStatus |
| POST | `/api/v1/auth/verify-2fa` | AuthHandler.Verify2FA |
| GET | `/api/v1/challenge/page` | ChallengeHandler.GetChallengePage |
| POST | `/api/v1/challenge/verify` | ChallengeHandler.VerifyCaptcha |
| GET | `/api/v1/challenge/validate` | ChallengeHandler.ValidateToken |
| GET | `/api/v1/public/ui-settings` | SystemSettingsHandler.GetPublicUISettings |

### 6.2 Auth Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/auth/me` | 현재 사용자 |
| POST | `/api/v1/auth/change-credentials` | 사용자명+비밀번호 변경 |
| POST | `/api/v1/auth/change-password` | 비밀번호 변경 |
| POST | `/api/v1/auth/change-username` | 사용자명 변경 |
| GET | `/api/v1/auth/account` | 계정 정보 |
| POST | `/api/v1/auth/2fa/setup` | TOTP QR 생성 |
| POST | `/api/v1/auth/2fa/enable` | 2FA 활성화 |
| POST | `/api/v1/auth/2fa/disable` | 2FA 비활성화 |
| GET/PUT | `/api/v1/auth/language` | 언어 설정 |
| GET/PUT | `/api/v1/auth/font` | 폰트 설정 |

### 6.3 Proxy Hosts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/proxy-hosts` | 목록 (pagination, search, sort) |
| POST | `/api/v1/proxy-hosts` | 생성 |
| GET | `/api/v1/proxy-hosts/by-domain/:domain` | 도메인으로 조회 |
| POST | `/api/v1/proxy-hosts/sync` | 전체 config 동기화 |
| GET | `/api/v1/proxy-hosts/:id` | 단일 조회 |
| PUT | `/api/v1/proxy-hosts/:id` | 수정 |
| DELETE | `/api/v1/proxy-hosts/:id` | 삭제 |
| POST | `/api/v1/proxy-hosts/:id/test` | 업스트림 연결 테스트 |
| POST | `/api/v1/proxy-hosts/:id/clone` | 복제 |
| PUT | `/api/v1/proxy-hosts/:id/favorite` | 즐겨찾기 토글 (nginx reload 없음) |

### 6.4 Security (per-host)

| Method | Path | Feature |
|--------|------|---------|
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/rate-limit` | Rate Limit |
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/fail2ban` | Fail2ban |
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/bot-filter` | Bot Filter |
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/security-headers` | Security Headers |
| POST | `/api/v1/proxy-hosts/:id/security-headers/preset/:preset` | 프리셋 적용 |
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/upstream` | Upstream/LB |
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/uri-block` | URI Block |
| POST/DELETE | `/api/v1/proxy-hosts/:id/uri-block/rules(/:ruleId)` | URI Block 규칙 |
| GET/POST/PUT/DELETE | `/api/v1/proxy-hosts/:id/geo` | GeoIP 제한 |
| GET/PUT | `/api/v1/proxy-hosts/:id/blocked-cloud-providers` | 클라우드 차단 |
| GET/PUT/DELETE | `/api/v1/proxy-hosts/:id/challenge` | CAPTCHA 설정 |

### 6.5 WAF

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/waf/rules` | OWASP CRS 규칙 목록 |
| GET | `/api/v1/waf/hosts` | 전체 호스트 WAF 설정 |
| GET | `/api/v1/waf/hosts/:id/config` | 호스트 WAF 설정 |
| GET | `/api/v1/waf/hosts/:id/history` | 정책 변경 이력 |
| POST | `/api/v1/waf/hosts/:id/rules/:ruleId/disable` | 규칙 비활성화 |
| DELETE | `/api/v1/waf/hosts/:id/rules/:ruleId/disable` | 규칙 활성화 |
| GET | `/api/v1/waf/global/rules` | 글로벌 규칙 |
| POST/DELETE | `/api/v1/waf/global/rules/:ruleId/disable` | 글로벌 규칙 on/off |

### 6.6 Certificates

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/certificates` | 목록/발급 |
| POST | `/api/v1/certificates/upload` | 커스텀 업로드 |
| GET | `/api/v1/certificates/expiring` | 만료 예정 |
| GET | `/api/v1/certificates/history` | 이력 |
| GET/DELETE | `/api/v1/certificates/:id` | 조회/삭제 |
| PUT | `/api/v1/certificates/:id/upload` | 업데이트 |
| POST | `/api/v1/certificates/:id/renew` | 갱신 |
| GET | `/api/v1/certificates/:id/logs` | 발급 로그 |
| GET | `/api/v1/certificates/:id/download` | 다운로드 |

### 6.7 Global Features

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/api/v1/banned-ips` | IP 차단 목록/추가 |
| DELETE | `/api/v1/banned-ips/:id` | IP 차단 해제 |
| GET | `/api/v1/banned-ips/history(/stats/ip/:ip)` | 차단 이력 |
| GET/PUT | `/api/v1/global-uri-block` | 글로벌 URI 차단 |
| POST/DELETE | `/api/v1/global-uri-block/rules(/:ruleId)` | 글로벌 URI 규칙 |
| GET/POST | `/api/v1/exploit-rules` | 익스플로잇 규칙 |
| GET/PUT/DELETE | `/api/v1/exploit-rules/:id` | 규칙 CRUD |
| POST | `/api/v1/exploit-rules/:id/toggle` | 활성/비활성 |
| GET/PUT | `/api/v1/challenge-config` | 글로벌 CAPTCHA |
| GET/POST | `/api/v1/cloud-providers` | 클라우드 프로바이더 |

### 6.8 Dashboard & Settings

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/dashboard` | 대시보드 요약 |
| GET | `/api/v1/dashboard/health(/history)` | 시스템 헬스 |
| GET | `/api/v1/dashboard/stats/hourly` | 시간별 통계 |
| GET | `/api/v1/dashboard/containers` | Docker 상태 |
| GET | `/api/v1/docker/containers` | Docker 컨테이너 목록 |
| GET/PUT | `/api/v1/settings` | 글로벌 nginx 설정 |
| POST | `/api/v1/settings/reset` | 설정 초기화 |
| GET/PUT | `/api/v1/system-settings` | 시스템 설정 |
| GET/POST | `/api/v1/backups` | 백업 목록/생성 |
| POST | `/api/v1/backups/:id/restore` | 백업 복원 |

### 6.9 Logs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/logs` | 로그 조회 (30+ 필터) |
| GET | `/api/v1/logs/stats` | 통계 |
| GET | `/api/v1/logs/autocomplete/{hosts,ips,user-agents,countries,uris,methods}` | 자동완성 |
| GET | `/api/v1/system-logs` | 시스템 로그 |
| GET | `/api/v1/audit-logs` | 감사 로그 |

---

## 7. Data Models

### 7.1 Request/Response Pattern

```go
// Create: 필수 필드는 일반 타입
type CreateProxyHostRequest struct {
    DomainNames []string; ForwardScheme string; ForwardHost string; ForwardPort int
}
// Update: 선택 필드는 포인터 (nil = 변경 없음)
type UpdateProxyHostRequest struct {
    DomainNames *[]string; ForwardScheme *string; ForwardHost *string
}
// List Response: 페이지네이션 포함
type ProxyHostListResponse struct {
    Data []ProxyHost; Total int; Page int; PerPage int; TotalPages int
}
```

### 7.2 Key TypeScript Interfaces

```ts
// ProxyHost
interface ProxyHost {
  id, domain_names[], forward_scheme, forward_host, forward_port
  ssl_enabled, ssl_force_https, ssl_http2, ssl_http3, certificate_id?
  waf_enabled, waf_mode, waf_paranoia_level, waf_anomaly_threshold
  cache_enabled, block_exploits, access_list_id?, is_favorite, enabled
  proxy_connect_timeout?, proxy_send_timeout?, proxy_read_timeout?
  client_max_body_size?, advanced_config?
  created_at, updated_at
}

// Log (30+ fields)
interface Log {
  id, log_type, timestamp, host?, client_ip?
  geo_country_code?, geo_city?, geo_asn?
  request_method?, request_uri?, status_code?
  block_reason?, bot_category?, exploit_rule?
  rule_id?, rule_message?, rule_severity?
}

// Security types: RateLimit, Fail2banConfig, BannedIP, BotFilter,
// SecurityHeaders, Upstream, URIBlock, GeoRestriction
```

---

## 8. Feature Specifications

### 8.1 Proxy Host CRUD Flow

```
Create:
  Handler.Create → Bind → Validate domains
  → Service.Create:
    1. repo.Create (INSERT + pq.Array)
    2. getHostConfigData (12 repos 데이터 조합)
    3. getMergedWAFExclusions (global + host)
    4. nginx.GenerateConfigAndReload (atomic write + test + reload)
  → Audit log

Update:
  Same + domain 변경 시 old config cleanup

Delete:
  repo.Delete → nginx.RemoveConfigAndReload → Audit log

Sync All:
  모든 host iterate → build config → single reload
```

### 8.2 SSL Certificate Lifecycle

```
Issue (Let's Encrypt):
  1. Create cert record (status: pending)
  2. Async goroutine: ACME HTTP-01/DNS-01 challenge
  3. Save PEM to DB + disk
  4. Status → issued, set expires_at
  5. CertificateReadyCallback → regenerate all hosts using cert

Auto-Renew (every 6h):
  Query expiring (30 days) → distributed lock (Valkey)
  → Renew via ACME → save → callback → unlock

Custom Upload:
  Validate PEM → save to DB + disk → callback
```

**Supported DNS Providers (DNS-01):**

| Provider | Type Constant | Credentials | lego Package |
|----------|--------------|-------------|-------------|
| Cloudflare | `cloudflare` | API Token 또는 API Key + Email | `providers/dns/cloudflare` |
| AWS Route53 | `route53` | Access Key ID + Secret Access Key + Region + Hosted Zone ID(선택) | `providers/dns/route53` |
| DuckDNS | `duckdns` | Token | `providers/dns/duckdns` |
| Dynu | `dynu` | API Key | `providers/dns/dynu` |
| Manual | `manual` | (없음) | HTTP-01 webroot |

### 8.3 WAF (ModSecurity)

- **Engine:** ModSecurity v3 + OWASP CRS 4.21
- **Modes:** blocking (403) / detection (log only)
- **Paranoia:** 1-4 levels, anomaly threshold 1-100
- **Per-host config:** `modsec/host_{id}.conf` with SecRuleRemoveById
- **Exclusions:** global + host-specific, merged at config generation
- **Auto-ban:** WAFAutoBanService monitors events, bans IPs exceeding threshold

### 8.4 Bot Filter

- **Categories:** bad_bots, ai_bots, search_engines, suspicious
- **Lists:** configurable in system_settings (newline-separated)
- **Detection:** nginx user-agent regex matching
- **Nginx:** `if ($http_user_agent ~* "...") { return 403; }`

### 8.5 GeoIP Restriction

- **Database:** MaxMind GeoLite2 (Country + City + ASN)
- **Modes:** whitelist (allow only) / blacklist (block listed)
- **Actions:** block (403) / challenge (CAPTCHA redirect)
- **Nginx:** geoip2 module lookup → geo variable → if block
- **CAPTCHA integration:** `auth_request /api/v1/challenge/validate`

### 8.6 Rate Limiting & Fail2ban

**Rate Limit (nginx-level):**
- Per-host: `limit_req_zone` + `limit_req` directives
- Config: RPS, burst, zone size, limit_by (ip/uri), response code

**Fail2ban (application-level):**
- Real-time log monitoring via LogCollector
- Redis counters: `fail2ban:{hostID}:{IP}`
- Actions: ban_ip (add to banned_ips) / throttle
- Auto-expire after ban_time

### 8.7 CAPTCHA Challenge

```
User hits blocked page
  → Nginx redirects to /api/v1/challenge/page
    → HTML with CAPTCHA widget (Turnstile/reCAPTCHA)
      → User solves → POST /challenge/verify
        → API validates with provider → issues cookie
          → Subsequent requests include cookie
            → nginx auth_request validates cookie
```

### 8.8 Cloud Provider Blocking

- Built-in: AWS, GCP, Azure, Cloudflare, Oracle, Vultr, etc.
- Auto-updates IP ranges from vendor feeds
- Per-host: select which providers to block
- Modes: block (403) / challenge (CAPTCHA)
- Nginx: `geo` directive with provider CIDR ranges

### 8.9 Backup & Restore

```
Create:
  1. ExportAllData → export.json (all tables)
  2. tar.gz: export.json + conf.d/*.conf + certs/
  3. SHA256 checksum

Restore (2-phase):
  Phase 1 (DB): extract JSON → TRUNCATE + INSERT (if fails, stop)
  Phase 2 (Files): extract configs + certs
  Post: regenerate all configs → nginx -t → reload
```

### 8.10 Dashboard

- **StatsCollector:** 30초 주기로 nginx_status + gopsutil + log aggregation
- **Tables:** dashboard_stats_hourly (월별 파티션), dashboard_stats_daily
- **Docker Stats:** `docker stats --no-stream` + `docker system df`
- **GeoIP Stats:** country 별 요청 분포
- **React:** refetchInterval: 30000ms

---

## 9. Security Architecture

### 9.1 Defense in Depth

```
Layer 1: Nginx ModSecurity WAF (OWASP CRS 4.21)
Layer 2: IP Blocking (banned_ips, cloud provider, GeoIP)
Layer 3: Rate Limiting (nginx limit_req + application fail2ban)
Layer 4: Bot Filtering (user-agent matching)
Layer 5: URI Blocking (pattern-based, global + per-host)
Layer 6: Exploit Blocking (SQLI/XSS/RFI/LFI patterns)
Layer 7: Access Control (IP allowlists)
Layer 8: Authentication (session + 2FA TOTP + API tokens)
Layer 9: Audit Trail (all admin actions logged)
Layer 10: Advanced Config Sandbox (blocks dangerous nginx directives)
```

### 9.2 Token Security

- Session: 32-byte random hex → SHA256 hash stored in DB
- API Token: similar, with permission scopes and IP allowlist
- 2FA: TOTP with 10 bcrypt-hashed backup codes
- Login: 5 failures → 15 min lockout

### 9.3 Advanced Config Validation

Blocked directives: `load_module`, `include`, `lua_*`, `perl_*`, `js_*`, `njs_*`, `set_by_lua`, `content_by_lua`, `worker_processes`, `daemon`, `modsecurity`, `SecRuleEngine`, `ssl_certificate`

---

## 10. Development Guide

### 10.1 Build Commands

```bash
# 반드시 Docker로 빌드 (호스트에 Go/Node 미설치)
docker compose -f docker-compose.dev.yml build api
docker compose -f docker-compose.dev.yml build ui
docker compose -f docker-compose.dev.yml up -d api ui
```

### 10.2 File Size Limits

| Type | Max Lines |
|------|-----------|
| React Component (.tsx) | 400줄 |
| Custom Hook | 200줄 |
| Go Handler | 300줄 |
| Go Service | 500줄 |

### 10.3 New Feature Checklist

**Backend (Go):**
1. `model/` — 데이터 구조체 + Request/Response
2. `migrations/001_init.sql` — CREATE TABLE + UPGRADE SECTION
3. `repository/` — DB CRUD
4. `service/` — 비즈니스 로직
5. `handler/` — HTTP 핸들러
6. `cmd/server/main.go` — DI + 라우트

**Frontend (React):**
1. `types/` — TypeScript 인터페이스
2. `api/` — API 함수
3. `components/` — 컴포넌트 (400줄 제한)
4. `i18n/locales/{ko,en}/` — 번역 (두 언어 모두)
5. `App.tsx` — 라우트 (필요 시)

### 10.4 UI Checklist

| Item | Method |
|------|--------|
| 반응형 | `sm:`, `md:`, `lg:` breakpoints |
| 다크모드 | `dark:` classes |
| 다국어 | `useTranslation()`, 하드코딩 금지 |
| 툴팁 | `<HelpTip>` 컴포넌트 |

### 10.5 DB Migration Pattern

| Object | Idempotent Pattern |
|--------|-------------------|
| Table | `CREATE TABLE IF NOT EXISTS` |
| Index | `CREATE INDEX IF NOT EXISTS` |
| Column | `ADD COLUMN IF NOT EXISTS` |
| ENUM | `DO $ BEGIN ... EXCEPTION WHEN duplicate_object THEN NULL; END $;` |
| Function | `CREATE OR REPLACE FUNCTION` |

### 10.6 Version Update (릴리즈 전)

| File | Location |
|------|----------|
| `api/internal/config/constants.go` | `const AppVersion = "x.x.x"` |
| `ui/package.json` | `"version": "x.x.x"` |

---

## Document Maintenance

이 문서는 아래 경우에 업데이트합니다:
- 새 API 엔드포인트 추가
- DB 테이블/컬럼 추가
- 새 컴포넌트/라우트 추가
- 아키텍처 패턴 변경
- 새 보안 기능 추가
- 환경변수 추가/변경

**업데이트 방법:** 해당 섹션을 직접 수정하고, 상단의 Last Updated 날짜를 갱신합니다.

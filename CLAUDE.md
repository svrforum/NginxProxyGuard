# Nginx Proxy Guard - Development Specification

## Project Overview
**Nginx Proxy Guard**는 홈서버 운영자를 위한 올인원 보안 리버스 프록시 플랫폼.
Nginx Proxy Manager의 상위호환으로, 자동화된 보안과 직관적인 관리를 제공한다.

| Layer | Technology |
|-------|------------|
| Proxy | Nginx 1.28 + ModSecurity v3 + OWASP CRS 4.21 |
| Backend | Go 1.24 (Echo v4) |
| Frontend | React 18 + TypeScript 5.6 + Vite 6 + TailwindCSS 3.4 |
| Database | TimescaleDB 17 (PostgreSQL 17) |
| Cache | Valkey 8 (Redis 호환, 선택적) |

---

## Architecture Reference

> **중요**: 상세 아키텍처 명세는 `ARCHITECTURE.md`를 반드시 참조할 것.
> 이 문서(CLAUDE.md)는 개발 규칙과 빠른 참조용이고,
> `ARCHITECTURE.md`는 전체 API 카탈로그, DB 스키마, 기능 흐름, 컴포넌트 구조 등 상세 명세를 담고 있다.
> 구조적 변경(API 추가, DB 변경, 라우트 추가 등) 시 `ARCHITECTURE.md`도 함께 업데이트한다.

## Quick Session Start

새 세션 시작 시 아래 파일들로 현재 상태를 빠르게 파악:

| 목적 | 파일 |
|------|------|
| 아키텍처 전체 명세 | `ARCHITECTURE.md` |
| 현재 버전 | `api/internal/config/constants.go` → `AppVersion` |
| API 라우트 전체 | `api/cmd/server/main.go` → route 등록 부분 |
| DB 스키마 현황 | `api/internal/database/migrations/001_init.sql` 하단 UPGRADE SECTION |
| 프론트 라우팅 | `ui/src/App.tsx` → Routes 부분 |
| i18n 키 구조 | `ui/src/i18n/locales/en/common.json` |
| 도커 서비스 구성 | `docker-compose.dev.yml` |

---

## Core Principles

1. **DB = Nginx State** - DB 상태가 곧 Nginx 설정. DB 변경 → config 생성 → nginx -t → reload
2. **Fail-Safe** - `nginx -t` 실패 시 reload 절대 금지, 실패 시 이전 config 롤백
3. **Automation First** - SSL 발급/갱신, 설정 생성, reload 모두 자동화
4. **Security by Default** - 기본값은 가장 안전한 설정
5. **Graceful Degradation** - Redis 없이도 동작 (캐시만 비활성)

---

## Architecture Overview

### Data Flow (핵심 흐름)
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

### Layer Architecture
```
┌─────────────────────────────────────────────┐
│  Handler Layer (Echo HTTP handlers)          │ ← 요청 파싱, 응답 포맷, 에러 분류
├─────────────────────────────────────────────┤
│  Service Layer (비즈니스 로직)                │ ← 다중 repo 조합, nginx 연동, 콜백
├─────────────────────────────────────────────┤
│  Repository Layer (DB 접근)                  │ ← SQL 실행, 캐시 연동
├─────────────────────────────────────────────┤
│  Nginx Manager (설정 생성)                   │ ← 템플릿 렌더링, atomic write, 뮤텍스
├─────────────────────────────────────────────┤
│  Database (TimescaleDB) + Cache (Valkey)     │
└─────────────────────────────────────────────┘
```

### Dependency Injection (main.go 에서의 조립)
```
config.Load()
  → database.New() + cache.NewRedisClient()
    → Repository들 생성 (db 주입) + SetCache(redis)
      → Service들 생성 (repos + nginxManager 주입)
        → 서비스 간 Callback 연결 (순환참조 방지)
          → Handler들 생성 (services 주입)
            → Echo 라우트 등록 + 미들웨어 체인
              → Scheduler 시작 (갱신, 파티션, 로그, 백업)
```

---

## Backend (Go) Architecture

### Directory Structure
```
api/
├── cmd/server/main.go          # 엔트리포인트, DI 조립, 라우트 등록
├── internal/
│   ├── config/                 # 환경변수 로드, 상수 정의
│   │   ├── config.go           # Config struct, Load()
│   │   └── constants.go        # AppVersion, 타임아웃, 임계값
│   ├── database/
│   │   ├── database.go         # DB 커넥션 풀 (25 open, 5 idle)
│   │   ├── migration.go        # 마이그레이션 실행기
│   │   └── migrations/001_init.sql  # 전체 스키마 (62 테이블)
│   ├── handler/                # HTTP 핸들러 (18개 파일)
│   ├── middleware/             # 인증, API 토큰, 레이트리밋
│   ├── model/                  # 데이터 구조체 (20개 파일)
│   ├── nginx/                  # Nginx 설정 생성 엔진
│   ├── repository/             # DB 접근 계층 (25개 파일)
│   ├── scheduler/              # 백그라운드 작업 (갱신, 파티션, 로그, 백업)
│   └── service/                # 비즈니스 로직 (15개 파일)
├── pkg/
│   ├── acme/acme.go            # Let's Encrypt ACME 클라이언트
│   └── cache/redis.go          # Valkey/Redis 클라이언트
└── tests/integration/          # 통합 테스트
```

### Handler Pattern
```go
// 구조체: service 주입
type ProxyHostHandler struct {
    service *service.ProxyHostService
    audit   *service.AuditService
}

// 메서드: Echo 핸들러 시그니처
func (h *ProxyHostHandler) Create(c echo.Context) error {
    var req model.CreateProxyHostRequest
    if err := c.Bind(&req); err != nil {
        return badRequestError(c, "Invalid request body")
    }
    host, err := h.service.Create(c.Request().Context(), &req)
    if err != nil {
        // 에러 분류: 409 Conflict, 400 Bad Request, 500 Internal
        return classifyError(c, "create proxy host", err)
    }
    auditCtx := service.ContextWithAudit(c.Request().Context(), c)
    h.audit.LogProxyHostCreate(auditCtx, req.DomainNames, destination)
    return c.JSON(http.StatusCreated, host)
}
```

**에러 분류 패턴:**
- `"already exist"` → 409 Conflict
- `"invalid"` → 400 Bad Request
- 그 외 → 500 Internal Server Error

### Service Pattern
```go
// 인터페이스 기반 의존성 (순환참조 방지)
type NginxManager interface {
    GenerateConfigAndReload(ctx, data, wafExclusions) error
    TestConfig(ctx) error
}

type ProxyHostService struct {
    repo       *repository.ProxyHostRepository
    wafRepo    *repository.WAFRepository
    nginx      NginxManager  // 인터페이스
}

// 핵심 패턴: Data Aggregation → Config Generation → Test → Reload
func (s *ProxyHostService) Update(ctx, id, req) (*model.ProxyHost, error) {
    host, _ := s.repo.Update(ctx, id, req)           // 1. DB 업데이트
    configData, _ := s.getHostConfigData(ctx, host)   // 2. 다중 repo에서 데이터 조합
    wafExcl, _ := s.getMergedWAFExclusions(ctx, id)   // 3. Global + Host WAF 규칙 병합
    s.nginx.GenerateConfigAndReload(ctx, *configData, wafExcl) // 4. 설정 생성+테스트+리로드
    return host, nil
}
```

**Cross-Service Callback 패턴 (순환참조 방지):**
```go
// main.go에서 연결
certService.SetCertificateReadyCallback(func(ctx, certID string) error {
    return proxyHostService.RegenerateConfigsForCertificate(ctx, certID)
})
```

### Repository Pattern
```go
type ProxyHostRepository struct {
    db    *database.DB
    cache *cache.RedisClient  // 선택적, SetCache()로 주입
}

// SQL Null 처리
var certificateID sql.NullString
err := r.db.QueryRowContext(ctx, query, params...).Scan(&certificateID, ...)
if certificateID.Valid { host.CertificateID = &certificateID.String }

// PostgreSQL 배열 처리
pq.Array(req.DomainNames)         // 쓰기
var domainNames pq.StringArray    // 읽기
```

### Nginx Manager - Config Generation Engine
**핵심 메커니즘:**
1. **Global Mutex** - 모든 nginx 작업은 `globalNginxMutex`로 직렬화
2. **Atomic File Write** - temp file → fsync → rename (중간 상태 없음)
3. **Test Before Reload** - `nginx -t` 실패 시 롤백
4. **Docker Exec** - 컨테이너 내 nginx 명령 실행

```
GenerateConfigAndReload()
  → Lock(globalNginxMutex)
    → GenerateConfigFull()     // proxy host .conf 생성
    → GenerateHostWAFConfig()  // modsec/host_{id}.conf 생성
    → testAndReloadNginx()     // nginx -t → nginx -s reload
  → Unlock()
```

### Middleware Chain
```
APITokenAuth → AuthMiddleware → Handler
```
- **APITokenAuth**: API 토큰 검증, 성공 시 user_id context 설정
- **AuthMiddleware**: Bearer 토큰(세션) 검증, user 정보 context 설정
- **OptionalAuthMiddleware**: 인증 선택적 (공개 엔드포인트용)

### Scheduler (Background Jobs)
| 스케줄러 | 간격 | 역할 |
|----------|------|------|
| RenewalScheduler | 6시간 | SSL 인증서 만료 30일 전 자동 갱신 |
| PartitionScheduler | - | 월별 로그 파티션 생성/삭제 |
| LogRotateScheduler | 일간 | nginx raw 로그 회전 |
| BackupScheduler | cron | 자동 백업 (DB + 설정) |
| StatsCollector | 주기적 | 대시보드 통계 수집 |
| LogCollector | 실시간 | nginx 접근 로그 수집/파싱 |

### Key Constants (`config/constants.go`)
| 상수 | 값 | 용도 |
|------|-----|------|
| HTTPClientTimeout | 30s | 외부 HTTP 요청 |
| NginxReloaderDebounce | 2s | nginx reload 디바운스 |
| CertRenewalThresholdDays | 30 | 인증서 갱신 시점 |
| WAFAutoBanWindowSeconds | 300 | WAF 자동 차단 윈도우 |
| maxFailedAttempts | 5 | 로그인 실패 잠금 기준 |
| lockoutWindow | 15min | 로그인 잠금 시간 |
| sessionDuration | 24h | 세션 유효 시간 |

---

## Frontend (React) Architecture

### Directory Structure
```
ui/src/
├── main.tsx                    # React 18 root + QueryClient + Suspense
├── App.tsx                     # Auth 상태머신 + BrowserRouter + Routes
├── api/                        # API 클라이언트 모듈 (15개)
│   ├── client.ts               # 공통 HTTP 래퍼 (apiGet/Post/Put/Delete)
│   ├── auth.ts                 # 인증, 2FA, 토큰 관리
│   ├── proxy-hosts.ts          # 프록시 호스트 CRUD
│   ├── waf.ts                  # WAF 규칙 관리
│   └── ...
├── types/                      # TypeScript 타입 정의 (8개)
│   ├── proxy-host.ts           # ProxyHost, CreateProxyHostRequest
│   ├── waf.ts                  # WAFRule, WAFRuleExclusion
│   └── ...
├── components/                 # React 컴포넌트 (143 파일, 24 디렉토리)
│   ├── Dashboard.tsx           # 대시보드 (실시간 통계, Recharts)
│   ├── Login.tsx               # 로그인 + 2FA
│   ├── ProxyHostList.tsx       # 프록시 호스트 목록
│   ├── proxy-host/             # 프록시 호스트 폼 (탭 기반)
│   │   ├── ProxyHostForm.tsx   # 메인 래퍼
│   │   ├── hooks/useProxyHostForm.ts  # 폼 로직 훅
│   │   └── tabs/               # BasicTab, SSLTab, SecurityTab...
│   ├── log-viewer/             # 로그 뷰어 (서브컴포넌트 분리)
│   ├── exploit-rules/          # 익스플로잇 규칙 관리
│   └── common/HelpTip.tsx      # 공통 툴팁 컴포넌트
├── hooks/
│   ├── useDarkMode.ts          # 다크모드 토글 + localStorage
│   └── useEscapeKey.ts         # ESC 키 이벤트
└── i18n/
    ├── index.ts                # i18next 설정
    └── locales/{ko,en}/        # 각 16개 JSON 파일
```

### Auth State Machine (App.tsx)
```
AuthState: 'loading' | 'unauthenticated' | 'authenticated' | 'initial-setup'

1. getToken() → 저장된 토큰 확인
2. getAuthStatus() → API로 유효성 검증
3. is_initial_setup ? → InitialSetup 컴포넌트
4. authenticated → AppContent (라우팅)
```

### API Client Pattern (`api/client.ts`)
```typescript
apiGet<T>(url: string): Promise<T>
apiPost<T>(url: string, data?): Promise<T>
apiPut<T>(url, data): Promise<T>
apiDelete(url): Promise<void>

// 자동 처리:
// - Bearer 토큰 헤더 추가 (localStorage 'npg_token')
// - 401 → 토큰 삭제 + 페이지 리로드 (세션 만료)
// - 502/503/504 → 서버 불가 메시지
// - ApiError class (message + details + status)
```

### API Module Pattern
```typescript
// 파일당 하나의 도메인, 함수 단위 export
export async function fetchProxyHosts(page, perPage, search, sortBy, sortOrder): Promise<ProxyHostListResponse>
export async function createProxyHost(data: CreateProxyHostRequest): Promise<ProxyHost>
export async function updateProxyHost(id, data): Promise<ProxyHost>
export async function deleteProxyHost(id): Promise<void>
```

### State Management
| 영역 | 기술 | 용도 |
|------|------|------|
| 서버 데이터 | React Query (`useQuery`, `useMutation`) | API 데이터, 캐싱, 자동 갱신 |
| 폼 상태 | `useState` | 입력값, 유효성 에러 |
| UI 상태 | `useState` | 모달, 탭, 로딩 |
| 인증 | localStorage + React Query | 토큰, 세션 |
| 설정 | localStorage | 테마, 언어, 폰트 |
| 네비게이션 | React Router | URL 기반 라우팅 |

**Redux/Context 없음** - React Query가 서버 상태를 중앙 관리

### React Query Config
```typescript
const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5000, retry: 1 } }
})
// 대시보드: refetchInterval: 30000 (30초)
// 컨테이너 상태: refetchInterval: 15000 (15초)
```

### Component Patterns

**복합 컴포넌트 분리 패턴 (proxy-host/ 참고):**
```
ProxyHostForm.tsx (래퍼, 374줄)
  → useProxyHostForm.ts (로직 훅)
  → tabs/BasicTab.tsx, SSLTab.tsx, SecurityTab.tsx...
  → tabs/security/WAFSettings.tsx, GeoIPSettings.tsx...
  → SaveProgressModal.tsx
```

**모달 패턴:** 폼은 라우트가 아닌 모달 오버레이, 부모가 visibility 관리, ESC 닫기

### i18n 사용법
```typescript
const { t } = useTranslation('proxyHost')           // 네임스페이스 지정
const { t } = useTranslation(['auth', 'common'])     // 복수 네임스페이스
t('form.tabs.basic')                                  // 키 참조
t('common:buttons.save')                              // 크로스 네임스페이스
// 설정: fallbackLng: 'ko', localStorage key: 'npg_language'
// 지원 언어: ko (한국어), en (영어) - 각 16개 JSON
```

**네임스페이스 (16개):** common, navigation, auth, dashboard, proxyHost, redirectHost, waf, logs, settings, certificates, errors, accessControl, exploitRules, exploitLogs, exploitExceptions, fail2ban

### Tailwind CSS Conventions
**다크모드:** `dark:` prefix → `bg-white dark:bg-slate-800`
**반응형:** `grid-cols-1 md:grid-cols-2 lg:grid-cols-4`
**색상:** Primary(`primary-*`), Gray(`slate-*`), Status(`green-*`,`red-*`,`amber-*`,`purple-*`)
**공통 패턴:**
- Card: `bg-white dark:bg-slate-800 rounded-lg shadow p-6`
- Button: `px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50`
- Input: `px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-primary-500`
- Modal: `fixed inset-0 bg-black/50 flex items-center justify-center z-50`

---

## Nginx / Infrastructure

### Docker Services (5개)
| Service | Container | Port | Image |
|---------|-----------|------|-------|
| db | npg-db | 5432 (내부) | timescale/timescaledb:17-pg17 |
| valkey | npg-valkey | 6379 (내부) | valkey/valkey:8-alpine |
| api | npg-api | 8080 (내부) | svrforum/nginxproxyguard-api |
| ui | npg-ui | 81→443 | svrforum/nginxproxyguard-ui |
| nginx | npg-proxy | 80, 443 (host mode) | svrforum/nginxproxyguard-nginx |

### Nginx Config Structure
```
nginx/
├── nginx.conf                  # 메인 (동적 모듈, real_ip, 캐시, 로깅)
├── conf.d/
│   ├── default.conf            # catch-all, ACME, /health
│   ├── logging.conf            # 로그 포맷
│   └── geoip.conf              # GeoIP2 설정
├── includes/
│   ├── proxy_params.conf       # 프록시 헤더
│   └── block_exploits.conf     # SQLI, RFI, XSS 규칙
├── modsec/
│   ├── main.conf               # Blocking 모드
│   ├── modsec-base.conf        # 기본 설정
│   └── host_{id}.conf          # 호스트별 WAF (API 생성)
└── scripts/docker-entrypoint.sh
```

**동적 모듈:** modsecurity, brotli, headers_more, geoip2

### API가 생성하는 Nginx Config 파일
| 파일 | 위치 | 생성 조건 |
|------|------|----------|
| `{domain}.conf` | conf.d/ | 프록시 호스트 생성/수정 |
| `host_{id}.conf` | modsec/ | WAF 활성화 시 |
| `default.conf` | conf.d/ | 기본 서버 설정 변경 |
| `banned_ips.conf` | conf.d/ | IP 차단 목록 갱신 |

### Volume Sharing
```
npg_nginx_data (API ↔ Nginx 공유)
  ← API: config 파일 쓰기
  → Nginx: config 파일 읽기
```

---

## Database Schema

### 핵심 테이블 (62개 중 주요)
| 카테고리 | 테이블 | 설명 |
|----------|--------|------|
| **프록시** | proxy_hosts | 리버스 프록시 설정 |
| | redirect_hosts | HTTP 리다이렉트 |
| | certificates | SSL/TLS 인증서 |
| | certificate_history | 발급/갱신 이력 |
| | dns_providers | DNS 프로바이더 인증정보 |
| **보안** | banned_ips | IP 차단 |
| | access_lists / access_list_items | IP 허용/차단 규칙 |
| | bot_filters | 봇 탐지 |
| | exploit_block_rules | 익스플로잇 패턴 |
| | challenge_configs / challenge_logs / challenge_tokens | CAPTCHA |
| | cloud_providers | 클라우드 IP 차단 |
| **로깅** | logs / logs_partitioned | 접근 로그 (월별 파티션) |
| | dashboard_stats_hourly / daily | 대시보드 통계 |
| | system_logs | 시스템 이벤트 |
| | audit_logs | 감사 로그 |
| **인증** | auth_sessions | 세션 |
| | api_tokens / api_token_usage | API 토큰 |
| **설정** | settings | 글로벌 설정 (key-value) |
| | users | 사용자 (2FA 포함) |
| | backups | 백업 메타데이터 |

### 주요 ENUM
```sql
block_reason: 'none','waf','bot_filter','rate_limit','geo_block',
             'exploit_block','banned_ip','uri_block','cloud_provider_challenge',
             'cloud_provider_block','access_denied'
log_type: 'access','error','modsec'
system_log_level: 'debug','info','warn','error','fatal'
```

---

## Key Data Models

### ProxyHost (핵심)
```go
type ProxyHost struct {
    ID                  string
    DomainNames         pq.StringArray  // 도메인 목록
    ForwardScheme       string          // http/https
    ForwardHost         string
    ForwardPort         int
    SSLEnabled          bool
    CertificateID       *string         // FK → certificates
    WAFEnabled          bool
    WAFMode             string          // "blocking" | "detection"
    WAFParanoiaLevel    int             // 1-4
    WAFAnomalyThreshold int             // 기본 5
    CacheEnabled        bool
    BlockExploits       bool
    AdvancedConfig      string          // 커스텀 nginx 지시자
    AccessListID        *string         // FK → access_lists
    Enabled             bool
}
```

### Request/Response 타입 패턴
```go
// Create: 필수 필드 일반 타입
type CreateProxyHostRequest struct { DomainNames []string; ForwardScheme string; ... }
// Update: 포인터 필드로 partial update
type UpdateProxyHostRequest struct { DomainNames *[]string; ForwardScheme *string; ... }
```

---

## Feature Map

### 보안 기능
| 기능 | Handler | Service/Config |
|------|---------|----------------|
| WAF (ModSecurity) | waf.go, waf_global.go | modsec/host_{id}.conf |
| 봇 필터 | security.go | nginx server block |
| GeoIP 차단 | geo.go | geoip.conf |
| Rate Limiting | security.go | nginx limit_req zone |
| IP 차단 | security.go | banned_ips.conf |
| Access List | access_list.go | nginx allow/deny |
| URI 차단 | security.go | nginx location block |
| 익스플로잇 차단 | exploit_block_rule.go | block_exploits.conf |
| CAPTCHA | challenge.go | challenge_configs |
| Cloud Provider 차단 | cloud_provider.go | - |

### 프론트엔드 라우트
```
/dashboard                  → Dashboard.tsx
/proxy-hosts                → ProxyHostList.tsx + ProxyHostForm (모달)
/certificates/*             → CertificateList, CertificateHistory, DNSProviderList
/redirects                  → RedirectHostManager.tsx
/waf/*                      → WAFSettings, BannedIPList, URIBlockManager, WAFTester,
                              ExploitBlockRules, Fail2banManagement
/access/lists               → AccessListManager.tsx
/logs/*                     → LogViewer (access, waf-events, bot-filter, exploit-blocks,
                              system, audit, raw-files)
/settings/*                 → GlobalSettings, ChallengeSettings, GeoIPSettings,
                              SSLACMESettings, MaintenanceSettings, BackupManager,
                              BotFilterSettings, WAFAutoBanSettings, SystemLogSettings
```

---

## Development Rules

### Build Commands

> **중요**: 호스트에 Go/Node.js 미설치. 반드시 Docker로 빌드!
> - `docker-compose.yml`: 프로덕션 (Docker Hub 이미지, host network mode)
> - `docker-compose.dev.yml`: 개발/테스트 (로컬 코드 빌드)

```bash
# 개발환경 빌드 - 코드 수정 후 항상 이것 사용
docker compose -f docker-compose.dev.yml build api
docker compose -f docker-compose.dev.yml build ui
docker compose -f docker-compose.dev.yml up -d api
docker compose -f docker-compose.dev.yml up -d ui

# 전체 재시작
docker compose -f docker-compose.dev.yml up -d --build
```

### API 테스트 (인증 필요 시)
```bash
# 1. 세션 토큰 생성
TEST_TOKEN=$(openssl rand -hex 32)
TOKEN_HASH=$(echo -n "$TEST_TOKEN" | sha256sum | cut -d' ' -f1)
USER_ID="사용자_UUID"
docker compose exec db psql -U postgres -d nginx_guard -c \
  "INSERT INTO auth_sessions (user_id, token_hash, ip_address, user_agent, expires_at) \
   VALUES ('$USER_ID', '$TOKEN_HASH', '127.0.0.1', 'test', NOW() + INTERVAL '1 hour');"

# 2. API 호출
docker compose exec api wget -qO- --header="Authorization: Bearer $TEST_TOKEN" \
  "http://localhost:8080/api/v1/endpoint"
```

### File Size Limits
| File Type | Max Lines |
|-----------|-----------|
| React Component (.tsx) | 400줄 |
| Custom Hook | 200줄 |
| Go Handler | 300줄 |
| Go Service | 500줄 |

초과 시 서브 컴포넌트/훅으로 분리

### UI 개발 체크리스트
| 항목 | 구현 방법 |
|------|----------|
| 반응형 | `sm:`, `md:`, `lg:` 브레이크포인트 |
| 다크모드 | `dark:` 클래스 |
| 다국어 | `useTranslation()`, 하드코딩 금지 |
| 툴팁 | 설정 항목에 `<HelpTip>` 컴포넌트 |

### 새 기능 추가 시 체크리스트

**Backend (Go):**
1. `model/` - 데이터 구조체 + Request/Response 타입
2. `migrations/001_init.sql` - CREATE TABLE + UPGRADE SECTION 둘 다 추가
3. `repository/` - DB CRUD
4. `service/` - 비즈니스 로직 (nginx 연동 시)
5. `handler/` - HTTP 핸들러
6. `cmd/server/main.go` - DI 조립 + 라우트 등록

**Frontend (React):**
1. `types/` - TypeScript 인터페이스
2. `api/` - API 함수 모듈
3. `components/` - 컴포넌트 (400줄 제한)
4. `i18n/locales/{ko,en}/` - 번역 (두 언어 모두)
5. `App.tsx` - 라우트 추가 (필요 시)

**문서 (개발 완료 후 필수):**
- `ARCHITECTURE.md` 업데이트 — API 추가 시 §6 엔드포인트, DB 변경 시 §5 스키마, 모델 변경 시 §7 타입, Repository 변경 시 §2.7 인벤토리 등 해당 섹션 반영

### Database Migration
- **단일 파일**: `001_init.sql`로 전체 스키마 관리
- **항상 안전**: 서버 시작 시 매번 실행
- **새 컬럼**: CREATE TABLE에 추가 + UPGRADE SECTION에 ALTER TABLE 추가

| 객체 | 멱등성 패턴 |
|------|------------|
| 테이블 | `CREATE TABLE IF NOT EXISTS` |
| 인덱스 | `CREATE INDEX IF NOT EXISTS` |
| 컬럼 | `ADD COLUMN IF NOT EXISTS` |
| ENUM | `DO $ BEGIN ... EXCEPTION WHEN duplicate_object THEN NULL; END $;` |
| 함수 | `CREATE OR REPLACE FUNCTION` |

---

## Git Configuration

| 항목 | 값 |
|------|-----|
| Name | svrforum |
| Email | svrforum.com@gmail.com |
| Repository | https://github.com/svrforum/nginxproxyguard |

### Commit Rules
- **Claude 서명 금지**: `Generated with Claude Code` 및 `Co-Authored-By: Claude` 추가 금지
- 커밋 형식: `type: description` (feat:, fix:, docs:, chore:, refactor:, release:)

### Version Update (릴리즈 전 필수)
| 파일 | 위치 |
|------|------|
| `api/internal/config/constants.go` | `const AppVersion = "x.x.x"` |
| `ui/package.json` | `"version": "x.x.x"` |

### CI/CD
- GitHub Actions: `v*` 태그 push → 변경 감지 → 멀티아키텍처 Docker 빌드 (amd64, arm64)
- 컴포넌트별 독립 빌드 (api, ui, nginx SHA256 해시 비교)

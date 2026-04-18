# Codebase Structural Cleanup — Design Spec

> **Date:** 2026-04-17
> **Target Version:** 2.10.0 (post-2.9.1)
> **Scope:** Balanced refactoring of accumulated technical debt across backend and frontend
> **Authors:** Pair session (user: svrforum / jmlee0108@toss.im)

## 1. Background

`git log` 및 구조 분석 결과, v2.9.1 시점에서 다음 부채가 누적됨:

1. **문서 드리프트** — `CLAUDE.md`(handler 18/service 15/repo 25/model 20)와 `ARCHITECTURE.md`(handler 26/service 20/repo 30/model 23)가 실제 코드(handler 37/service 29/repo 30/model 25)와 불일치. `AppVersion` 표기가 여러 문서에서 엇갈림(2.7.4 / 2.7.6 / git 기준 2.9.1). `ui/src/pages/` 디렉토리는 구조도에 누락.
2. **파일 크기 규정 위반** — `CLAUDE.md`의 자체 규칙(Handler 500, Service 800, Component 600, Hook 300줄) 초과 파일이 **백엔드 6개 + 프론트 11개**. 가장 심각: `nginx/proxy_host_template.go` 1931줄, `useProxyHostForm.ts` 677줄(한도 2.3배).
3. **얇은 테스트 커버리지** — 백엔드 테스트 파일 5개, nginx config 생성 엔진과 WAF 병합 로직에 단위 테스트 부재.
4. **main.go DI 비대화** — 988줄 단일 함수가 DB/Cache/Repos(29)/Services/Callbacks/Handlers/Schedulers/Routes를 순차 조립.

### 범위 확정 (브레인스토밍 결과)

- **공격성 수준:** **B (균형적)** — 문서·파일 분할·테스트·`main.go` 포함. 아키텍처 변경(god-service 해소, repo 비즈니스 로직 승격) 등 C 범위는 별도 프로젝트로 분리.
- **PR 전략:** **A (단계별 독립 PR)** — Phase별로 회귀 시 특정 PR만 롤백 가능.
- **테스트 전략:** **A (테스트 먼저)** — Phase 2에서 특성 테스트 작성 후 그 위에서 리팩토링.
- **Phase 순서:** **위험도 오름차순** — 쉬운 것으로 신뢰 구축 → 안전망 → 점점 위험한 변경.

### 범위 밖 (명시적 배제)

- `ProxyHostService` god-service 해소 (`ProxyHostConfigBuilder` 추출)
- `repository/log.go`의 비즈니스 로직을 Service로 승격
- E2E 테스트 커버리지 확장
- `components/` 폴더 규칙 전면 재정비 (Phase 5는 대상 파일의 도메인 서브폴더 이동까지만)
- 관련 없는 클린업 / 스타일 변경 / 의존성 업그레이드

---

## 2. Architecture Overview

6개 Phase × 7개 PR로 구성. 각 PR은 검증 게이트(빌드 + E2E + 테스트) 통과 후에만 머지.

| Phase | PR | 브랜치 | 리스크 | 의존 |
|-------|-----|--------|--------|------|
| 1 | `chore: sync architecture docs and prune legacy` | `phase1/docs-sync` | 🟢 | - |
| 2 | `test: add characterization tests for config generation` | `phase2/characterization-tests` | 🟢 | 1 |
| 3 | `refactor(api): extract main.go bootstrap into setup functions` | `phase3/main-bootstrap` | 🟡 | 2 |
| 4a | `refactor(api): split proxy_host_template by section` | `phase4a/template-split` | 🟡 | 2 |
| 4b | `refactor(api): split oversized repositories` | `phase4b/repo-split` | 🟡 | 2 |
| 5 | `refactor(ui): split large components below 600 LOC` | `phase5/ui-component-split` | 🟡 | 1 |
| 6 | `refactor(ui): decompose useProxyHostForm into domain hooks` | `phase6/proxy-host-form-hooks` | 🔴 | 2, 5 |

### 검증 게이트 (모든 Phase 공통)

1. `docker compose -f docker-compose.dev.yml build api` 및 `build ui` 성공
2. Phase 2 이후: `cd api && go test ./...` 녹색
3. `docker compose -f docker-compose.e2e-test.yml up -d --build`
4. `cd test/e2e && npx playwright test` — 해당 Phase 영향 범위의 스펙 녹색
5. Phase 6: 수동 체크리스트 (아래 §9.3) 전부 통과

### 목표 지표

| 영역 | 현재 | Phase 6 완료 후 목표 |
|------|------|---------------------|
| Handler 파일 | ≤500줄 원칙 | 유지 (현재 OK) |
| Service 파일 | 1개 위반 (838) | 모두 ≤800줄 |
| Repository 파일 | 5개 >800줄 (log 1687, backup_export 1115, proxy_host 1086, backup_import 961, waf 944) | 모두 해소, 파일당 ≤800줄 |
| Nginx 템플릿 파일 | 1931줄 단일 | embed.FS + 파일당 ≤400줄 |
| `main.go` | 988줄 | ≤200줄 |
| React Component | 11개 >600줄 | 모두 ≤600줄 (목표 ≤500) |
| Custom Hook | 1개 677줄 | 모두 ≤300줄 |
| 특성 테스트 | 0개 | 4개 (config 생성, WAF 병합, AdvancedConfig 충돌, Sync 복구) |
| 문서 파일 수 정확도 | 전 문서 불일치 | 코드와 일치 |

---

## 3. Phase 1 — Docs Sync + Legacy Cleanup

### 3.1 작업 항목

1. **`CLAUDE.md` 갱신**
   - Backend Architecture §3.1: 파일 개수 실제에 맞춤 (handler 37, service 29, repo 30, model 25, nginx 10, middleware 3, scheduler 5, util 1)
   - Frontend §3.1: `ui/src/pages/` 디렉토리 추가 (4개 파일), `util/query.go` 언급
2. **`ARCHITECTURE.md` 갱신**
   - §2.1: 디렉토리 트리의 파일 개수 실제에 맞춤
   - §2.7: Repository inventory 업데이트 (누락된 레포 추가 또는 제거)
   - §2.11: `AppVersion = "2.9.1"` 반영
   - §3.1: 프론트 컴포넌트 파일 수 업데이트
3. **`AppVersion` 단일 출처 원칙 명시**
   - `api/internal/config/constants.go`의 `AppVersion`이 SoT
   - `ARCHITECTURE.md` 헤더의 수동 버전 표기 제거, "코드 기준" 문구로 대체
   - 릴리즈 체크리스트에 "ARCHITECTURE.md 버전 확인" 단계 추가
4. **레거시 nginx config 파일 조사 및 제거**
   - 사전 조사: `grep -rn "main.conf\|detection-only.conf" nginx/ api/` 로 로드 여부 확인
   - 어디서도 `include`되지 않으면 `nginx/modsec/main.conf`, `nginx/modsec/detection-only.conf` 제거
   - 로드되고 있으면 **Phase 1에서 제거 보류** — `ARCHITECTURE.md` §4.2 "레거시" 표기는 유지하되 비고에 "런타임 참조 존재, 제거 보류" 한 줄 추가 후 다음 Phase로 진행
5. **`ui/pages/` vs `components/` 경계 문서화**
   - 4개 파일(`CertificatesPage`, `LogsPage`, `SettingsPage`, `WAFPage`)이 탭 호스트 역할임을 확인
   - `ARCHITECTURE.md` §3.1에 역할 구분 추가 ("pages/ = 라우트 단위 컨테이너, components/ = 재사용 단위")

### 3.2 검증

- `git diff` 변경이 문서 파일과 제거된 nginx conf 파일로 국한됨
- `docker compose -f docker-compose.dev.yml up -d nginx && docker logs npg-proxy` 로 `nginx -t` 통과
- E2E 테스트 실행 불필요 (런타임 동작 무변경)

---

## 4. Phase 2 — Characterization Tests

모두 `*_characterization_test.go`로 명명, Golden-file 패턴 사용. 변경 갱신은 `-update-golden` 플래그 필요.

### 4.1 `internal/nginx/proxy_host_template_characterization_test.go`

**대상:** `GenerateConfigFull(ctx, data)` 렌더링 결과 고정
**케이스 (6개):**
1. HTTP only — 기본 프록시 (SSL off)
2. HTTPS — Force HTTPS, HTTP/2 enabled, cert id 주입
3. WAF on — blocking mode, paranoia 2, threshold 5, exclusions 3개
4. Cache on — proxy_cache_valid 설정
5. Advanced config — `proxy_connect_timeout 10s;` 직접 삽입 시 auto-generated 충돌 없음 검증
6. Upstream + LB — least_conn 전략, 3개 backend

**픽스처 위치:** `api/internal/nginx/testdata/golden/proxy_host_*.conf`

### 4.2 `internal/nginx/waf_merge_characterization_test.go`

**대상:** `ProxyHostService.getMergedWAFExclusions(ctx, hostID)` (순수 병합 로직)
**케이스 (4개):**
1. 글로벌만 있음
2. 호스트만 있음
3. 양쪽 모두 + 중복 rule_id (호스트 우선)
4. 전부 비어있음 → 빈 슬라이스 반환

### 4.3 `internal/nginx/advanced_config_characterization_test.go`

**대상:** `parseAdvancedConfigDirectives()` + `hasDirective()` 템플릿 함수
**케이스 (20개):** 실제 사용자가 advanced_config에 넣을 법한 샘플 모음 (주석 포함, 멀티라인 포함, 잘못된 syntax 포함)
**검증:** 각 샘플별로 "어떤 directive가 skip되어야 하는가" 목록이 기대값과 일치

### 4.4 `internal/service/sync_auto_recovery_characterization_test.go`

**대상:** `ProxyHostService.SyncAllConfigs()` 자동 복구 루프
**방식:**
- `NginxManager` 인터페이스의 fake 구현 (mock 아님, 스텁)
  - `GenerateConfigFull`: 지정된 host ID에서 특정 문자열 반환
  - `TestConfig`: 특정 호스트의 config 내용에 "FAIL_MARKER"가 있으면 에러 반환
- fake DB: 5개 호스트 중 2개에 FAIL_MARKER를 포함하도록 설정
- 실행 후: 에러 2개는 `config_status="error"`, 나머지 3개는 정상 config 생성됨을 확인
- `TestConfig` 호출 횟수 ≤ 5회 (최대 재시도 제한 준수)

### 4.5 검증

- `cd api && go test ./internal/nginx/... ./internal/service/... -v` 전부 녹색
- 기존 테스트 회귀 없음 (`proxy_host_test.go` 등)

---

## 5. Phase 3 — `main.go` DI 분해

### 5.1 새 패키지 구조

```
api/internal/bootstrap/
├── container.go       # Container 구조체 + NewContainer() + Close()
├── storage.go         # InitDB, InitCache
├── repositories.go    # InitRepositories (29 repos + cache 주입)
├── services.go        # InitServices + wireCallbacks
├── handlers.go        # InitHandlers
├── routes.go          # RegisterRoutes(e *echo.Echo, c *Container) + RegisterMiddleware
├── schedulers.go      # StartSchedulers, StopSchedulers
└── startup.go         # Startup(ctx): SyncAllConfigs + GenerateDefaultServerConfig + background services
```

### 5.2 Container 구조

```go
type Container struct {
    Config       *config.Config
    DB           *database.DB
    Cache        *cache.RedisClient
    Nginx        nginx.Manager
    Repositories *Repositories
    Services     *Services
    Handlers     *Handlers
    Schedulers   *Schedulers
}

func NewContainer(cfg *config.Config) (*Container, error) { /* 조립 순서 동일 */ }
func (c *Container) Close() error { /* DB, Cache close */ }
func (c *Container) Startup(ctx context.Context) error { /* sync + bg services */ }
func (c *Container) StartSchedulers(ctx context.Context) { /* renewal, partition, etc */ }
func (c *Container) StopAll() { /* 순서대로 stop */ }
```

### 5.3 새 `main.go` (예상 ~170줄)

```go
func main() {
    cfg := config.Load()
    c, err := bootstrap.NewContainer(cfg)
    if err != nil { log.Fatalf("container init: %v", err) }
    defer c.Close()

    ctx, cancel := context.WithCancel(context.Background())
    if err := c.Startup(ctx); err != nil { log.Fatalf("startup: %v", err) }

    e := echo.New()
    bootstrap.RegisterMiddleware(e, cfg)
    bootstrap.RegisterRoutes(e, c)

    c.StartSchedulers(ctx)

    go handleShutdown(cancel, c, e)
    port := cfg.Port
    if port == "" { port = "8080" }
    log.Printf("Starting server on port %s", port)
    if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
        log.Fatalf("Server error: %v", err)
    }
}

func handleShutdown(cancel context.CancelFunc, c *bootstrap.Container, e *echo.Echo) {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    <-sigChan
    log.Println("Shutting down...")
    cancel()
    c.StopAll()
    e.Close()
}
```

### 5.4 불변 조건 (회귀 방지)

- DI 조립 순서: **DB→Cache→Nginx→Repos→(cache inject 4개)→Services→Callbacks→Startup→Handlers→Routes→Schedulers** — 기존과 동일
- Cross-service 콜백 연결 위치: `services.go`의 `wireCallbacks(services *Services)` 함수에 집중
- `main_test.go`가 통과해야 함 (기동 테스트)

### 5.5 검증

- Phase 2 특성 테스트 전부 녹색
- `docker compose -f docker-compose.dev.yml up -d api && docker logs npg-api` 로 기동 로그 확인 (에러 없음)
- E2E 전체 실행: `cd test/e2e && npx playwright test`

---

## 6. Phase 4a — `proxy_host_template.go` 분할

### 6.1 새 구조 (embed.FS)

```
api/internal/nginx/
├── proxy_host_template.go         # ~300줄: 템플릿 로딩 + 렌더링 API + FuncMap
└── templates/proxy_host/
    ├── base.conf.tmpl             # server 블록 스켈레톤, {{template "section_name" .}} 조합
    ├── ssl.conf.tmpl
    ├── waf.conf.tmpl
    ├── cache.conf.tmpl
    ├── upstream.conf.tmpl
    ├── security_headers.conf.tmpl
    ├── access_list.conf.tmpl
    ├── location_defaults.conf.tmpl  # block_exploits, client_max_body_size, timeouts (모두 hasDirective 가드)
    └── advanced.conf.tmpl           # {{ .AdvancedConfig }} - 마지막 위치
```

### 6.2 핵심 기술

```go
//go:embed templates/proxy_host/*.tmpl
var proxyHostTemplates embed.FS

var proxyHostTmpl = template.Must(
    template.New("base.conf.tmpl").
        Funcs(templateFuncMap).  // hasDirective, etc.
        ParseFS(proxyHostTemplates, "templates/proxy_host/*.tmpl"),
)

func (m *Manager) GenerateConfigFull(ctx context.Context, data ProxyHostData) error {
    var buf bytes.Buffer
    if err := proxyHostTmpl.ExecuteTemplate(&buf, "base.conf.tmpl", data); err != nil {
        return fmt.Errorf("render proxy host config: %w", err)
    }
    return m.writeFileAtomic(configPath, buf.Bytes(), 0644)
}
```

### 6.3 불변 조건

- **외부 API 불변:** `GenerateConfigFull(ctx, data)` 시그니처 동일, Service 레이어 수정 없음
- **FuncMap 불변:** `hasDirective`, `safe` 등 기존 헬퍼 그대로 유지
- **Atomic write 경로 불변:** `writeFileAtomic(temp→fsync→rename)` 동일

### 6.4 검증

- **Phase 2의 6개 golden file과 바이트 단위 일치** (한 바이트 다르면 FAIL)
- E2E 관련 스펙 전체 녹색 (`specs/proxy-host/*`, `specs/security/waf.spec.ts`)

---

## 7. Phase 4b — Oversized Repository 분할 (5개 파일)

**공통 원칙:** Go의 **파일 간 메서드 분산 허용**을 활용 — 모든 파일이 같은 receiver 메서드 정의 가능. 구조체 정의(`type XxxRepository struct { ... }` + `NewXxxRepository`)는 base 파일 한 곳에만.

**외부 인터페이스 불변:** 모든 public 메서드 시그니처 동일. Service 레이어, 호출자 전혀 수정 없음.

### 7.1 `log.go` 분할 (1687줄 → 5개 파일)

```
repository/
├── log.go              # 구조체 + 핵심 CRUD: Create, List, GetByID, Delete
├── log_queries.go      # GetDistinctHosts, GetDistinctClientIPs, GetDistinctUserAgents 등 6개
├── log_stats.go        # GetStats, 시간별 집계, top IPs 등
├── log_settings.go     # GetSettings, UpdateSettings, retention config
└── log_cleanup.go      # Cleanup, 파티션 삭제 호출, retention 정책 적용
```

### 7.2 `backup_export.go` + `backup_import.go` 분할 (2076줄 → 8개 파일)

```
repository/
├── backup_export.go             # 오케스트레이터 ExportAllData (~300줄 목표)
├── backup_export_proxy.go       # proxy_hosts, redirect_hosts, certificates, dns_providers
├── backup_export_security.go    # access_lists, bot_filters, rate_limits, waf_*, exploit_*, cloud_providers
├── backup_export_settings.go    # global_settings, system_settings, users, api_tokens, filter_subscriptions
├── backup_import.go             # 오케스트레이터 ImportAllData
├── backup_import_proxy.go
├── backup_import_security.go    # CHECK 제약 fallback 로직 (waf_paranoia_level 등) 여기에
└── backup_import_settings.go
```

### 7.3 `proxy_host.go` 분할 (1086줄 → 3개 파일)

```
repository/
├── proxy_host.go               # 구조체 + Create, Update, Delete, GetByID, GetByDomain
├── proxy_host_queries.go       # List(페이지네이션/정렬/검색), GetByCertificateID, GetForCloudProvider 등 조회
└── proxy_host_favorites.go     # ToggleFavorite 및 즐겨찾기 관련 메서드
```

### 7.4 `waf.go` 분할 (944줄 → 3개 파일)

```
repository/
├── waf.go                      # 구조체 + GetHostConfig (기본 조회)
├── waf_exclusions.go           # CreateExclusion, DeleteExclusion, Global/Host exclusion CRUD
└── waf_snapshots.go            # waf_rule_snapshots, waf_rule_change_events, waf_rule_snapshot_details 관련
```

### 7.5 불변 조건 (매우 중요)

- **Export JSON 스키마 불변** — 기존 백업 파일 100% 호환
- **`model/backup.go`의 구조체 불변** (`ProxyHostData` 등)
- **Import의 CHECK 제약 fallback 로직 완전 유지** — 하위 버전 백업 복구 지원 (`CLAUDE.md`의 "하위 버전 백업 호환성" 조항)
- **Repository 공개 메서드 시그니처 불변** — Service 레이어 수정 금지
- **캐시 주입 경로 불변** — `ProxyHostRepository.SetCache()`, `ExploitBlockRuleRepository.SetCache()` 등은 `bootstrap/repositories.go`에서 기존처럼 호출 (Phase 3과 정합)

### 7.6 검증

- 기존 백업 파일로 export → import 라운드트립 테스트 추가 (`repository/backup_roundtrip_test.go`)
- E2E: `specs/settings/backup.spec.ts`, `specs/proxy-host/*`, `specs/security/waf.spec.ts` 전부 녹색
- Phase 2 특성 테스트 (특히 WAF 병합) 녹색 유지

---

## 8. Phase 5 — UI Component Split (11 files)

### 8.1 공통 원칙

- 파일당 목표 **≤500줄** (한도 600줄의 여유 확보)
- 대상 파일이 속한 **도메인 서브폴더로 이동**
- 리스트/테이블/모달/필터/툴바 단위로 추출
- 상태·핸들러는 얇은 컨테이너에 유지, 프레젠테이션만 분리
- **API 시그니처, 라우트, i18n 키, 외부 import 경로는 불변**

### 8.2 파일별 분할 계획

| 대상 파일 (현재줄) | 이동/생성 디렉토리 | 서브컴포넌트 |
|---|---|---|
| `LogViewer.tsx` (825) | `components/log-viewer/` (기존) | `LogTable.tsx`, `LogToolbar.tsx`, `useLogQuery.ts` |
| `ExploitBlockLogs.tsx` (799) | `components/exploit-block-logs/` (신규) | `ExploitLogTable.tsx`, `ExploitLogFilters.tsx`, `ExploitLogDetailModal.tsx` |
| `LogDetailModal.tsx` (709) | `components/log-viewer/modals/` (기존) | `LogDetailHeader.tsx`, `LogDetailBody.tsx`, `LogRawBlock.tsx` |
| `BackupManager.tsx` (687) | `components/backup/` (신규) | `BackupList.tsx`, `BackupActions.tsx`, `BackupScheduleCard.tsx` |
| `APITokenManager.tsx` (653) | `components/api-token/` (신규) | `TokenList.tsx`, `TokenCreateModal.tsx`, `TokenUsageModal.tsx` |
| `FilterSubscriptionList.tsx` (640) | `components/filter-subscription/` (신규) | `SubscriptionTable.tsx`, `SubscriptionForm.tsx`, `SubscriptionActions.tsx` |
| `AccountSettings.tsx` (623) | `components/account/` (신규) | `ProfileTab.tsx`, `PasswordTab.tsx`, `TwoFactorTab.tsx`, `LanguageFontTab.tsx` |
| `LogFilters.tsx` (621) | `components/log/` (기존) | `BasicFilters.tsx`, `AdvancedFilters.tsx`, `FilterActions.tsx` |
| `ProxyHostList.tsx` (615) | `components/proxy-host-list/` (기존) | `ProxyHostRow.tsx`, `ProxyHostBulkActions.tsx`, `ProxyHostFilters.tsx` |
| `TestResultModal.tsx` (614) | `components/proxy-host-list/` (기존) | `TestResultSummary.tsx`, `TestResultDetails.tsx`, `TestResultLogs.tsx` |

### 8.3 Import 경로 처리

- **외부 import는 불변** — 예: `import { LogViewer } from '@/components/LogViewer'`
- 서브컴포넌트 이동 시 `App.tsx`, `pages/*.tsx` 등의 import 경로 변경 발생 가능 → 모두 함께 갱신

### 8.4 검증

- `cd ui && npm run build` 통과
- `cd test/e2e && npx playwright test` — 전체 녹색
- 수동 smoke: 각 리팩토링된 화면 1회씩 수동 렌더링 확인

---

## 9. Phase 6 — `useProxyHostForm` 훅 분해 (🔴 최고 리스크)

### 9.1 새 구조

```
ui/src/components/proxy-host/hooks/
├── useProxyHostForm.ts              # <120줄: 컨테이너 훅. 서브훅 조합만
├── useProxyHostFormState.ts         # <200줄: 필드 상태 + 초기값 + setters + validation errors 상태
├── proxyHostValidation.ts           # <150줄: validateBasic/SSL/Security/All. 상태 없는 순수 함수 모듈 (React 훅 아니므로 `use` 접두사 생략)
├── useProxyHostCertificate.ts       # <200줄: 인증서 선택/생성 + 2s 폴링 (120s timeout)
├── useProxyHostSubmit.ts            # <250줄: 6단계 submit 오케스트레이터
└── useProxyHostExtras.ts            # <150줄: bot filter / geo / cloud 등 skip_reload=true 추가 저장
```

### 9.2 외부 API 불변 (유일한 안전 방벽)

```typescript
// ProxyHostForm.tsx에서의 호출 시그니처 그대로
const {
  formData, errors, activeTab, setActiveTab,
  handleSubmit, saveProgress, resetForm, /* ... */
} = useProxyHostForm(host, onClose);
```

내부 재배선:
```typescript
export function useProxyHostForm(host, onClose) {
  const state = useProxyHostFormState(host);
  const validation = validateAll(state.formData);  // import { validateAll } from './proxyHostValidation'
  const cert = useProxyHostCertificate(state);
  const extras = useProxyHostExtras();
  const submit = useProxyHostSubmit({ state, validation, cert, extras, onClose });
  return { ...state, ...submit, errors: validation };
}
```

### 9.3 수동 체크리스트 (필수)

- [ ] 신규 프록시 호스트 생성 (HTTP only)
- [ ] 신규 프록시 호스트 생성 (HTTPS + 인증서 동시 발급, DNS challenge)
- [ ] 기존 호스트 수정 — Basic 탭
- [ ] 기존 호스트 수정 — SSL 탭
- [ ] 기존 호스트 수정 — Security 탭 (WAF, Access List, Bot Filter, GeoIP)
- [ ] 기존 호스트 수정 — Protection 탭 (Rate Limit, Fail2ban, URI Block)
- [ ] 기존 호스트 수정 — Performance 탭 (Cache)
- [ ] 기존 호스트 수정 — Upstream 탭 (LB 전략)
- [ ] 기존 호스트 수정 — Advanced 탭 (커스텀 nginx 지시자)
- [ ] 폼 검증 에러 처리 (필수 필드 누락, 중복 도메인 등)
- [ ] WAF 규칙 저장 후 `nginx/modsec/host_{id}.conf` 파일에 반영 확인
- [ ] 저장 진행 상태 모달(`SaveProgressModal`)이 모든 단계 표시

### 9.4 롤백 기준

- E2E 1개라도 실패 → PR 머지 중단, 브랜치 재작업
- 수동 체크리스트 1개라도 실패 → 머지 중단
- Phase 2 특성 테스트 재실행하여 green 유지 (백엔드 회귀 방지)

---

## 10. 커밋 / PR / 브랜치 규칙

### 10.1 커밋

- **형식:** `type(scope): short description` (영문, 72자 이내)
- **타입:** `docs`, `chore`, `test`, `refactor`
- **Claude 서명 금지** (`CLAUDE.md` 규칙)
- 여러 논리 단위는 여러 커밋으로 분리 (한 Phase 내에서도 가능)

### 10.2 PR

- 제목: 위 표의 PR 제목 그대로
- 본문 템플릿:
  ```markdown
  ## Scope
  Phase N of codebase-cleanup — <description>
  Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §N

  ## Changes
  - <changes list>

  ## Verification
  - [x] `docker compose -f docker-compose.dev.yml build api` / `build ui`
  - [x] `go test ./...` green
  - [x] `npx playwright test specs/<related>` green
  - [x] Manual smoke (if applicable)

  ## Out of scope
  - <explicitly excluded items>
  ```

### 10.3 브랜치

- `phase1/docs-sync`
- `phase2/characterization-tests`
- `phase3/main-bootstrap`
- `phase4a/template-split`
- `phase4b/repo-split`
- `phase5/ui-component-split`
- `phase6/proxy-host-form-hooks`

모두 `main`에서 분기, 이전 Phase 머지 후 rebase.

---

## 11. 성공 기준 (Definition of Done)

프로젝트 완료 조건:

1. 7개 PR 전부 `main`에 머지됨
2. `git log --oneline main --since="2026-04-17"` 상 `release: v2.10.0` 커밋 생성
3. §2 목표 지표 전체 달성
4. `cd api && go test ./...` 녹색
5. `cd test/e2e && npx playwright test` 녹색
6. `docker compose -f docker-compose.dev.yml up -d` 기동 후 UI 로그인 + 프록시 호스트 생성 수동 확인
7. `CLAUDE.md`와 `ARCHITECTURE.md`의 파일 개수·디렉토리 구조 표가 실제 `find` 결과와 일치

## 12. 예상 일정

각 Phase는 동일한 Claude Code 세션에서 연속 진행 가정. 실제 소요는 예상 기반 추정.

| Phase | 예상 소요 | 누적 |
|-------|---------|------|
| 1 | 1h | 1h |
| 2 | 4h | 5h |
| 3 | 3h | 8h |
| 4a | 4h | 12h |
| 4b | 5-6h | 17-18h |
| 5 | 6h | 23-24h |
| 6 | 4h | 27-28h |

**총 예상: ~27-28시간** (연속이 아니라도 누적 작업 시간). 실제 일정은 리뷰 대기 등으로 더 길어질 수 있음.

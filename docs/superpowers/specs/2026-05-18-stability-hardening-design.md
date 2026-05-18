# Stability Hardening (P0 + P1) — Design Spec

> **Date:** 2026-05-18
> **Target Version:** post-2.13.19 (e.g., 2.14.0)
> **Scope:** HTTP/HTTPS template partial 분리, 3-way 동기화 자동 검증, 차단 변수 회귀 가드 (E2E), ModSec audit fixture 자동화
> **Author:** Pair session (user: svrforum / jmlee0108@toss.im)
> **Priority:** Stability first — load-bearing 테스트는 Playwright + 실제 nginx 기반

## 1. Background

v2.13.19까지 활발한 유지보수와 합리적 핵심 설계를 갖췄지만, **코드 평가에서 두 부류의 부채**가 식별됨:

### 1.1 구조적 부채 (회귀 위험 큼)

1. **HTTP/HTTPS 템플릿 중복** — `base.conf.tmpl`(691줄, HTTP)과 `ssl.conf.tmpl`(~700줄, HTTPS)이 보안 로직 ~650줄을 거의 동일하게 복제. #137(에러 페이지 언어), #129(force-HTTPS)가 모두 한쪽만 고쳐 발생한 회귀였음.
2. **3-way 수동 동기화 부재** — DB 마이그레이션 3곳(init.sql 본문 / init.sql UPGRADE SECTION / migration.go upgradeSQL) 및 백업 3파일(model / export / import) 동기화가 CLAUDE.md 문서로만 강제됨. 컴파일·CI가 누락을 잡지 못해 누락 시 데이터 손실급 사고로 이어짐.

### 1.2 조용한 실패 패턴 (사용자 incident로만 발견됨)

3. **차단 사유 추적 누락 반복** — 최근 30일 5건의 버그 픽스(#130, #133, #134, #137, f0be478)가 모두 "보안 레이어가 차단은 하지만 `$block_reason_var`가 비거나 잘못 채워짐". nginx 빌드/룰 매칭(403)은 정상이지만 로그·UI에 "왜 막혔는지" 안 적힘 → 사용자가 인지 후 보고로 발견.
4. **ModSec audit JSON 포맷 변화 미감지** — #139에서 ModSecurity 3.0.15가 `http_version`을 number → string으로 바꿔 파서가 깨졌고, WAF 로그 전부가 DB에 도달 못 함. nginx 빌드·룰 매칭만으로는 회귀 감지 불가.

### 1.3 범위 확정 (브레인스토밍 결과)

- **범위 레벨:** **P0 + P1** — 안정성 위주, P2(service 파일 분할)·P3(log pipeline 재검토 등)은 후속
- **HTTP/HTTPS 통합 방식:** Go template partial 분리 (`{{template "_security" .}}`)
- **3-way 검증 위치:** Go 단위 테스트 (`go test ./...`에 자연스럽게 포함)
- **차단 변수 회귀 가드 깊이:** 단위 grep + **E2E (Playwright + 실제 nginx + 로그 ingestion 검증)** 병행. Load-bearing은 E2E.
- **ModSec fixture 자동화:** Schema lockfile + capture script + parser 검증 + E2E ingestion 검증 (3-layer)

### 1.4 범위 밖 (명시적 배제)

- service 파일 분할(filter_subscription 863줄 등) — P2 후속
- 마이그레이션 파일 분할(001_init.sql 단일 → 002, 003) — P2
- log pipeline 재검토(docker logs tail → fluent-bit) — P3
- 외부 의존성 circuit breaker — P3
- E2E nginx의 host mode → bridge 전환(SeaweedFS 충돌 근본 회피) — 별도 작업

---

## 2. Architecture Overview

4개 워크 아이템 (A·B·C·D)이 5개 Milestone (M0~M4)에 매핑됨.

| Milestone | 작업 | 핵심 산출물 | 의존 |
|-----------|------|------------|------|
| M0 | 사전 정찰 | UPGRADE SECTION 포맷, db tag 분포, GeoLite2 sample 라이선스 확인 메모 | - |
| M1 (A) | Template partial 분리 | `_common_init.conf.tmpl`, `_security.conf.tmpl`, `_challenge_endpoints.conf.tmpl` | M0 |
| M2 (B) | 3-way 동기화 검증 | `migration_sync_test.go`, `backup_sync_test.go` | M0 (병렬 가능) |
| M3 (C) | 차단 변수 회귀 가드 | `block_reason_regression_test.go` (단위) + `block-reason-regression.spec.ts` (E2E) + `log-helper.ts` | M1 |
| M4 (D) | ModSec fixture 자동화 | `capture-modsec-audit.sh`, schema lockfile, parser test, `waf-audit-format.spec.ts` | M0 (병렬 가능) |

### 2.1 검증 게이트 (모든 Milestone 공통)

1. `docker compose -f docker-compose.dev.yml build api` 성공
2. `docker compose -f docker-compose.dev.yml run --rm api go test ./...` green
3. `docker compose -f docker-compose.e2e-test.yml up -d --build` 후 `cd test/e2e && npx playwright test` green (영향 받는 spec 위주)
4. `docker exec npg-proxy nginx -t` 통과 (M1 이후)
5. Manual smoke: 호스트 생성 → 보안 레이어 활성화 → 차단 요청 → 로그 페이지 표시 확인

---

## 3. Milestone M1 — Template Partial 분리 (A항목)

### 3.1 현재 상태

`templates/proxy_host/` 9개 파일 중 `base.conf.tmpl`과 `ssl.conf.tmpl`이 SSL 디렉티브(~40줄) 외에 보안 로직 ~650줄을 거의 동일 복제.

복제된 블록 (라인 추정):

| 블록 | 줄 수 |
|------|------|
| 변수 초기화 + Search bot 검출 + Open File Cache + ACME 게이트 + 에러 페이지 | ~50 |
| Geo Direct Block + Geo Challenge Mode | ~160 |
| WAF (modsecurity on/off) | ~10 |
| Access List | ~10 |
| Block Exploits (4 타입) | ~185 |
| Banned IPs + Cloud IPs + Bot Filter (4종) + Filter Subscription UA | ~150 |
| Rate Limit + URI Block | ~45 |
| Challenge endpoints | ~40 |
| **공통 합계** | **~650** |

### 3.2 제안 구조

```
templates/proxy_host/
├── base.conf.tmpl              ★ HTTP 진입부만 (~50줄)
├── ssl.conf.tmpl               ★ HTTPS 진입부 + SSL 디렉티브만 (~80줄)
├── _common_init.conf.tmpl      🆕 변수 초기화, search bot, OFC, ACME 게이트, 에러 페이지
├── _security.conf.tmpl         🆕 Geo/WAF/AccessList/Exploit/Banned/Cloud/Bot/Filter/Rate/URI
├── _challenge_endpoints.tmpl   🆕 Challenge validate + api_fallback + /api/v1/challenge/
├── upstream.conf.tmpl          (변경 없음)
├── access_list.conf.tmpl       (변경 없음)
├── advanced.conf.tmpl
├── cache.conf.tmpl
├── header.conf.tmpl
├── rate_limit.conf.tmpl
└── waf.conf.tmpl
```

### 3.3 구현 메커니즘

`proxy_host_template.go`의 `template.New().ParseFiles(...)`에 새 partial 3개 추가:

```go
tmpl, err := template.New("proxy_host").Funcs(funcMap).ParseFiles(
    filepath.Join(templatesDir, "_common_init.conf.tmpl"),
    filepath.Join(templatesDir, "_security.conf.tmpl"),
    filepath.Join(templatesDir, "_challenge_endpoints.conf.tmpl"),
    filepath.Join(templatesDir, "base.conf.tmpl"),
    filepath.Join(templatesDir, "ssl.conf.tmpl"),
)
// 렌더 시 .ExecuteTemplate(buf, "base.conf.tmpl", data) 호출
```

각 partial 파일은 `{{define "_common_init"}}...{{end}}` 형태. base/ssl에서 `{{template "_common_init" .}}` 호출.

### 3.4 base.conf.tmpl (변경 후 스켈레톤)

```gotmpl
{{if .Host.Enabled}}
server {
    listen {{.HTTPPort}};
{{if .EnableIPv6}}    listen [::]:{{.HTTPPort}};
{{end}}    server_name {{join .Host.DomainNames " "}};

    {{template "_common_init" .}}
    {{template "_security" .}}
    {{template "_challenge_endpoints" .}}

    # proxy_pass / location / 마무리
    ...
}
{{end}}
```

### 3.5 ssl.conf.tmpl (변경 후 스켈레톤)

```gotmpl
{{if .Host.SSLEnabled}}
server {
    listen {{.HTTPSPort}} ssl;
{{if .EnableIPv6}}    listen [::]:{{.HTTPSPort}} ssl;
{{end}}{{if .Host.SSLHTTP2}}    http2 on;
{{end}}{{if .Host.SSLHTTP3}}    listen {{.HTTPSPort}} quic;
    listen [::]:{{.HTTPSPort}} quic;
    ssl_early_data on;
{{end}}    server_name {{join .Host.DomainNames " "}};

    # SSL 디렉티브 (cert path, protocols, ciphers, ecdh_curve)
    ssl_certificate /etc/nginx/certs/{{certPath .Host}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{certPath .Host}}/privkey.pem;
    ssl_protocols ...;

    {{template "_common_init" .}}
    {{template "_security" .}}
    {{template "_challenge_endpoints" .}}

    ...
}
{{end}}
```

### 3.6 회귀 방지 (Characterization)

기존 `proxy_host_template_characterization_test.go`를 확장. 변경 전 후 **byte-identical 렌더 결과** 보장이 핵심 invariant.

**Characterization 케이스 (8~10개)**:

| 케이스 | 데이터 | 검증 |
|-------|--------|------|
| minimal_enabled | 모든 보안 OFF, Enabled=true | base 블록 생성 |
| ssl_force_https | SSL on, force_https=true | base 리다이렉트 + ssl 본문 |
| all_security_on | Geo+WAF+AccessList+Exploit+Banned+Cloud+Bot+Filter+RateLimit+URIBlock 전부 활성 | base와 ssl partial 부분 동일 |
| http3_quic | SSLHTTP3=true | quic listen 추가 |
| no_ipv6 | EnableIPv6=false | `listen [::]` 누락 |
| (외 3~5개) | 다양한 조합 | |

**Invariant**: refactor 전 골든 파일과 refactor 후 렌더 결과가 (공백 정규화 후) 동일해야 함.

### 3.7 위험 & 완화

| 위험 | 완화 |
|------|------|
| 들여쓰기/공백 변화로 nginx config 시각 비교 어려움 | 변경 전 base/ssl 렌더 결과를 golden file에 dump → diff |
| `{{define}}` 블록의 `.` 컨텍스트가 호출 컨텍스트와 다를 가능성 | 모든 partial이 `.`로 호출되므로 동일. `$.` 참조도 그대로 |
| ssl.conf.tmpl만 SSL 한정 로직 누락 가능성 | 현재 코드에는 그런 분기 없음. characterization 테스트가 보장 |
| partial 누락 시 런타임 에러 | bootstrap 단계에서 즉시 발견 (API 시작 실패) → 운영자 즉시 인지 |

### 3.8 Commit 단위

M1 전체를 단일 커밋: `refactor(nginx): extract shared security partial from base/ssl templates`

---

## 4. Milestone M2 — 3-way 동기화 검증 (B항목)

### 4.1 마이그레이션 동기화 (`migration_sync_test.go`)

**불변 조건**: `001_init.sql` 하단 UPGRADE SECTION의 SQL 문과 `migration.go`의 `upgradeSQL` 배열 항목이 1:1 대응되어야 함. 누락 시 → 기존 사용자 업그레이드 실패 또는 신규 설치만 OK인 컬럼 발생.

**파일 위치**: `api/internal/database/migration_sync_test.go`

**검증 방식**:

```go
func TestMigrationUpgradeSync(t *testing.T) {
    upgradeFromSQL := extractUpgradeSection(t, "migrations/001_init.sql")
    upgradeFromGo := normalizeAll(upgradeSQL)
    diff := multisetDiff(upgradeFromSQL, upgradeFromGo)

    if len(diff.MissingFromGo) > 0 {
        t.Errorf("Statements in 001_init.sql UPGRADE SECTION but not in upgradeSQL:\n%s",
            strings.Join(diff.MissingFromGo, "\n---\n"))
    }
    if len(diff.MissingFromSQL) > 0 {
        t.Errorf("Statements in upgradeSQL but not documented in 001_init.sql:\n%s",
            strings.Join(diff.MissingFromSQL, "\n---\n"))
    }
}
```

**정규화 규칙**: 다중 공백 → 단일, 주석 제거, 키워드 대문자화, 끝 세미콜론 제거, 양쪽 trim.

**UPGRADE SECTION 파싱 전제**: 001_init.sql 하단에 `-- UPGRADE SECTION` 마커 라인 이후 각 SQL이 주석으로 시작(`-- ALTER TABLE ...`). M0에서 실제 포맷 확인하고 파서 룰 fit.

### 4.2 백업 동기화 (`backup_sync_test.go`)

**불변 조건**: 백업 대상 struct의 모든 `db:"col"` 태그가 `backup_export.go`의 SELECT와 `backup_import.go`의 INSERT 양쪽에 등장해야 함.

**파일 위치**: `api/internal/repository/backup_sync_test.go`

**검증 방식**: Reflection + Source grep

```go
targets := []struct {
    name        string
    structValue any
    exportFile  string
    importFile  string
    tableHint   string
}{
    {"ProxyHost", model.BackupProxyHost{}, "backup_export.go", "backup_import.go", "exportProxyHosts"},
    {"RedirectHost", model.BackupRedirectHost{}, "backup_export.go", "backup_import.go", "exportRedirectHosts"},
    // ... 추가 테이블 (M0에서 확정)
}

for _, tc := range targets {
    fields := dbTagFields(tc.structValue)
    exportSQL := extractFuncBody(t, tc.exportFile, tc.tableHint)
    importSQL := extractFuncBody(t, tc.importFile, tc.tableHint)

    for _, col := range fields {
        if !containsColumn(exportSQL, col) {
            t.Errorf("[%s] column %q in struct but missing from %s", tc.name, col, tc.exportFile)
        }
        if !containsColumn(importSQL, col) {
            t.Errorf("[%s] column %q in struct but missing from %s", tc.name, col, tc.importFile)
        }
    }
}
```

**전제**: 백업 대상 struct에 `db:"col"` 태그 일관 부착. 누락 시 M0에서 파악 → M2 일부로 태그 추가.

**`extractFuncBody`**: `go/parser` AST로 안전하게 함수 본문 추출. 명시적 마커(`// BACKUP_SYNC:ProxyHost:START`/`:END`)도 대안.

### 4.3 위험 & 완화

| 위험 | 완화 |
|------|------|
| 001_init.sql UPGRADE SECTION 포맷이 가정과 다름 | M0에서 실제 포맷 확인 → 파서 룰 fit. 필요 시 포맷 통일 작은 chore |
| `db:"..."` 태그 일부 struct 누락 | M0에서 파악 → 누락분 태그 추가 (백업 SQL과 이미 1:1 대응이라 위험 낮음) |
| extractFuncBody가 잘못 잘라냄 | AST 사용 또는 명시 마커 |
| 백업 대상이 아닌 컬럼 오탐 | struct에서 제외 또는 `db:"-"` 태그 |

### 4.4 Commit 단위

B.1과 B.2 별도 커밋:
- `test(migration): add upgradeSQL ↔ 001_init.sql UPGRADE SECTION sync guard`
- `test(backup): add struct ↔ export/import SQL sync guard`

---

## 5. Milestone M3 — 차단 변수 회귀 가드 (C항목)

### 5.1 검증 깊이 — 2-Layer

Load-bearing은 **E2E (Playwright + 실제 nginx + DB ingestion 검증)**. 단위 grep은 개발 사이클 빠른 피드백용 보조.

```
[Layer 1: 단위 grep]   block_reason_regression_test.go
   ↓ 18 케이스, 템플릿 렌더 후 substring 검증
   ↓ 실행 시간 < 1초, 매 go test 실행

[Layer 2: E2E]         block-reason-regression.spec.ts
   ↓ 18 케이스 × Playwright
   ↓ 호스트 생성 → trigger 요청 → access log → 파서 → DB → block_reason 검증
   ↓ 실행 시간 ~수 분, PR 머지 전 / nightly
```

### 5.2 검증 대상 — 18 케이스

| # | Layer | 데이터 트리거 | 기대 block_reason | 기대 상태 |
|---|-------|--------------|------------------|----------|
| 1 | Geo Direct Block (blacklist) | `Mode="blacklist", Countries=["KR"]` | `geo_block` | 403 |
| 2 | Geo Direct Block (whitelist) | `Mode="whitelist", Countries=["US"]` | `geo_block` | 403 |
| 3 | Geo Challenge Mode | `ChallengeMode=true` | `geo_block` | 200 (challenge page) |
| 4 | Access List | `Items=[{deny, 1.2.3.4}]` | `access_denied` | 403 |
| 5 | Exploit Block — query_string | `pattern_type: query_string` | `exploit_block` | 403 |
| 6 | Exploit Block — request_uri | `pattern_type: request_uri` | `exploit_block` | 403 |
| 7 | Exploit Block — user_agent | `pattern_type: user_agent` | `exploit_block` (bot_category=scanner) | 403 |
| 8 | Exploit Block — request_method | `pattern_type: request_method` | `exploit_block` | 405 |
| 9 | Banned IP (manual) | `BannedIPs=[...]` | `banned_ip` | 403 |
| 10 | Banned IP (filter sub) | `UseFilterSubscription=true` | `filter_subscription` | 403 |
| 11 | Cloud Provider Block | `BlockedCloudIPRanges=[...]` | `cloud_provider_block` | 403 |
| 12 | Cloud Provider Challenge | `CloudProviderChallengeMode=true` | `cloud_provider_challenge` | 418 |
| 13 | Bot Filter — bad_bot | `BlockBadBots=true` | `bot_filter` (bot_category=bad_bot) | 403 |
| 14 | Bot Filter — ai_bot | `BlockAIBots=true` | `bot_filter` (bot_category=ai_bot) | 403 |
| 15 | Bot Filter — suspicious | `BlockSuspiciousClients=true` | `bot_filter` (bot_category=suspicious) | 403 |
| 16 | Bot Filter — custom | `CustomBlockedAgents=...` | `bot_filter` (bot_category=custom) | 403 |
| 17 | Filter Subscription UA | `UseFilterSubscription=true` (UA 매칭) | `filter_subscription` | 403 |
| 18 | URI Block | `URIBlock.Enabled=true, Rules=[...]` | `uri_block` | 403 |

> Rate Limit(429)은 block_reason을 박지 않는 의도된 설계 — 케이스에 포함하되 `reason='-'` 검증.

### 5.3 Layer 1 — 단위 grep 테스트

**파일**: `api/internal/nginx/block_reason_regression_test.go`

**테이블 드리븐**:

```go
func TestBlockReasonRegression(t *testing.T) {
    base := minimalEnabledHost(t)

    tests := []struct {
        name   string
        data   func(d ProxyHostConfigData) ProxyHostConfigData
        reason string
        status int
        extra  []string
    }{
        {name: "geo_block_blacklist", data: withGeoBlacklist("CN"), reason: "geo_block", status: 403},
        {name: "exploit_user_agent_sets_scanner_category",
         data: withExploitRule("user_agent", "sqlmap"), reason: "exploit_block", status: 403,
         extra: []string{`set $bot_category_var "scanner"`}},
        {name: "cloud_challenge_mode_uses_418",
         data: withCloudChallenge(), reason: "cloud_provider_challenge", status: 418},
        // ... 18 케이스
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            output := renderProxyHost(t, tc.data(base))
            assertBlockReason(t, output, tc.reason)
            if tc.status != 0 {
                assertReturnStatus(t, output, tc.status)
            }
            for _, needle := range tc.extra {
                if !strings.Contains(output, needle) {
                    t.Errorf("missing %q in output", needle)
                }
            }
        })
    }
}
```

**A항목과의 시너지**: M1 partial 분리 후 base와 ssl이 같은 `_security.conf.tmpl`을 include → 18 케이스가 base 렌더에서 통과하면 ssl도 자동 보장 (characterization 테스트가 동일성 보장).

### 5.4 Layer 2 — E2E spec

**파일**: `test/e2e/specs/security/block-reason-regression.spec.ts`

**보조 유틸**:
- `test/e2e/utils/log-helper.ts` — `triggerRequest`, `pollForLog`
- `test/e2e/fixtures/geoip-test.mmdb` — MaxMind GeoLite2 sample
- `test/e2e/utils/api-helper.ts` — 보안 설정 헬퍼 확장 (`setGeoRestriction`, `setAccessList`, `setBannedIPs`, ...)

**케이스 단일 흐름**:

```ts
test('geo_block: blacklist mode records block_reason=geo_block in logs', async ({ request }) => {
  const api = new APIHelper(request);
  await api.login();

  const host = await api.createProxyHost({
    domain_names: [`geo-${randomId()}.test.local`],
    forward_host: 'whoami', forward_port: 80, forward_scheme: 'http',
    enabled: true,
  });
  await api.setGeoRestriction(host.id, {
    enabled: true, mode: 'blacklist', countries: ['KR'],
    allow_private_ips: false, allow_search_bots: false,
  });

  const resp = await triggerRequest({
    host: host.domain_names[0],
    proxyPort: 18080,
    spoofIP: '203.243.0.1',  // KR (KISA range)
  });
  expect(resp.status).toBe(403);

  const log = await pollForLog(api, {
    host_id: host.id,
    expected_block_reason: 'geo_block',
    timeoutMs: 10_000,
  });
  expect(log.block_reason).toBe('geo_block');
  expect(log.status).toBe(403);
  expect(log.geo_country).toMatch(/KR/);

  await api.deleteProxyHost(host.id);
});
```

**IP 스푸핑**: nginx의 `real_ip_header X-Forwarded-For` + `set_real_ip_from`에 사설 대역이 신뢰됨 → 테스트 러너에서 `X-Forwarded-For` 헤더로 spoof 가능.

**GeoIP DB**: MaxMind GeoLite2 sample을 fixture로 동봉 → e2e nginx에 마운트. 라이선스 텍스트 동봉.

**Parallel 실행**: 각 케이스 독립 (unique domain) → `test.describe.parallel()` 활용.

### 5.5 인프라 가드

**Playwright globalSetup**:
- Port 18080 점유 확인 (SeaweedFS 충돌 감지) → 점유 시 명확한 에러로 즉시 종료
- GeoLite2 sample fixture 존재 확인

### 5.6 단위 vs E2E 역할 분담

| 테스트 | 무엇을 검증 | 실행 빈도 |
|--------|------------|----------|
| `block_reason_regression_test.go` (단위) | 템플릿이 올바른 `set $block_reason_var` 텍스트 생성 | 매 `go test` (수 ms) |
| `block-reason-regression.spec.ts` (E2E) | nginx 실행 → 차단 → 로그 → 파서 → DB 도달 | PR 머지 전 / nightly (~수 분) |

**Load-bearing은 E2E.** 충돌 시 E2E 우선.

### 5.7 위험 & 완화

| 위험 | 완화 |
|------|------|
| 18 케이스 직렬 실행 시 느림 | `test.describe.parallel()` + unique domain 격리 |
| 로그 ingestion 비동기 → flaky | `pollForLog` 타임아웃 + 명확한 실패 메시지. ingestion이 sub-second면 안정적 |
| GeoLite2 sample 라이선스 | MaxMind GeoLite2는 명시적으로 테스트 허용. fixture 디렉토리에 LICENSE 동봉 |
| SeaweedFS 18080 충돌 시 모든 spec 실패 | globalSetup에서 점유 확인 → 명확한 에러로 즉시 종료 |
| 외부 IP DB 의존 (Cloudflare 범위, AI bot 리스트) | 테스트 시작 시 fixed seed로 DB seed |

### 5.8 Commit 단위

- `test(nginx): add block_reason variable unit-level regression guard`
- `test(e2e): add end-to-end block_reason ingestion spec for 18 security layers`

---

## 6. Milestone M4 — ModSec Audit Fixture 자동화 (D항목)

### 6.1 3-Layer 검증 구조

```
[Layer 1: Capture (E2E)]    scripts/capture-modsec-audit.sh
   ↓ e2e compose → SQLi/XSS/LFI/RFI 프로브 → audit log 캡처
   ↓ 산출물: testdata/modsec_audit_v{VERSION}.json
   ↓        testdata/modsec_audit_schema.json  ← lockfile

[Layer 2: Parser 단위 테스트]  log_collector_parser_test.go
   ↓ fixture 읽어 파서 적용 → 핵심 필드 검증
   ↓ schema lockfile 대비 누락/추가/타입 변화 감지

[Layer 3: E2E ingestion]    waf-audit-format.spec.ts
   ↓ WAF 활성화 호스트 → SQLi 요청 → DB logs_partitioned(log_type='modsec') 행 검증
```

### 6.2 Layer 1 — Capture Script

**파일**: `scripts/capture-modsec-audit.sh` + `scripts/extract-schema.jq`

**동작 흐름**:

1. e2e 환경 기동 (이미 떠 있으면 skip)
2. WAF 활성화된 테스트 호스트 생성 (api-helper)
3. 표준 probe set 발사 — SQLi, XSS, LFI, RFI, Shellshock, Scanner UA (각 ModSec rule family 1개씩)
4. nginx 컨테이너에서 `/var/log/nginx/modsec_audit.log` 수집
5. `extract-schema.jq`로 schema 추출 (key + type, 재귀)
6. 기존 `modsec_audit_schema.json`과 diff:
   - 동일 → 통과, fixture 갱신만
   - 다름 → 사람에게 review 요구하고 실패. 의도된 변화면 새 schema commit

**산출물**:
- `api/internal/service/testdata/modsec_audit_v{VERSION}.json` — full audit JSON samples
- `api/internal/service/testdata/modsec_audit_schema.json` — key/type lockfile

**Lockfile 예시**:

```json
{
  "transaction": {
    "client_ip": "string",
    "request": {
      "method": "string",
      "http_version": "string",
      "uri": "string"
    },
    "response": { "http_code": "number" },
    "messages": [{
      "details": {
        "ruleId": "string",
        "severity": "string"
      }
    }]
  }
}
```

→ ModSec이 `http_version`을 또 바꾸거나 새 필드 추가하면 **diff에서 즉시 보임**.

### 6.3 Layer 2 — Parser 단위 테스트

**파일**: `api/internal/service/log_collector_parser_test.go` (기존, `d683ea6`에서 fixture pin 완료)

**추가 테스트**:

```go
func TestModSecParser_FixtureSchema(t *testing.T) {
    versions := []string{"3.0.15"}  // 향후 버전 추가
    for _, v := range versions {
        t.Run("v"+v, func(t *testing.T) {
            fixtureBytes := readTestdata(t, fmt.Sprintf("modsec_audit_v%s.json", v))
            var entries []map[string]any
            require.NoError(t, json.Unmarshal(fixtureBytes, &entries))
            require.NotEmpty(t, entries)

            // 1. 파서가 모든 fixture entry를 무손실로 파싱
            for i, raw := range entries {
                rawBytes, _ := json.Marshal(raw)
                parsed, err := parseModSecAudit(rawBytes)
                require.NoError(t, err, "entry %d", i)
                assert.NotEmpty(t, parsed.Transaction.UniqueID)
                assert.NotEmpty(t, parsed.Transaction.Request.URI)
            }

            // 2. fixture schema가 lockfile과 일치
            extractedSchema := extractSchemaFromJSON(t, entries[0])
            lockedSchema := readLockfile(t, "modsec_audit_schema.json")
            require.Equal(t, lockedSchema, extractedSchema,
                "Fixture schema does not match lockfile. Run scripts/capture-modsec-audit.sh and review.")
        })
    }
}
```

**파서 회복력 (이미 `38802ae`에서 작업됨)**:

```go
type HTTPVersion string
func (h *HTTPVersion) UnmarshalJSON(b []byte) error {
    var s string
    if err := json.Unmarshal(b, &s); err == nil { *h = HTTPVersion(s); return nil }
    var n json.Number
    if err := json.Unmarshal(b, &n); err == nil { *h = HTTPVersion(n.String()); return nil }
    return fmt.Errorf("http_version: not string nor number: %s", b)
}
```

### 6.4 Layer 3 — E2E ingestion spec

**파일**: `test/e2e/specs/security/waf-audit-format.spec.ts` (신규)

기존 `waf.spec.ts`는 "차단 동작" 검증, 새 spec은 **"audit JSON 파이프라인 끝까지 도달"** 검증:

```ts
test('modsec audit JSON parsed end-to-end with required fields', async ({ request }) => {
  const api = new APIHelper(request);
  await api.login();

  const host = await api.createProxyHost({
    domain_names: [`waf-audit-${randomId()}.test.local`],
    forward_host: 'whoami', forward_port: 80, forward_scheme: 'http',
    enabled: true, waf_enabled: true,
    waf_mode: 'blocking', waf_paranoia_level: 1,
  });

  const probeResp = await triggerRequest({
    host: host.domain_names[0],
    proxyPort: 18080,
    path: "/?q=1'+OR+1=1--",
  });
  expect(probeResp.status).toBe(403);

  const log = await pollForLog(api, {
    host_id: host.id,
    expected_log_type: 'modsec',
    timeoutMs: 10_000,
  });
  expect(log.rule_id).toMatch(/^\d{6}$/);   // CRS rule ID (6자리)
  expect(log.severity).toMatch(/CRITICAL|WARNING|NOTICE|ERROR|ALERT/);
  expect(log.message).toBeTruthy();
  expect(log.matched_data).toBeTruthy();
  expect(log.uri).toContain('q=');
  expect(log.client_ip).toBeTruthy();

  await api.deleteProxyHost(host.id);
});
```

### 6.5 운영 SOP — ModSec 버전 업그레이드

`nginx/CLAUDE.md`의 기존 6단계 체크리스트에 capture script 단계 추가:

```bash
# 1. Dockerfile ARG 수정 → MODSECURITY_VERSION
# 2. nginx 이미지 재빌드 (e2e용)
docker compose -f docker-compose.e2e-test.yml build --no-cache nginx
docker compose -f docker-compose.e2e-test.yml up -d

# 3. fixture 재캡처 (schema diff 자동 검출)
scripts/capture-modsec-audit.sh

# 4. 파서 수정 (필요 시)
vim api/internal/service/log_collector_parser.go

# 5. 단위 + E2E 통합 검증
docker compose -f docker-compose.dev.yml run --rm api go test ./internal/service/... -run ModSec
cd test/e2e && npx playwright test specs/security/waf-audit-format.spec.ts
```

### 6.6 위험 & 완화

| 위험 | 완화 |
|------|------|
| capture script가 e2e 환경 의존 → CI 무거움 | capture script는 로컬/SOP 도구. CI는 Layer 2만 실행. fixture 갱신은 명시적 commit |
| ModSec audit log 비동기 flush 타이밍 | nginx audit log는 sync 가능. 그래도 1초 sleep + retry |
| Probe response가 차단 안 됨 | CRS paranoia 1 + 단순 SQLi는 보장. fail 시 환경 문제로 즉시 인지 |
| Schema lockfile 끝없이 커짐 | 정상. ModSec audit JSON 자체가 ~50 필드 수준 |
| 누가 script 실행 잊음 | Layer 2 파서 테스트가 lockfile 불일치 시 빌드 실패 |

### 6.7 Commit 단위

- `feat(modsec): add audit JSON capture script and schema lockfile` (D.1+D.2)
- `test(e2e): add ModSec audit pipeline ingestion spec` (D.3)
- `docs(nginx): update ModSec version bump checklist with capture step` (D.4)

---

## 7. Implementation Order & Schedule

### 7.1 의존성 그래프

```
M0 사전 정찰
   ├─→ M1 (A) ──→ M3 (C)
   ├─→ M2 (B)                (M1과 병렬 가능)
   └─→ M4 (D)                (M1과 병렬 가능)
```

### 7.2 일정 추정

| Milestone | 소요 | 누적 (단일 작업자) |
|-----------|------|-------------------|
| M0 사전 정찰 | 0.5d | 0.5d |
| M1 Template partial | 1.5d | 2.0d |
| M2 3-way sync | 1.0d | 3.0d |
| M3 차단 변수 가드 | 2.5d | 5.5d |
| M4 ModSec fixture | 1.5d | 7.0d |

**총 ~7 working days.** M2/M4를 M1/M3와 컨텍스트 스위치로 병렬 진행 시 ~5–6일 가능.

### 7.3 권장 작업 순서 (단일 작업자 기준)

1. **M0** — 사전 정찰 (메모만)
2. **M1.A.0** — Characterization 골든 파일 캡처 (refactor 전 baseline 확정)
3. **M1.A.1** — partial 추출
4. **M1.A.2** — characterization 통과 확인 + nginx -t
5. **M2.B.1** — Migration sync test (M1과 분리된 영역, 짧은 휴식 효과)
6. **M2.B.2** — Backup sync test
7. **M3.C.1** — 단위 grep 테스트 (M1 partial 위에)
8. **M4.D.1+D.2** — Capture script + parser schema 테스트 (E2E 환경 한 번 띄운 김에 D 먼저)
9. **M3.C.2** — E2E block-reason-regression (log-helper 작성 후 18 케이스)
10. **M4.D.3** — E2E waf-audit-format
11. **M4.D.4** — CLAUDE.md SOP 갱신

---

## 8. Definition of Done

전체 작업 완료라 말할 수 있는 조건:

- [ ] `docker compose -f docker-compose.dev.yml run --rm api go test ./...` 전체 통과
- [ ] `docker compose -f docker-compose.e2e-test.yml up -d --build` 후:
  - [ ] `cd test/e2e && npx playwright test specs/security/block-reason-regression.spec.ts` 18 케이스 통과
  - [ ] `cd test/e2e && npx playwright test specs/security/waf-audit-format.spec.ts` 통과
- [ ] 기존 E2E spec(`waf.spec.ts`, `geoip.spec.ts`, `exploit-rules.spec.ts` 등) 회귀 없음
- [ ] `scripts/capture-modsec-audit.sh` 로컬 실행 시 현재 lockfile과 일치 (no diff)
- [ ] `docker exec npg-proxy nginx -t` 통과 (M1 이후)
- [ ] `nginx/CLAUDE.md` ModSec 체크리스트에 capture 단계 명시
- [ ] `ARCHITECTURE.md` 갱신 — Template 구조(§nginx) 반영
- [ ] **사용자 명시적 승인** 후 release (CLAUDE.md: release flow needs approval)

---

## 9. 후속 작업 (이번 범위 밖)

이 작업의 결과로 회귀 가드(M2/M3/M4)가 깔리면 다음 P2/P3 후속 작업이 안전하게 진행 가능:

- **P2** service 파일 분할 (filter_subscription 863줄 → catalog/subscribe/refresh 분리)
- **P2** 마이그레이션 파일 분할 (`001_init.sql` 단일 → `002_*.sql`, `003_*.sql`)
- **P2** nginx config 재생성 벤치마크 (100/500 호스트 시 SyncAllConfigs 소요시간)
- **P3** log pipeline 재검토 (docker logs tail → fluent-bit/promtail 직접 연동)
- **P3** 외부 의존성 circuit breaker (ACME/GeoIP/Filter fetch에 exponential backoff)
- 별도 작업: E2E nginx의 host mode → bridge 전환 (SeaweedFS 18080 충돌 근본 회피)

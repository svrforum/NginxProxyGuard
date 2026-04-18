# NPG Community Filter Subscription System — Design Spec

## 개요

커뮤니티 기반 보안 필터 구독 시스템. AdGuard/Adblock 필터 리스트 모델을 보안 위협에 적용.
별도 레포(`svrforum/npg-filters`)에서 커뮤니티가 필터를 관리하고, NPG 본체가 이를 구독하여 자동 반영.

**지원 필터 타입:** IP, CIDR, User-Agent (3가지만)

**핵심 원칙:** 구독 기능이 어떻게 실패하든 기존 프록시 서비스는 영향받지 않는다.

---

## Part 1 — npg-filters 레포 구조

**레포:** `https://github.com/svrforum/npg-filters`

### 디렉토리 구조

```
npg-filters/
├── README.md
├── schema.json                    # 필터 리스트 JSON 스키마
├── lists/
│   ├── ips/                       # 단일 IP 필터
│   │   ├── web-scanners.json
│   │   └── brute-force.json
│   ├── cidrs/                     # IP 대역 필터
│   │   ├── known-botnets.json
│   │   └── tor-exits.json
│   └── user-agents/               # 악성 UA 패턴
│       ├── sql-injection-tools.json
│       └── scraper-bots.json
├── tools/
│   ├── validate.py                # 스키마 검증 + 형식 체크
│   └── build-index.py             # lists/ 스캔 → index.json 자동 생성
└── .github/
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        ├── validate.yml           # PR 시 검증
        └── build-index.yml        # main 머지 시 index.json 빌드 + 커밋
```

### 빌드 결과물 (CI 자동 생성)

```
npg-filters/
└── index.json                     # 카탈로그 (CI 자동 생성, 수동 편집 금지)
```

### 필터 리스트 포맷

```json
{
  "name": "Web Scanners",
  "description": "알려진 웹 취약점 스캐너 IP",
  "type": "ip",
  "expires": "24h",
  "max_entries": 5000,
  "entries": [
    {
      "value": "1.2.3.4",
      "reason": "Nuclei scanner",
      "added": "2026-03-30",
      "contributor": "github-username"
    }
  ]
}
```

필드 설명:

| 필드 | 필수 | 설명 |
|------|------|------|
| `name` | ✅ | 리스트 이름 |
| `description` | ✅ | 리스트 설명 |
| `type` | ✅ | `ip`, `cidr`, `user_agent` 중 하나 |
| `expires` | ✅ | 권장 갱신 주기 (`6h`, `12h`, `24h`, `48h`) |
| `max_entries` | ❌ | 파일당 최대 항목 수 (기본 5,000) |
| `entries` | ✅ | 필터 항목 배열 |
| `entries[].value` | ✅ | IP, CIDR, 또는 UA 정규식 패턴 |
| `entries[].reason` | ✅ | 차단 사유 |
| `entries[].added` | ✅ | 추가 날짜 (YYYY-MM-DD) |
| `entries[].contributor` | ✅ | GitHub 사용자명 |

### index.json 포맷 (CI 자동 생성)

```json
{
  "version": 1,
  "generated_at": "2026-03-31T00:00:00Z",
  "lists": [
    {
      "name": "Web Scanners",
      "description": "알려진 웹 취약점 스캐너 IP",
      "type": "ip",
      "path": "lists/ips/web-scanners.json",
      "entry_count": 127,
      "updated_at": "2026-03-31T00:00:00Z"
    }
  ]
}
```

### CI 검증 항목

- JSON 스키마 유효성
- IP/CIDR 형식 유효성
- UA 정규식 컴파일 가능 여부
- 파일당 항목 수 제한 (5,000개)
- 리스트 간 중복 체크
- 항목당 `reason` 필수
- 사설/루프백 IP 거부 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`)

---

## Part 2 — NPG 본체 DB 설계

### 신규 테이블: `filter_subscriptions`

```sql
CREATE TABLE IF NOT EXISTS public.filter_subscriptions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL UNIQUE,
    format TEXT NOT NULL DEFAULT 'npg-json',
    type TEXT NOT NULL,
    enabled BOOLEAN DEFAULT true,
    refresh_type TEXT NOT NULL DEFAULT 'interval',
    refresh_value TEXT NOT NULL DEFAULT '24h',
    last_fetched_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    entry_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
```

필드 설명:

| 필드 | 설명 |
|------|------|
| `format` | `npg-json` (npg-filters 포맷) 또는 `plaintext` (Spamhaus, FireHOL 등) |
| `type` | `ip`, `cidr`, `user_agent` |
| `refresh_type` | `interval` (주기별), `daily` (매일 정해진 시간), `cron` (cron 표현식) |
| `refresh_value` | interval: `6h`, `12h`, `24h`, `48h` / daily: `03:00` / cron: `0 */6 * * *` |
| `last_fetched_at` | 마지막 fetch 시도 시각 |
| `last_success_at` | 마지막 성공 시각 |
| `last_error` | 마지막 실패 에러 메시지 (성공 시 NULL) |

### 신규 테이블: `filter_subscription_entries`

```sql
CREATE TABLE IF NOT EXISTS public.filter_subscription_entries (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    subscription_id UUID NOT NULL REFERENCES filter_subscriptions(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(subscription_id, value)
);
CREATE INDEX idx_fse_subscription ON filter_subscription_entries(subscription_id);
CREATE INDEX idx_fse_value ON filter_subscription_entries(value);
```

- 기존 `banned_ips`, `bot_filters` 테이블은 건드리지 않음
- 구독에서 가져온 항목은 이 테이블에 별도 저장

### 신규 테이블: `filter_subscription_host_exclusions`

```sql
CREATE TABLE IF NOT EXISTS public.filter_subscription_host_exclusions (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    subscription_id UUID NOT NULL REFERENCES filter_subscriptions(id) ON DELETE CASCADE,
    proxy_host_id UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(subscription_id, proxy_host_id)
);
```

- "글로벌 적용 + 호스트별 예외" 구현
- 이 테이블에 등록된 (subscription_id, proxy_host_id) 조합은 해당 호스트에 미적용

### 설계 결정사항

- 기존 `banned_ips`, `bot_filters` 테이블 변경 없음 — 완전 독립 구조
- `ON DELETE CASCADE`로 구독 삭제 시 entries와 exclusions 자동 정리
- NPG 전체 구독 항목 총량 제한: 50,000개

---

## Part 3 — NPG API 엔드포인트

### 필터 구독 관리

```
GET    /api/v1/filter-subscriptions              # 구독 목록
POST   /api/v1/filter-subscriptions              # 구독 추가 (URL 직접 입력)
GET    /api/v1/filter-subscriptions/{id}          # 구독 상세 (항목 포함)
PUT    /api/v1/filter-subscriptions/{id}          # 구독 수정 (이름, 갱신주기, 활성화)
DELETE /api/v1/filter-subscriptions/{id}          # 구독 삭제 (entries 포함 CASCADE)
POST   /api/v1/filter-subscriptions/{id}/refresh  # 수동 즉시 갱신
```

### 호스트별 예외 관리

```
GET    /api/v1/filter-subscriptions/{id}/exclusions              # 제외된 호스트 목록
POST   /api/v1/filter-subscriptions/{id}/exclusions/{hostId}     # 호스트 제외 추가
DELETE /api/v1/filter-subscriptions/{id}/exclusions/{hostId}     # 호스트 제외 해제
```

### 카탈로그 (npg-filters index.json 프록시)

```
GET    /api/v1/filter-subscriptions/catalog               # index.json fetch → 카탈로그 반환
POST   /api/v1/filter-subscriptions/catalog/subscribe      # 카탈로그에서 선택하여 구독
```

### Request/Response 예시

**구독 추가 (URL 직접 입력):**
```json
POST /api/v1/filter-subscriptions
{
  "url": "https://raw.githubusercontent.com/svrforum/npg-filters/main/lists/ips/web-scanners.json",
  "refresh_type": "interval",
  "refresh_value": "24h"
}
```
- `name`, `description`, `type`은 fetch 후 JSON에서 자동 추출
- 플레인텍스트 URL인 경우 사용자가 `name`, `type`을 직접 지정

**카탈로그 구독:**
```json
POST /api/v1/filter-subscriptions/catalog/subscribe
{
  "paths": [
    "lists/ips/web-scanners.json",
    "lists/cidrs/known-botnets.json"
  ],
  "refresh_type": "daily",
  "refresh_value": "03:00"
}
```
- base URL (`https://raw.githubusercontent.com/svrforum/npg-filters/main/`)은 NPG 설정에 저장

---

## Part 4 — 서비스 / 스케줄러 설계

### FilterSubscriptionService

```go
type FilterSubscriptionService struct {
    repo       *repository.FilterSubscriptionRepository
    httpClient *http.Client
    nginx      NginxManager
}
```

주요 메서드:

| 메서드 | 역할 |
|--------|------|
| `Create(ctx, req)` | URL fetch → 포맷 감지 → 파싱 → entries 저장 |
| `Update(ctx, id, req)` | 이름, 갱신 주기, 활성화 수정 |
| `Delete(ctx, id)` | 구독 + entries + exclusions CASCADE 삭제 → nginx reload |
| `Refresh(ctx, id)` | 재fetch → 기존 entries 전체 교체 (트랜잭션) |
| `GetCatalog(ctx)` | npg-filters index.json fetch → 반환 |
| `SubscribeFromCatalog(ctx, paths, refreshType, refreshValue)` | 카탈로그 항목들 일괄 구독 |
| `AddHostExclusion(ctx, subscriptionID, hostID)` | 호스트 제외 추가 → nginx reload |
| `RemoveHostExclusion(ctx, subscriptionID, hostID)` | 호스트 제외 해제 → nginx reload |

### 포맷 자동 감지 로직

```
1. HTTP GET → Content-Type 확인
2. 응답 본문 첫 바이트가 '{' → JSON 시도
   → "entries" 키 존재 → npg-json
   → 실패 → plaintext 폴백
3. 그 외 → plaintext (줄 단위 파싱)
   → '#', ';' 시작 → 주석 스킵
   → CIDR 표기('/' 포함) → type=cidr
   → IP 형식 → type=ip
   → 그 외 → 무시

**참고:** 플레인텍스트 포맷은 ip/cidr 타입만 지원. user_agent 타입은 정규식 패턴이므로 npg-json 포맷 전용.
```

### FilterRefreshScheduler

```
10분마다 체크 실행:
  → 각 구독의 refresh_type/refresh_value + last_fetched_at 비교
  → interval: last_fetched_at + interval 경과 여부
  → daily: 오늘 해당 시간 도래 + 아직 미실행 여부
  → cron: next run time 계산하여 도래 여부
  → 해당되는 구독만 fetch
  → 변경분 있으면 entries 트랜잭션 교체 → nginx config 재생성 + reload
  → 실패 시 last_error 기록, 기존 데이터 유지
```

### nginx config 생성 연동

`proxy_host_config.go`의 `getHostConfigData()` 수정:

```
기존 흐름:
  → ListBannedIPs (수동 차단)
  → BotFilter (수동 설정)

추가 흐름:
  → 해당 호스트가 제외되지 않은 ip/cidr 구독의 entries 조회
  → 해당 호스트가 제외되지 않은 user_agent 구독의 entries 조회
  → 기존 banned_ips + 구독 ip/cidr → 합산하여 deny 규칙 생성
  → 기존 bot_filter custom_blocked_agents + 구독 user_agent → 합산하여 UA 차단 규칙 생성
```

---

## Part 5 — 프론트엔드 UI 설계

### 라우트

```
/settings/filter-subscriptions    → FilterSubscriptionList.tsx
```

### 페이지 구성

**카탈로그 탭:**
- npg-filters index.json에서 가져온 필터 목록을 타입별(IP, CIDR, User Agent)로 그룹화
- 각 항목: 이름, 설명, 항목 수 표시
- 체크박스로 선택 → 갱신 방식 설정 → 일괄 구독

**내 구독 목록 탭:**
- 구독 중인 필터 리스트: 이름, 타입, 항목 수, 갱신 주기, 상태(정상/오류)
- 마지막 갱신 시각
- 액션: 수동 갱신, 설정, 삭제

**구독 추가 모달 (URL 직접 입력):**
- URL 입력
- 이름 (자동 감지 또는 직접 입력)
- 갱신 방식 선택: 주기별 / 매일 / 고급(cron)

**구독 설정 모달:**
- 갱신 방식 변경
- 호스트 제외 설정: 프록시 호스트 목록 + 체크박스로 제외할 호스트 선택

### 기존 페이지 연동

- **Banned IP 목록** (`/waf/banned-ips`): 구독에서 온 IP는 "필터 구독" 뱃지 표시, 수정/삭제 불가
- **봇 필터 설정** (프록시 호스트 보안 탭): 구독 UA 패턴 적용 중이면 안내 문구 표시

### i18n

- 신규 네임스페이스: `filterSubscription`
- ko, en 각 1개 JSON 파일

---

## Part 6 — 보안 / 악용 방지 / 안정성

### 레포 측 보안 (npg-filters)

| 위협 | 대응 |
|------|------|
| 악성 항목 PR | PR 리뷰 필수, CODEOWNERS 설정 |
| 과도한 항목 수 | CI에서 파일당 5,000개 제한 |
| 잘못된 형식 | CI에서 IP/CIDR 형식, UA 정규식 컴파일 검증 |
| 중복 항목 | CI에서 리스트 간 중복 체크 |
| 사설/루프백 IP | CI에서 사설 대역 거부 |

### NPG 측 보안

| 위협 | 대응 |
|------|------|
| SSRF (악성 URL) | fetch 시 사설 IP 대역 차단, 리다이렉트 제한 (최대 3회) |
| 과도한 총 항목 수 | 구독 전체 합산 50,000개 제한 |
| 거대한 응답 (DoS) | HTTP 응답 크기 제한 (10MB) |
| 느린 응답 (Slowloris) | fetch 타임아웃 30초 |
| 자기 자신 차단 | 자체 IP 포함 시 경고 로그 + 해당 항목 제외 |
| ReDoS | UA 패턴 컴파일 시 타임아웃, 실패 시 스킵 |
| 권한 | 관리자(admin) 전용, API 토큰 접근 가능 |

### 안정성 — fetch 격리

| 항목 | 방안 |
|------|------|
| 별도 goroutine | fetch는 메인 서비스와 분리, 실패해도 다른 기능 무영향 |
| 타임아웃 계층화 | HTTP connect 5초 + 전체 요청 30초 + 파싱 10초 |
| 메모리 보호 | 응답 스트리밍 파싱, 10MB 초과 시 즉시 중단 |
| panic recovery | fetch/파싱 goroutine에 recover 적용 |

### 안정성 — nginx config

| 항목 | 방안 |
|------|------|
| 점진적 적용 | 기존 debounce(2초) 메커니즘 활용 |
| nginx -t 필수 | 구독 데이터 반영 후에도 반드시 테스트 통과해야 reload |
| 롤백 | nginx -t 실패 시 반영 전 config로 자동 복원 |
| deny 규칙 상한 | 호스트당 10,000개 초과 시 `geo`/`map` 모듈 방식으로 전환 |

### 안정성 — 데이터 무결성

| 항목 | 방안 |
|------|------|
| 트랜잭션 교체 | `BEGIN → DELETE old → INSERT new → COMMIT`, 실패 시 롤백 |
| 빈 응답 보호 | fetch 결과 0건이면 기존 entries 유지 |
| 기존 기능 독립 | 수동 IP 차단, 봇 필터 등 기존 기능은 구독과 완전 독립 |

### 장애 시나리오별 동작

| 시나리오 | 동작 |
|----------|------|
| GitHub 다운 | fetch 실패 → last_error 기록, 기존 데이터로 계속 동작 |
| 잘못된 JSON | 파싱 실패 → 기존 entries 유지, 에러 로그 |
| DB 디스크 풀 | INSERT 실패 → 트랜잭션 롤백, 기존 상태 유지 |
| 메모리 부족 | 10MB 제한 + 총량 50,000개 제한으로 사전 방지 |
| nginx -t 실패 | config 롤백, 서비스 무중단 |
| 구독 URL 변조 | 사설IP 차단 + 크기 제한 + 형식 검증으로 방어 |

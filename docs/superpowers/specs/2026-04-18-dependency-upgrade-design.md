# Dependency Upgrade Design — v2.12.0 & v2.13.0

- **Date**: 2026-04-18
- **Status**: Approved (design phase)
- **Scope**: Full stack dependency upgrade (frontend, backend, infra)
- **Baseline**: v2.11.0

## 1. Background

현재 프로젝트 전반의 의존성 최신도를 점검한 결과, 다수의 메이저·마이너 버전 갱신이 가능함을 확인했다. 장기 보안·성능·생태계 호환 유지를 위해 전체 업그레이드를 수행한다. Node.js는 LTS(22.x) 유지를 전제한다.

### 1.1 Current vs Latest (조사 완료)

| Area | Component | Current | Latest | Decision |
|------|-----------|---------|--------|----------|
| Frontend | React | 18.3.1 | 19.2.5 | → 19.x (Phase 2) |
| Frontend | Vite | 6.0.1 | 8.0.8 | → 7.x (Phase 2, 7이 더 성숙) |
| Frontend | TypeScript | 5.6.2 | 6.0.3 | → 5.9.x (Phase 1, 6은 너무 최신) |
| Frontend | TailwindCSS | 3.4.15 | 4.2.2 | → 4.x (Phase 2) |
| Frontend | @tanstack/react-query | 5.60 | 5.99 | → 5.99 (Phase 1) |
| Frontend | react-router-dom | 7.9.6 | 7.14.1 | → 7.14 (Phase 1) |
| Frontend | recharts | 3.5.1 | 3.8.1 | → 3.8 (Phase 1) |
| Frontend | i18next | 25.7.1 | 26.0.5 | → 26.x (Phase 2) |
| Frontend | react-i18next | 16.4.0 | (compat w/ i18next 26) | → Phase 2 동반 |
| Frontend | ESLint | 9.39.2 | 10.2.1 | → 10.x (Phase 2) |
| Frontend | Node (builder) | 22-alpine | 22 LTS | 유지 |
| Backend | Go toolchain | 1.22.0 / 1.22.12 | 1.26.2 | → 1.25 (Phase 1, 1.26은 너무 최신) |
| Backend | Go container base | 1.24-alpine | 1.26.x | → 1.25-alpine (Phase 1) |
| Backend | Echo | v4.12.0 | v4.15.0 (v5.1.0 있음) | → v4.15 (Phase 1, v5는 메이저 브레이킹) |
| Infra | Nginx | 1.28.0 | 1.30.0 | → 1.30.0 (Phase 1) |
| Infra | ModSecurity | 3.0.14 | 3.0.14 | 유지 (최신) |
| Infra | OWASP CRS | 4.21.0 | 4.25.0 | → 4.25.0 (Phase 1) |
| Infra | Valkey | 8-alpine | 9.0.3 | → 9-alpine (Phase 2) |
| Infra | TimescaleDB/PG | 17-pg17 | pg17 지원 | 유지 |
| Infra | Alpine | 3.23 | 3.23 | 유지 |

## 2. Goals

- 장기 안정성이 확보된 최신 버전으로 전체 스택 갱신
- 안정 동작 보장을 위한 **단계적 릴리즈**(v2.12.0 → v2.13.0)
- 각 변경을 독립 커밋으로 분리하여 `git bisect` 가능하도록 유지
- 모든 단계에서 **전체 E2E(Playwright) 통과**를 완료 게이트로 강제

### 2.1 Non-Goals

- TypeScript 6, Echo v5, Go 1.26, Vite 8 등 **최신 직후 버전**은 이번 차수에서 다루지 않음 (다음 사이클)
- 의존성 추가/삭제 없는 **순수 업그레이드** (리팩터링·기능 변경은 제외)
- Node.js 메이저 변경 없음 (22 LTS 유지)

## 3. Approach — 리스크별 2단계

```
main (v2.11.0)
  │
  ├─ phase1/low-risk-upgrades ──▶ v2.12.0   (약 1주)
  │    · 저위험 마이너/패치/보안 패치
  │    · 단일 PR 내 커밋 단위로 작업 분리
  │    · E2E 전체 통과 후 머지
  │
  └─ phase2/major-upgrades    ──▶ v2.13.0   (약 2–3주)
       · 메이저 브레이킹 체인지
       · 하위 단계(2.1~2.6) 커밋으로 분리 → 각 단계별 E2E
       · 최종 통합 E2E 통과 후 머지·릴리즈
```

- **하나의 브랜치·하나의 릴리즈** 원칙 — 버전 혼입을 방지
- **커밋 분리**는 bisect 및 부분 revert를 위해 필수
- 릴리즈는 두 번만 발생: **v2.12.0**, **v2.13.0**

## 4. Phase 1 — v2.12.0 (Low-Risk Bundle)

브랜치: `phase1/low-risk-upgrades`

### 4.1 Backend (Go)

| 변경 | From → To | 커밋 힌트 |
|------|-----------|-----------|
| `api/go.mod` `go` directive + toolchain | 1.22.0 → **1.25** | `chore(api): bump Go toolchain to 1.25` |
| `api/Dockerfile` base image | `golang:1.24-alpine` → `golang:1.25-alpine` | 위 커밋에 포함 |
| Echo | v4.12.0 → **v4.15.0** | `chore(api): bump Echo to v4.15` |
| 간접 의존성 일괄 패치 | `go get -u ./... && go mod tidy` | `chore(api): patch-level dep updates` |

### 4.2 Infra

| 변경 | From → To | 커밋 힌트 |
|------|-----------|-----------|
| `nginx/Dockerfile` `NGINX_VERSION` | 1.28.0 → **1.30.0** | `chore(nginx): bump Nginx to 1.30.0` |
| `nginx/Dockerfile` `OWASP_CRS_VERSION` | 4.21.0 → **4.25.0** | `chore(nginx): bump CRS to 4.25.0` |
| ModSecurity / Alpine / TimescaleDB / Valkey 8 / Node 22 | 유지 | — |

### 4.3 Frontend (마이너·패치)

| 변경 | From → To | 커밋 힌트 |
|------|-----------|-----------|
| TypeScript | 5.6.2 → **5.9.x** (5.x 최신) | `chore(ui): bump TypeScript to 5.9` |
| Vite | 6.0.1 → **6.x 최신** (메이저 라인 유지) | `chore(ui): patch-level Vite update` |
| @tanstack/react-query | 5.60.0 → **5.99.x** | 통합 |
| react-router-dom | 7.9.6 → **7.14.x** | 통합 |
| recharts | 3.5.1 → **3.8.x** | 통합 |
| i18next | 25.7.1 → **25.x 최신** (26은 Phase 2) | 통합 |
| 기타 devDependencies 패치 (@types/*, autoprefixer, postcss 등) | latest patch | 통합 커밋 |

### 4.4 버전 파일 갱신

- `api/internal/config/constants.go`: `AppVersion = "2.12.0"`
- `ui/package.json`: `"version": "2.12.0"`

### 4.5 Phase 1 완료 게이트 (모두 통과 시 머지)

1. `docker compose -f docker-compose.dev.yml build api ui nginx` 성공
2. `docker compose -f docker-compose.e2e-test.yml build --no-cache && up -d` 성공
3. `cd test/e2e && npx playwright test` 100% 통과
4. WAF 회귀 확인: `specs/security/waf.spec.ts`, `exploit-blocks.spec.ts` — CRS 4.25 오탐 부재
5. nginx 설정 테스트: `nginx -t` + 리로드 검증 (E2E에 포함)

## 5. Phase 2 — v2.13.0 (Major Bundle)

브랜치: `phase2/major-upgrades`. **하위 단계 순서**는 격리도 높은 것(외부 영향 작은 것) 먼저.

| # | 하위 단계 | 변경 | 격리도 | 주요 리스크 |
|---|-----------|------|--------|-------------|
| 2.1 | **Valkey 8 → 9** | `docker-compose*.yml`의 이미지 태그 한 줄 | 서버 단독 | 캐시 데이터 포맷(무해) |
| 2.2 | **Tailwind 3.4 → 4.x** | `tailwind.config.js`, `postcss.config.js`, `index.css` `@import` 문법, `@tailwindcss/vite` 플러그인 | CSS 단독 | 유틸 클래스 리네이밍, 다크모드 variant |
| 2.3 | **Vite 6 → 7** | `vite.config.ts`, 플러그인 업데이트 | 빌드 단독 | 노드 엔진 요구치, 기본 target |
| 2.4 | **ESLint 9 → 10 + typescript-eslint 최신** | `eslint.config.*`, 규칙/플러그인 | 정적 분석 단독 | 신규 경고·오류 대응 |
| 2.5 | **React 18.3 → 19.x** + `@types/react 19` + `react-dom 19` + `react-datepicker` 호환 버전 | 프론트엔드 전역 | 런타임 핵심 | Strict Mode 이펙트 재호출, ref 포워딩, 써드파티 호환 |
| 2.6 | **i18next 25 → 26** + `react-i18next` 호환 상향 | i18n 초기화 | 국제화 | init 옵션 변경, fallback 동작 |

### 5.1 Valkey 8 → 9 주의 (본 프로젝트 한정 영향)

본 프로젝트는 Valkey를 **스탠드얼론 캐시 전용**(`pkg/cache/redis.go`)으로 사용한다. 공식 릴리즈 노트 기준:
- 클러스터 기능 강화(Atomic Slot Migration, Numbered Databases) — **해당 없음**
- 신규 커맨드 `HEXPIRE`/`DELIFEQ`/지오 폴리곤 — 추가, 기존 기능 영향 없음
- 이전 deprecated 25개 커맨드 **복원** — 제거 아님
- Urgency **LOW**

코드에서 사용하는 커맨드는 모두 Redis 2.x/3.x 이래 안정된 기본 커맨드(`GET/SET/DEL/EXPIRE`, `SADD/SREM/SISMEMBER`, `ZADD/ZCARD/ZREMRANGEBYSCORE`, `INCR/EXPIRE/PEXPIRE`, `SETNX`, `XADD/XRANGE/XDEL/XLEN`, `INFO`, `DBSIZE`, `EVAL`). Valkey 9에서 동작 변경 없음.

CLAUDE.md 원칙 #5(Graceful Degradation)로 인해 캐시 자체가 실패해도 서비스는 유지됨. 최악의 경우 `docker volume rm npg_valkey_data`로 캐시 초기화 가능(무해).

### 5.2 하위 단계 작업 루틴 (2.1 ~ 2.6 공통)

```
1. 하위 단계별로 커밋 분리 (2.1부터 순서대로)
2. docker compose -f docker-compose.dev.yml build 성공
3. docker compose -f docker-compose.e2e-test.yml 재빌드·기동
4. cd test/e2e && npx playwright test 전체 통과
5. 실패 시 해당 하위 단계 커밋 내에서 수정 (새 커밋 X)
6. 통과 시 다음 하위 단계 진행
```

### 5.3 추가 수동 점검 (UI 영향 있는 하위 단계만)

2.2(Tailwind 4), 2.5(React 19), recharts 렌더링 경로에서 다음을 수동 확인:
- 다크모드 토글 정상
- i18n 언어 전환 정상
- 대시보드 차트 렌더
- 프록시 호스트 폼(탭 기반) 정상 렌더

### 5.4 버전 파일 갱신

- `api/internal/config/constants.go`: `AppVersion = "2.13.0"`
- `ui/package.json`: `"version": "2.13.0"`

### 5.5 Phase 2 완료 게이트

1. 모든 하위 단계 통과
2. 최종 통합 E2E 100% 통과
3. CHANGELOG.md에 브레이킹 체인지 공지 작성
   - Tailwind 4 CSS 변경(커스텀 유틸 사용자용 안내)
   - React 19 동작 변경(Strict Mode, ref)
   - i18next 26 설정 변경
   - Valkey 9 안내(무해)

## 6. Release & Rollback

### 6.1 릴리즈 트리거

GitHub Actions의 `v*` 태그 푸시가 멀티아키텍처 이미지를 자동 빌드한다.

```bash
# Phase 1 완료
git checkout main && git merge --no-ff phase1/low-risk-upgrades
git tag v2.12.0 && git push origin main v2.12.0

# Phase 2 완료 (2–3주 뒤)
git checkout main && git merge --no-ff phase2/major-upgrades
git tag v2.13.0 && git push origin main v2.13.0
```

### 6.2 롤백 매트릭스

| 상황 | 조치 |
|------|------|
| Phase 1 작업 중 E2E 실패 | 해당 커밋 내 수정 (새 커밋 금지) |
| Phase 1 머지 후 프로덕션 이슈 | `git revert` merge 커밋 → `v2.11.0` 이미지 재배포 |
| Phase 2 하위 단계 실패 | 해당 하위 단계 커밋만 revert, 이전 하위 단계 보존 |
| Phase 2 머지 후 프로덕션 이슈 | `git revert` merge 커밋 → `v2.12.0` 이미지 재배포 |
| Valkey 9 볼륨 호환 이슈 | 컨테이너 중지 → `docker volume rm npg_valkey_data` → 재시작 |

GitHub Actions가 태그별 이미지를 영구 보관하므로 이전 버전 재배포에 재빌드가 필요하지 않다.

## 7. Commit Style

- CLAUDE.md 규칙 준수: `Generated with Claude Code` 및 `Co-Authored-By: Claude` 서명 **금지**
- 형식: `type(scope): description`
  - `chore(ui): bump React to 19.2`
  - `chore(api): bump Echo to v4.15`
  - `chore(nginx): bump CRS to 4.25.0`

## 8. Out-of-Scope / Deferred

- TypeScript 6.0 — 릴리즈 직후, 타입 생태계 적응기 필요
- Echo v5 — 메이저 브레이킹, 레퍼런스 부족
- Go 1.26 — 최신 직후
- Vite 8 — React 19·Tailwind 4 조합 실전 레퍼런스 Vite 7 쪽이 풍부
- 이들은 다음 사이클에서 재평가

## 9. Open Questions / Future Work

- Phase 2 완료 후 위 Deferred 항목들의 성숙도 재평가 시점: v2.13.0 릴리즈 후 1~2 분기
- Vite 8 / Echo v5 전환은 각각 별도 설계·릴리즈(v2.14 또는 v3.0)

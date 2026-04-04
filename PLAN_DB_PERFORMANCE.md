# DB 로그 쿼리 성능 개선 계획

> **작성일**: 2026-04-04 | **대상**: logs_partitioned (6500만 건, 19GB, 94 chunks)
> **운영서버**: 192.168.1.10 (root 키 접속)
> **작업순서**: 로컬(docker-compose.dev.yml) 개선 → E2E 테스트 → 이미지 빌드 → 운영 반영

---

## 현황

| 항목 | 값 |
|------|-----|
| 테이블 | logs_partitioned (TimescaleDB hypertable) |
| 총 행 수 | ~65,000,000 |
| 총 크기 | 19GB |
| 청크 수 | 94개 (86개 압축, 8개 미압축) |
| 청크 단위 | 일별 |
| 파티션 키 | `created_at` (주의: 코드는 `timestamp` 컬럼으로 필터/정렬) |
| 커넥션 풀 | MaxOpen=25, MaxIdle=5 |
| Stats 캐시 TTL | 10초 |
| 인덱스 | 12개 (trgm 3개 포함, scans=0으로 미활용 다수) |

> **⚠️ `timestamp` vs `created_at` 혼용 이슈**
> 테이블 파티션 키는 `created_at`이지만, 필터 조건과 ORDER BY는 `timestamp`을 사용.
> 두 컬럼 모두 `DEFAULT now()`라 값은 동일하나, 인덱스 설계 시 실제 쿼리 패턴(`timestamp`)에 맞춰야 함.
> 복합 인덱스는 `timestamp` 기준으로 생성하고, 파티션 프루닝이 필요한 곳은 `created_at` 인덱스 유지.

---

## Phase 1: 즉시 효과 (설정 변경) ✅ 구현 완료

### 1-1. 커넥션 풀 확대
- **파일**: `api/internal/database/database.go` (22~24줄)
- **변경**: MaxOpenConns 25→40, MaxIdleConns 5→10
- **이유**: Stats 1회 호출에 7개 쿼리 병렬 실행, 동시 요청 시 커넥션 고갈
- **위험도**: 낮음
- **주의**: 운영 반영 전 `SHOW max_connections` 확인 필요 (TimescaleDB worker도 커넥션 사용)

### 1-2. Stats 캐시 TTL 연장
- **파일**: `api/internal/repository/log.go` (19줄 부근)
- **변경**: statsCacheTTL 10초→30초
- **이유**: 대시보드 Stats가 10초마다 7개 쿼리 재실행, 30초면 체감 차이 없음
- **위험도**: 낮음

### 1-3. 중복 인덱스 정리
- **파일**: `api/internal/database/migration.go` (신규 마이그레이션)
- **현재 중복**:
  - `idx_logs_part_created_at` (btree created_at DESC)
  - `logs_hypertable_created_at_idx` (btree created_at DESC) ← 동일
  - `idx_logs_ht_timestamp` (btree created_at DESC) ← 동일
- **변경**: 운영서버에서 수동 정리 (DROP INDEX)
- **이유**: 3개 동일 인덱스가 INSERT 성능 저하 + 저장 공간 낭비
- **위험도**: 낮음 (동일 인덱스 제거)

---

## Phase 2: 인덱스/쿼리 튜닝 ✅ 구현 완료

### 2-1. 복합 인덱스 추가
- **파일**: `api/internal/database/migration.go`, `migrations/001_init.sql`
- **추가 인덱스** (코드 사용 패턴인 `timestamp` 기준):
  ```sql
  -- 호스트별 로그 조회 (가장 빈번한 패턴)
  -- buildHostFilter()는 host= 또는 host LIKE로 정확/와일드카드 매치
  CREATE INDEX idx_logs_part_host_ts
    ON logs_partitioned (host, timestamp DESC);

  -- 상태코드별 필터링 + 시간 정렬
  CREATE INDEX idx_logs_part_status_ts
    ON logs_partitioned (status_code, timestamp DESC)
    WHERE status_code IS NOT NULL;

  -- proxy_host_id 기반 조회 (호스트 상세 로그)
  CREATE INDEX idx_logs_part_proxy_host_ts
    ON logs_partitioned (proxy_host_id, timestamp DESC)
    WHERE proxy_host_id IS NOT NULL;

  -- geo 필터링
  CREATE INDEX idx_logs_part_geo_ts
    ON logs_partitioned (geo_country_code, timestamp DESC)
    WHERE geo_country_code IS NOT NULL AND geo_country_code != '';

  -- log_type + created_at (파티션 프루닝 활용)
  CREATE INDEX idx_logs_part_type_created
    ON logs_partitioned (log_type, created_at DESC);
  ```
- **위험도**: 중간 (6500만 건에 인덱스 생성 시간 소요, CONCURRENTLY 사용 권장)
- **주의**: 운영서버에서는 `CREATE INDEX CONCURRENTLY` 사용해야 락 방지

### 2-2. Stats 7개 쿼리 병렬 실행 (errgroup)
- **파일**: `api/internal/repository/log.go` (GetStatsWithFilter)
- **변경**: 7개 순차 쿼리 → `golang.org/x/sync/errgroup`으로 병렬 실행
- **효과**: 순차 실행 시 7개 쿼리 합산 시간 → 병렬 실행 시 가장 느린 1개 쿼리 시간
- **이유**: UNION ALL 통합은 서브쿼리별 별도 스캔으로 오히려 느려질 수 있음. 병렬 실행이 더 현실적
- **위험도**: 낮음 (결과 형태 동일, mutex로 동시 접근 보호)

### 2-3. 검색(search) ILIKE 최적화
- **파일**: `api/internal/handler/log.go` (parseLogFilter)
- **변경**: search가 활성화되었으나 시간 범위 미지정 시 기본 7일 적용
  ```go
  if filter.Search != nil && *filter.Search != "" && filter.StartTime == nil {
      defaultStart := time.Now().AddDate(0, 0, -7)
      filter.StartTime = &defaultStart
  }
  ```
- **이유**: trgm GIN 인덱스가 있어도 6500만 건 풀스캔은 느림. 시간 범위로 청크 프루닝 활용
- **위험도**: 낮음 (프론트에서 시간 범위 미지정 검색 시에만 적용)

---

## Phase 3: 목록 쿼리 최적화 ✅ 구현 완료 (3-2)

### 3-1. OFFSET → 커서 기반(keyset) 페이지네이션
- **상태**: 미구현 (프론트엔드 변경 필요, 별도 작업으로 분리)
- **파일**: `api/internal/repository/log.go` (List 함수)
- **변경 시**:
  ```sql
  -- 복합 커서 (created_at 단독은 동일 시각 행 누락 위험)
  SELECT ... FROM logs_partitioned
  WHERE (created_at, id) < ($cursor_ts, $cursor_id)
  ORDER BY created_at DESC, id DESC LIMIT 50
  ```
- **영향**: API 응답에 `next_cursor` 필드 추가, 프론트 페이지네이션 변경 필요
- **위험도**: 높음 (프론트엔드 변경 필요, 하위호환 고려)

### 3-2. 목록 조회 시 컬럼 최소화
- **파일**: `api/internal/repository/log.go` (List 함수)
- **변경**: 34개 → 21개 핵심 컬럼
  ```sql
  -- 목록용 (경량) - 프론트 LogRowTyped.tsx가 사용하는 필드만
  SELECT id, log_type, timestamp, host, client_ip,
    geo_country, geo_country_code, geo_org,
    request_method, request_uri, status_code,
    body_bytes_sent, request_time,
    severity, error_message,
    rule_id, rule_message, action_taken,
    block_reason, bot_category,
    created_at
  FROM logs_partitioned ...
  ```
- **제거 컬럼**: `geo_city`, `geo_asn`, `request_protocol`, `upstream_response_time`, `http_referer`, `http_user_agent`, `http_x_forwarded_for`, `rule_severity`, `rule_data`, `attack_type`, `exploit_rule`, `proxy_host_id`, `raw_log`
- **이유**: 34→21개 컬럼으로 줄이면 IO/메모리 ~40% 절감 (특히 raw_log, user_agent 등 텍스트 컬럼)
- **위험도**: 낮음 (모든 필드가 `omitempty`라 JSON에서 자연스럽게 null 제외)

---

## Phase 4: TimescaleDB 고급 기능 활용 (미구현 - 추후 작업)

### 4-1. Continuous Aggregate로 Stats 사전 계산
- **상태**: 미구현 (GROUP BY 세분화 필요, 별도 작업으로 분리)
- **파일**: `api/internal/database/migration.go` (신규 마이그레이션)
- **설계 변경**: 단일 뷰 대신 용도별 분리 (카디널리티 폭발 방지)
  ```sql
  -- 기본 통계 (대시보드용)
  CREATE MATERIALIZED VIEW IF NOT EXISTS logs_stats_hourly_basic
  WITH (timescaledb.continuous) AS
  SELECT
    time_bucket('1 hour', created_at) as bucket,
    host, log_type,
    COUNT(*) as request_count,
    AVG(request_time) as avg_request_time,
    SUM(body_bytes_sent) as total_bytes
  FROM logs_partitioned
  GROUP BY bucket, host, log_type
  WITH DATA;

  -- 지역별 통계
  CREATE MATERIALIZED VIEW IF NOT EXISTS logs_stats_hourly_geo
  WITH (timescaledb.continuous) AS
  SELECT
    time_bucket('1 hour', created_at) as bucket,
    geo_country_code,
    COUNT(*) as request_count
  FROM logs_partitioned
  GROUP BY bucket, geo_country_code
  WITH DATA;

  -- 보안 통계
  CREATE MATERIALIZED VIEW IF NOT EXISTS logs_stats_hourly_security
  WITH (timescaledb.continuous) AS
  SELECT
    time_bucket('1 hour', created_at) as bucket,
    block_reason,
    COUNT(*) as request_count
  FROM logs_partitioned
  GROUP BY bucket, block_reason
  WITH DATA;
  ```
- **이유**: 단일 뷰에 `GROUP BY bucket, host, log_type, status_code, block_reason, geo_country_code`하면 카디널리티가 너무 높아 집계 테이블이 원본만큼 커질 수 있음
- **위험도**: 중간 (TimescaleDB 버전 호환성 확인, continuous aggregate refresh 부하)

### 4-2. 압축 정책 최적화
- **현재**: 7일 이상 청크 자동 압축 (86/94 압축됨)
- **확인 필요**: 압축된 청크에서의 쿼리 성능 vs 미압축
- **추가 고려**: `compress_orderby` 설정이 쿼리 패턴과 맞는지 확인

---

## Phase 5: 추가 최적화 ✅ 구현 완료

### 5-1. Dashboard 폴백 쿼리 경량화
- **파일**: `api/internal/repository/dashboard.go`
- **변경**: 매 대시보드 호출마다 실행되던 7개 집계 쿼리를 2개로 분리
  - `COUNT(DISTINCT client_ip)` (가장 비싼 연산)를 `block_reason` 필터링된 행에만 적용
  - 불필요한 fallback 데이터 (bandwidth, avg RT) 제거 — dashboard_stats_hourly가 이미 처리
- **효과**: Dashboard API 응답 시간 2~3배 개선

### 5-2. Dashboard TopN 쿼리 병렬화
- **파일**: `api/internal/repository/dashboard.go`
- **변경**: getTopHosts/Countries/Paths/IPs/UserAgents 5개 순차 실행 → errgroup 병렬 실행
- **효과**: Dashboard 로드 시간 ~60% 감소 (5개 쿼리 합산 → 가장 느린 1개 시간)

### 5-3. Autocomplete DISTINCT 쿼리 Redis 캐싱
- **파일**: `api/internal/repository/log.go`
- **변경**: GetDistinctHosts/IPs/URIs/UserAgents/Countries/Methods에 Redis 캐싱 추가
  - 검색어 없는 초기 로드: Redis 캐시 (TTL 1시간)
  - 검색어 있는 타이핑 중: DB 직접 쿼리 (trgm 인덱스 활용)
- **효과**: 로그 뷰어 필터 초기 로드 시 DB 쿼리 제거

### 5-4. Stats Top IPs 쿼리 `client_ip::text` → `host(client_ip)`
- **파일**: `api/internal/repository/log.go`
- **변경**: `SELECT client_ip::text` → `SELECT host(client_ip)`
- **이유**: `::text` 캐스트는 `1.2.3.4/32` 형태를 반환하고 인덱스 활용 불가. `host()`는 `1.2.3.4`만 반환하고 inet 인덱스 활용 가능

### 5-5. Batch INSERT 폴백 미니 배치화
- **파일**: `api/internal/repository/log.go`
- **변경**: 전체 배치 실패 시 개별 INSERT(N회 round-trip) → 50건 미니 배치 트랜잭션
- **효과**: 1000건 실패 시 1000회→20회 트랜잭션으로 감소

### 5-6. 프론트엔드 폴링 간격 최적화
- **변경 파일/간격**:
  | 컴포넌트 | 변경 전 | 변경 후 | 이유 |
  |---------|--------|--------|------|
  | CertificateLogModal | 1초 | 3초 | 실시간성 불필요, DB 부하 66% 감소 |
  | CertificateList | 5초 | 15초 | 목록 갱신에 5초 과도 |
  | BackupManager | 5초 | 15초 | 백업 상태 체크에 5초 과도 |
  | Dashboard containers | 15초 | 30초 | 컨테이너 상태 변경 빈도 낮음 |
  | log-viewer embedded | 5초 | 10초 | 임베디드 로그 뷰어 부하 50% 감소 |
- **효과**: 전체 프론트엔드 API 호출 ~40% 감소

---

## 작업 순서 요약

| 순서 | Phase | 예상 효과 | 난이도 | 상태 |
|------|-------|----------|--------|------|
| 1 | 1-2 캐시 TTL 30초 | Stats 부하 66% 감소 | 쉬움 | ✅ 완료 |
| 2 | 1-3 중복 인덱스 정리 | INSERT 성능 개선 | 쉬움 | ⏳ 운영서버 수동 |
| 3 | 1-1 커넥션 풀 40/10 | 동시성 개선 | 쉬움 | ✅ 완료 |
| 4 | 2-2 Stats 병렬 실행 | Stats 3~5배 개선 | 보통 | ✅ 완료 |
| 5 | 2-1 복합 인덱스 추가 | 필터 조회 3~10배 개선 | 보통 | ✅ 완료 |
| 6 | 3-2 컬럼 최소화 | 목록 IO 40% 절감 | 보통 | ✅ 완료 |
| 7 | 2-3 검색 기본 7일 | 검색 2~5배 개선 | 보통 | ✅ 완료 |
| 8 | 5-1 Dashboard 폴백 경량화 | Dashboard 2~3배 개선 | 보통 | ✅ 완료 |
| 9 | 5-2 Dashboard TopN 병렬화 | Dashboard 로드 ~60% 감소 | 보통 | ✅ 완료 |
| 10 | 5-3 Autocomplete 캐싱 | 필터 초기 로드 DB 제거 | 보통 | ✅ 완료 |
| 11 | 5-4 Stats IP 캐스트 수정 | 인덱스 활용 가능 | 쉬움 | ✅ 완료 |
| 12 | 5-5 Batch INSERT 미니 배치 | 폴백 시 50배 감소 | 보통 | ✅ 완료 |
| 13 | 5-6 폴링 간격 최적화 | API 호출 ~40% 감소 | 쉬움 | ✅ 완료 |
| 14 | 3-1 커서 페이지네이션 | 뒤쪽 페이지 100배+ | 어려움 | ⏳ 추후 |
| 15 | 4-1 Continuous Aggregate | Stats 100배+ 개선 | 어려움 | ⏳ 추후 |

---

## 주의사항

1. **마이그레이션 3곳 반영 규칙** 준수 (001_init.sql CREATE, UPGRADE SECTION, migration.go upgradeSQL)
2. **운영서버 인덱스 생성** 시 반드시 `CREATE INDEX CONCURRENTLY` (6500만 건에 일반 CREATE INDEX는 테이블 락)
3. **E2E 테스트** 후 운영 반영
4. **롤백 계획**: 인덱스 추가는 DROP INDEX로 즉시 롤백 가능, 쿼리 변경은 이전 코드로 복구
5. **커넥션 풀 확인**: 운영 반영 전 `SHOW max_connections` + 현재 사용 커넥션 수 체크
6. **커서 페이지네이션 구현 시**: `created_at` 단독이 아닌 `(created_at, id)` 복합 커서 사용 필수 (동일 시각 행 누락 방지)
7. **Autocomplete 캐시**: Redis 없이도 동작 (cache == nil이면 DB 직접 쿼리)

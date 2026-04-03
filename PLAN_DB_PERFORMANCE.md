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
| 커넥션 풀 | MaxOpen=25, MaxIdle=5 |
| Stats 캐시 TTL | 10초 |
| 인덱스 | 12개 (trgm 3개 포함, scans=0으로 미활용 다수) |

---

## Phase 1: 즉시 효과 (설정 변경)

### 1-1. 커넥션 풀 확대
- **파일**: `api/internal/database/database.go` (22~24줄)
- **변경**: MaxOpenConns 25→50, MaxIdleConns 5→15
- **이유**: Stats 1회 호출에 7개 쿼리 실행, 동시 요청 시 커넥션 고갈
- **위험도**: 낮음 (PostgreSQL 기본 max_connections=100)

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
- **변경**: 2개 제거, 1개만 유지
- **이유**: 3개 동일 인덱스가 INSERT 성능 저하 + 저장 공간 낭비
- **위험도**: 낮음 (동일 인덱스 제거)

---

## Phase 2: 인덱스/쿼리 튜닝

### 2-1. 복합 인덱스 추가
- **파일**: `api/internal/database/migration.go` (신규 마이그레이션)
- **추가할 인덱스**:
  ```sql
  -- 호스트별 로그 조회 (가장 빈번한 패턴)
  CREATE INDEX idx_logs_part_host_created 
    ON logs_partitioned (host, created_at DESC);
  
  -- 상태코드별 필터링 + 시간 정렬
  CREATE INDEX idx_logs_part_status_created 
    ON logs_partitioned (status_code, created_at DESC) 
    WHERE status_code IS NOT NULL;
  
  -- proxy_host_id 기반 조회 (호스트 상세 로그)
  CREATE INDEX idx_logs_part_proxy_host_created 
    ON logs_partitioned (proxy_host_id, created_at DESC) 
    WHERE proxy_host_id IS NOT NULL;
  
  -- geo 필터링
  CREATE INDEX idx_logs_part_geo_country 
    ON logs_partitioned (geo_country_code, created_at DESC) 
    WHERE geo_country_code IS NOT NULL AND geo_country_code != '';
  ```
- **이유**: 현재 단일 컬럼 인덱스만 있어서 복합 조건 시 인덱스 활용 못함
- **위험도**: 중간 (6500만 건에 인덱스 생성 시간 소요, CONCURRENTLY 사용 권장)
- **주의**: 운영서버에서는 `CREATE INDEX CONCURRENTLY` 사용해야 락 방지

### 2-2. Stats 7개 쿼리 → 1~2개로 통합
- **파일**: `api/internal/repository/log.go` (GetStatsWithFilter, 815~1214줄)
- **현재**: 7개 별도 쿼리 (count, status_codes, client_ips, user_agents, uris, rule_ids, countries)
- **변경**:
  ```sql
  -- 1개 쿼리로 count + 기본 통계 통합
  SELECT 
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE log_type = 'access') as access_count,
    COUNT(*) FILTER (WHERE log_type = 'error') as error_count,
    COUNT(*) FILTER (WHERE log_type = 'modsec') as modsec_count,
    COUNT(*) FILTER (WHERE block_reason != 'none') as blocked_count
  FROM logs_partitioned WHERE [conditions];
  
  -- Top N 집계는 2개 쿼리로 병합 (UNION ALL 또는 lateral join)
  ```
- **이유**: 동일 WHERE 조건으로 7번 스캔 → 2번으로 줄이면 3~4배 개선
- **위험도**: 중간 (쿼리 결과 형태가 바뀌므로 handler 수정 필요)

### 2-3. 검색(search) ILIKE 최적화
- **파일**: `api/internal/repository/log.go` (414~451줄 부근)
- **현재**: `host ILIKE '%term%' OR request_uri ILIKE '%term%' OR http_user_agent ILIKE '%term%' OR ...`
- **변경 방안**:
  - trgm GIN 인덱스가 이미 있으므로 `%term%` 패턴은 GIN이 처리 가능
  - 단, 여러 컬럼 OR 조건은 GIN 활용 어려움
  - **방법 A**: 검색 대상 컬럼 1개로 한정 (host만 or uri만) + 드롭다운 선택
  - **방법 B**: `to_tsvector` 기반 full-text search 인덱스 추가 (복합 컬럼)
  - **방법 C**: 현재 구조 유지하되 시간 범위 강제 (최근 7일 등)
- **권장**: 방법 C (가장 안전, UI 변경 불필요) + 시간 범위 미지정 시 기본 7일 적용
- **위험도**: 낮음~중간

---

## Phase 3: 페이지네이션 개선

### 3-1. OFFSET → 커서 기반(keyset) 페이지네이션
- **파일**: `api/internal/repository/log.go` (List 함수, 628~794줄)
- **현재**: `LIMIT $1 OFFSET $2` → 10만 번째 페이지면 10만*50행 스캔
- **변경**:
  ```sql
  -- 기존 (느림)
  SELECT ... FROM logs_partitioned ORDER BY created_at DESC LIMIT 50 OFFSET 5000
  
  -- 커서 기반 (빠름)
  SELECT ... FROM logs_partitioned 
  WHERE created_at < $cursor_timestamp 
  ORDER BY created_at DESC LIMIT 50
  ```
- **영향**: 
  - API 응답에 `next_cursor` 필드 추가
  - 프론트엔드 페이지네이션 로직 변경 (페이지 번호 → "다음/이전" 방식)
  - 기존 page/per_page 파라미터도 하위호환으로 유지
- **이유**: OFFSET이 커지면 성능 선형 저하, 커서는 항상 일정
- **위험도**: 높음 (프론트엔드 변경 필요, 하위호환 고려)

### 3-2. 목록 조회 시 컬럼 최소화
- **파일**: `api/internal/repository/log.go` (List 함수)
- **현재**: 33개 컬럼 전체 SELECT
- **변경**: 목록용 경량 쿼리 (10~15개 핵심 컬럼)
  ```sql
  -- 목록용 (경량)
  SELECT id, log_type, created_at, host, client_ip, 
         request_method, request_uri, status_code, 
         body_bytes_sent, request_time, block_reason, 
         geo_country_code, bot_category
  FROM logs_partitioned ...
  
  -- 상세용 (전체 컬럼) - 기존 유지
  SELECT * FROM logs_partitioned WHERE id = $1
  ```
- **이유**: 33→13개 컬럼으로 줄이면 IO/메모리 ~60% 절감
- **위험도**: 중간 (프론트에서 목록에 없는 필드 참조하는지 확인 필요)

---

## Phase 4: TimescaleDB 고급 기능 활용

### 4-1. Continuous Aggregate로 Stats 사전 계산
- **파일**: `api/internal/database/migration.go` (신규 마이그레이션)
- **변경**:
  ```sql
  -- 시간별 통계 자동 집계 (TimescaleDB Continuous Aggregate)
  CREATE MATERIALIZED VIEW IF NOT EXISTS logs_stats_hourly
  WITH (timescaledb.continuous) AS
  SELECT 
    time_bucket('1 hour', created_at) as bucket,
    host,
    log_type,
    status_code,
    block_reason,
    geo_country_code,
    COUNT(*) as request_count,
    AVG(request_time) as avg_request_time,
    SUM(body_bytes_sent) as total_bytes
  FROM logs_partitioned
  GROUP BY bucket, host, log_type, status_code, block_reason, geo_country_code
  WITH DATA;
  
  -- 자동 갱신 정책
  SELECT add_continuous_aggregate_policy('logs_stats_hourly',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour');
  ```
- **이유**: Stats 조회가 사전 집계 테이블에서 읽으므로 65M 행 스캔 불필요
- **위험도**: 중간 (TimescaleDB 버전 호환성 확인, continuous aggregate refresh 부하)

### 4-2. 압축 정책 최적화
- **현재**: 7일 이상 청크 자동 압축 (86/94 압축됨)
- **확인 필요**: 압축된 청크에서의 쿼리 성능 vs 미압축
- **추가 고려**: `compress_orderby` 설정이 쿼리 패턴과 맞는지 확인

---

## 작업 순서 요약

| 순서 | Phase | 예상 효과 | 난이도 | 프론트 변경 |
|------|-------|----------|--------|------------|
| 1 | 1-1 커넥션 풀 | 동시성 개선 | 쉬움 | 없음 |
| 2 | 1-2 캐시 TTL | Stats 부하 66% 감소 | 쉬움 | 없음 |
| 3 | 1-3 중복 인덱스 정리 | INSERT 성능 개선 | 쉬움 | 없음 |
| 4 | 2-1 복합 인덱스 추가 | 필터 조회 3~10배 개선 | 보통 | 없음 |
| 5 | 2-2 Stats 쿼리 통합 | Stats 3~4배 개선 | 보통 | 없음 |
| 6 | 2-3 검색 최적화 | 검색 2~5배 개선 | 보통 | 없음 |
| 7 | 3-2 컬럼 최소화 | 목록 IO 60% 절감 | 보통 | 확인 필요 |
| 8 | 3-1 커서 페이지네이션 | 뒤쪽 페이지 100배+ 개선 | 어려움 | 필요 |
| 9 | 4-1 Continuous Aggregate | Stats 100배+ 개선 | 어려움 | 없음 |

---

## 주의사항

1. **마이그레이션 3곳 반영 규칙** 준수 (001_init.sql CREATE, UPGRADE SECTION, migration.go upgradeSQL)
2. **운영서버 인덱스 생성** 시 반드시 `CREATE INDEX CONCURRENTLY` (6500만 건에 일반 CREATE INDEX는 테이블 락)
3. **E2E 테스트** 후 운영 반영
4. **롤백 계획**: 인덱스 추가는 DROP INDEX로 즉시 롤백 가능, 쿼리 변경은 이전 코드로 복구

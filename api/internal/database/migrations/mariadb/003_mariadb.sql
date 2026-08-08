-- Nginx Proxy Guard — MariaDB/MySQL 보충 스키마
--
-- 001_init.sql, 002_upgrades.sql과 달리 손으로 작성한 파일입니다. 여기 있는 것은
-- 전부 생성기가 PostgreSQL 원본에서 유도할 수 없는 객체들입니다. PostgreSQL
-- 정의가 PL/pgSQL DO 블록이거나, 형태 차이가 커서 기계적 재작성이 추측이 되는
-- 경우입니다.
--
-- 부팅할 때마다 재실행됩니다. 모든 문장은 멱등해야 합니다.

-- ---------------------------------------------------------------------------
-- ddns_records.proxy_host_id (#157)
--
-- PostgreSQL은 ADD CONSTRAINT에 IF NOT EXISTS가 없어 duplicate_object 오류를
-- 삼키는 DO 블록으로 이 변경을 적용합니다. 여기서는 둘 다 IF NOT EXISTS를
-- 지원하므로 평범한 문장 두 개로 끝납니다.
-- ---------------------------------------------------------------------------
ALTER TABLE ddns_records ADD COLUMN IF NOT EXISTS proxy_host_id VARCHAR(36);

ALTER TABLE ddns_records
    ADD CONSTRAINT ddns_records_proxy_host_id_fkey
    FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;

-- ---------------------------------------------------------------------------
-- logs_unified
--
-- PostgreSQL은 이 뷰를 동적으로 만듭니다. 파티션 테이블 마이그레이션 후에도
-- 레거시 `logs` 테이블이 남아 있을 때만 그것과 `logs_partitioned`를 UNION 합니다.
-- MariaDB/MySQL 설치에는 그런 이력이 없습니다. 첫 부팅부터 파티션 테이블이
-- 존재하고 로그 수집기도 거기에만 쓰므로, 이 뷰는 단순한 투영입니다. 테이블을
-- 직접 가리키지 않고 뷰로 두는 이유는 질의 계층을 두 백엔드에서 동일하게
-- 유지하기 위해서입니다.
--
-- CREATE OR REPLACE라 멱등하고, 업그레이드 시 컬럼 목록 변경도 반영됩니다.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW logs_unified AS
SELECT
    id, log_type, "timestamp", host, client_ip,
    geo_country, geo_country_code, geo_city, geo_asn, geo_org,
    request_method, request_uri, request_protocol, status_code,
    body_bytes_sent, request_time, upstream_response_time,
    http_referer, http_user_agent, http_x_forwarded_for,
    severity, error_message,
    rule_id, rule_message, rule_severity, rule_data,
    attack_type, action_taken,
    block_reason, bot_category,
    proxy_host_id, raw_log, created_at,
    upstream_addr, upstream_status
FROM logs_partitioned;

-- Nginx Proxy Guard — MariaDB/MySQL 초기 스키마
--
-- 생성된 파일입니다. 직접 수정하지 마세요.
-- 원본   : api/internal/database/migrations/001_init.sql (PostgreSQL)
-- 재생성 : python3 scripts/pg2mariadb-schema.py
--
-- 멱등합니다. 모든 객체를 IF NOT EXISTS로 생성합니다.

-- --------------------------------------------------------------------------
-- Tables
-- --------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_list_items (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    access_list_id VARCHAR(36) NOT NULL,
    directive VARCHAR(10) NOT NULL,
    address VARCHAR(255) NOT NULL,
    description TEXT,
    sort_order INT DEFAULT 0,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT access_list_items_directive_check CHECK (directive IN ('allow', 'deny'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS access_lists (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    satisfy_any BOOLEAN DEFAULT true,
    pass_auth BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS api_token_usage (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    token_id VARCHAR(36) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INT,
    client_ip VARCHAR(45),
    user_agent TEXT,
    request_body_size BIGINT,
    response_time_ms INT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS api_tokens (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    user_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    token_prefix VARCHAR(16) NOT NULL,
    permissions JSON NOT NULL DEFAULT ('["*"]'),
    allowed_ips TEXT,
    rate_limit INT DEFAULT 1000,
    expires_at DATETIME(6),
    last_used_at DATETIME(6),
    last_used_ip VARCHAR(45),
    use_count BIGINT DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    revoked_at DATETIME(6),
    revoked_reason VARCHAR(255),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY api_tokens_token_hash_key (token_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    user_id VARCHAR(36),
    username VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(255),
    resource_id VARCHAR(255),
    resource_name VARCHAR(255),
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin PAGE_COMPRESSED=1 PAGE_COMPRESSION_LEVEL=1;
CREATE TABLE IF NOT EXISTS auth_providers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL DEFAULT 'custom',
    provider_url TEXT NOT NULL,
    config JSON NOT NULL DEFAULT ('{}'),
    timeout_ms INT NOT NULL DEFAULT 5000,
    enabled BOOLEAN NOT NULL DEFAULT true,
    container_name TEXT,
    container_network TEXT,
    container_port INT,
    container_scheme TEXT,
    last_resolved_ip TEXT,
    last_reconcile_at DATETIME(6),
    last_reconcile_status TEXT,
    last_reconcile_error TEXT,
    reconcile_fail_count INT NOT NULL DEFAULT 0,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT auth_providers_type_check CHECK (type IN ('authelia', 'authentik', 'custom'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS auth_sessions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    user_id VARCHAR(36) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS backups (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL DEFAULT 0,
    file_path VARCHAR(500) NOT NULL,
    includes_config BOOLEAN NOT NULL DEFAULT true,
    includes_certificates BOOLEAN NOT NULL DEFAULT true,
    includes_database BOOLEAN NOT NULL DEFAULT true,
    backup_type VARCHAR(20) NOT NULL DEFAULT 'manual',
    description TEXT,
    "status" VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    checksum_sha256 VARCHAR(64),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    completed_at DATETIME(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS banned_ips (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(255),
    fail_count INT DEFAULT 0,
    banned_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6),
    is_permanent BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    is_auto_banned BOOLEAN DEFAULT false,
    banned_ips_ip_global_key VARCHAR(768) AS (CASE WHEN proxy_host_id IS NULL THEN CONCAT_WS('\n', COALESCE(ip_address, '')) END) VIRTUAL,
    banned_ips_ip_host_key VARCHAR(768) AS (CASE WHEN proxy_host_id IS NOT NULL THEN CONCAT_WS('\n', COALESCE(ip_address, ''), COALESCE(proxy_host_id, '')) END) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_banned_ips_ip_global_unique (banned_ips_ip_global_key),
    UNIQUE KEY idx_banned_ips_ip_host_unique (banned_ips_ip_host_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS bot_filters (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    block_bad_bots BOOLEAN DEFAULT true,
    block_ai_bots BOOLEAN DEFAULT false,
    allow_search_engines BOOLEAN DEFAULT true,
    custom_blocked_agents TEXT,
    custom_allowed_agents TEXT,
    challenge_suspicious BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    block_suspicious_clients BOOLEAN DEFAULT false,
    disable_global BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id),
    UNIQUE KEY bot_filters_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS certificate_history (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    certificate_id VARCHAR(36) NOT NULL,
    action VARCHAR(50) NOT NULL,
    "status" VARCHAR(50) NOT NULL,
    message TEXT,
    domain_names TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    expires_at DATETIME(6),
    logs JSON,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS certificates (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    domain_names TEXT NOT NULL,
    expires_at DATETIME(6),
    certificate_path VARCHAR(512),
    private_key_path VARCHAR(512),
    provider VARCHAR(50) DEFAULT 'letsencrypt',
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    dns_provider_id VARCHAR(36),
    "status" VARCHAR(20) NOT NULL DEFAULT 'pending',
    acme_account JSON DEFAULT ('{}'),
    auto_renew BOOLEAN NOT NULL DEFAULT true,
    renewal_attempted_at DATETIME(6),
    issued_at DATETIME(6),
    error_message TEXT,
    certificate_pem TEXT,
    private_key_pem TEXT,
    issuer_certificate_pem TEXT,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS challenge_configs (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    enabled BOOLEAN DEFAULT true,
    challenge_type VARCHAR(20) DEFAULT 'recaptcha_v2',
    site_key VARCHAR(255),
    secret_key VARCHAR(255),
    token_validity INT DEFAULT 86400,
    min_score DECIMAL(3,2) DEFAULT 0.5,
    apply_to VARCHAR(20) DEFAULT 'both',
    page_title VARCHAR(255) DEFAULT 'Security Check',
    page_message TEXT DEFAULT ('Please complete the security check to continue.'),
    theme VARCHAR(10) DEFAULT 'light',
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY challenge_configs_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS challenge_logs (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    client_ip VARCHAR(45) NOT NULL,
    user_agent TEXT,
    result VARCHAR(20) NOT NULL,
    trigger_reason VARCHAR(255),
    captcha_score DECIMAL(3,2),
    solve_time INT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS challenge_tokens (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    token_hash VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    user_agent TEXT,
    challenge_reason VARCHAR(255),
    issued_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    use_count INT DEFAULT 0,
    last_used_at DATETIME(6),
    revoked BOOLEAN DEFAULT false,
    revoked_at DATETIME(6),
    revoked_reason VARCHAR(255),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS cloud_providers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(50) NOT NULL,
    region VARCHAR(50) NOT NULL,
    description TEXT,
    ip_ranges TEXT NOT NULL DEFAULT ('{}'),
    ip_ranges_url VARCHAR(500),
    last_updated DATETIME(6),
    enabled BOOLEAN DEFAULT true,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY cloud_providers_slug_key (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- v2.24.7: logs_partitioned index ensure (documentation only — canonical
-- execution lives in migration.go ensureLogsPartitionedIndexes).
-- The background hypertable migration creates a NEW table (with only four
-- idx_logs_ht_* basics) and renames the original to logs_partitioned_backup,
-- which KEEPS every original idx_logs_part_* index name. From then on every
-- `CREATE INDEX IF NOT EXISTS idx_logs_part_*` silently no-ops (the name
-- exists — on the wrong table), so upgraded installs ran the hypertable
-- with almost no indexes (incl. the pg_trgm search indexes from
-- 011_trgm_indexes, whose one-shot schema_migrations gate also never re-ran).
-- ensureLogsPartitionedIndexes runs after the swap and on every boot: it
-- reclaims names squatted by logs_partitioned_backup (DROP INDEX — the backup
-- is verification-only) and builds the canonical index set on the live table
-- using timescaledb.transaction_per_chunk to keep ingest unblocked.
-- v2.32.0: cloudflare_tunnel singleton (Phase 1 token mode)
CREATE TABLE IF NOT EXISTS cloudflare_tunnel (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT false,
    token TEXT NOT NULL DEFAULT (''),
    mode VARCHAR(20) NOT NULL DEFAULT 'token',
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    CONSTRAINT chk_cloudflare_tunnel_mode CHECK (mode IN ('token', 'managed')),
    UNIQUE KEY idx_cloudflare_tunnel_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS dashboard_stats_daily (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    day_bucket DATE NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    status_2xx BIGINT NOT NULL DEFAULT 0,
    status_3xx BIGINT NOT NULL DEFAULT 0,
    status_4xx BIGINT NOT NULL DEFAULT 0,
    status_5xx BIGINT NOT NULL DEFAULT 0,
    avg_response_time DOUBLE DEFAULT 0,
    max_response_time DOUBLE DEFAULT 0,
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    waf_blocked BIGINT NOT NULL DEFAULT 0,
    rate_limited BIGINT NOT NULL DEFAULT 0,
    bot_blocked BIGINT NOT NULL DEFAULT 0,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY dashboard_stats_daily_proxy_host_id_day_bucket_key (proxy_host_id, day_bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS dashboard_stats_hourly (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    hour_bucket DATETIME(6) NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    status_2xx BIGINT NOT NULL DEFAULT 0,
    status_3xx BIGINT NOT NULL DEFAULT 0,
    status_4xx BIGINT NOT NULL DEFAULT 0,
    status_5xx BIGINT NOT NULL DEFAULT 0,
    avg_response_time DOUBLE DEFAULT 0,
    max_response_time DOUBLE DEFAULT 0,
    min_response_time DOUBLE DEFAULT 0,
    p95_response_time DOUBLE DEFAULT 0,
    p99_response_time DOUBLE DEFAULT 0,
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    waf_blocked BIGINT NOT NULL DEFAULT 0,
    waf_detected BIGINT NOT NULL DEFAULT 0,
    rate_limited BIGINT NOT NULL DEFAULT 0,
    bot_blocked BIGINT NOT NULL DEFAULT 0,
    top_countries JSON DEFAULT ('{}'),
    top_paths JSON DEFAULT ('[]'),
    top_ips JSON DEFAULT ('[]'),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    dashboard_stats_hourly_null_host_bucket_key VARCHAR(768) AS (CASE WHEN proxy_host_id IS NULL THEN CONCAT_WS('\n', COALESCE(CAST(hour_bucket AS CHAR), '')) END) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY dashboard_stats_hourly_proxy_host_id_hour_bucket_key (proxy_host_id, hour_bucket),
    UNIQUE KEY idx_dashboard_stats_hourly_null_host_bucket (dashboard_stats_hourly_null_host_bucket_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS dashboard_stats_hourly_partitioned (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    hour_bucket DATETIME(6) NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    status_2xx BIGINT NOT NULL DEFAULT 0,
    status_3xx BIGINT NOT NULL DEFAULT 0,
    status_4xx BIGINT NOT NULL DEFAULT 0,
    status_5xx BIGINT NOT NULL DEFAULT 0,
    avg_response_time DOUBLE DEFAULT 0,
    max_response_time DOUBLE DEFAULT 0,
    min_response_time DOUBLE DEFAULT 0,
    p95_response_time DOUBLE DEFAULT 0,
    p99_response_time DOUBLE DEFAULT 0,
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    waf_blocked BIGINT NOT NULL DEFAULT 0,
    waf_detected BIGINT NOT NULL DEFAULT 0,
    rate_limited BIGINT NOT NULL DEFAULT 0,
    bot_blocked BIGINT NOT NULL DEFAULT 0,
    top_countries JSON DEFAULT ('{}'),
    top_paths JSON DEFAULT ('[]'),
    top_ips JSON DEFAULT ('[]'),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id, hour_bucket)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
PARTITION BY RANGE COLUMNS(hour_bucket) (
    PARTITION p2025_12 VALUES LESS THAN ('2026-01-01 00:00:00'),
    PARTITION p2026_01 VALUES LESS THAN ('2026-02-01 00:00:00'),
    PARTITION p2026_02 VALUES LESS THAN ('2026-03-01 00:00:00'),
    PARTITION p2026_03 VALUES LESS THAN ('2026-04-01 00:00:00'),
    PARTITION p_max VALUES LESS THAN (MAXVALUE)
);
-- DDNS records (#154): keep registered hostnames' A records pointed at the server's public IPv4.
CREATE TABLE IF NOT EXISTS ddns_records (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    hostname VARCHAR(253) NOT NULL,
    dns_provider_id VARCHAR(36) NOT NULL,
    record_type VARCHAR(8) NOT NULL DEFAULT 'A',
    proxied BOOLEAN NOT NULL DEFAULT false,
    ttl INT NOT NULL DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_ip VARCHAR(45) NOT NULL DEFAULT '',
    last_synced_at DATETIME(6),
    last_status VARCHAR(16) NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT (''),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS dns_providers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name VARCHAR(100) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    credentials JSON NOT NULL DEFAULT ('{}'),
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    dns_providers_default_key VARCHAR(768) AS (CASE WHEN is_default = true THEN CONCAT_WS('\n', COALESCE(CAST(is_default AS CHAR), '')) END) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_dns_providers_default (dns_providers_default_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS exploit_block_rules (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    category VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    pattern TEXT NOT NULL,
    pattern_type VARCHAR(20) NOT NULL DEFAULT 'query_string',
    description TEXT,
    severity VARCHAR(20) DEFAULT 'warning',
    enabled BOOLEAN DEFAULT true,
    is_system BOOLEAN DEFAULT true,
    sort_order INT DEFAULT 0,
    auto_disabled_at DATETIME(6),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS fail2ban_configs (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    max_retries INT DEFAULT 5,
    find_time INT DEFAULT 600,
    ban_time INT DEFAULT 3600,
    fail_codes VARCHAR(100) DEFAULT '401,403,404',
    action VARCHAR(20) DEFAULT 'block',
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY fail2ban_configs_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS filter_subscription_entries (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    value TEXT NOT NULL,
    reason TEXT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_subscription_id_value (subscription_id, value(731))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Filter subscription entry exclusions (v2.8.0+)
CREATE TABLE IF NOT EXISTS filter_subscription_entry_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    value TEXT NOT NULL,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_subscription_id_value (subscription_id, value(731))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS filter_subscription_host_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    proxy_host_id VARCHAR(36) NOT NULL,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_subscription_id_proxy_host_id (subscription_id, proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Filter subscription tables (v2.7.0+)
CREATE TABLE IF NOT EXISTS filter_subscriptions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    format VARCHAR(20) NOT NULL DEFAULT 'npg-json',
    type VARCHAR(20) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    refresh_type VARCHAR(20) NOT NULL DEFAULT 'interval',
    refresh_value VARCHAR(50) NOT NULL DEFAULT '24h',
    last_fetched_at DATETIME(6),
    last_success_at DATETIME(6),
    last_error TEXT,
    entry_count INT DEFAULT 0,
    exclude_private_ips BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_filter_subscriptions_url (url(768))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS geo_restrictions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    mode VARCHAR(20) NOT NULL DEFAULT 'blacklist',
    countries TEXT NOT NULL DEFAULT ('{}'),
    enabled BOOLEAN DEFAULT true,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    allowed_ips TEXT DEFAULT ('{}'),
    challenge_mode BOOLEAN DEFAULT false,
    blocked_cloud_providers TEXT DEFAULT ('{}'),
    challenge_cloud_providers BOOLEAN DEFAULT false,
    allow_search_bots_cloud_providers BOOLEAN DEFAULT false,
    allow_private_ips BOOLEAN DEFAULT true,
    allow_search_bots BOOLEAN DEFAULT false,
    disable_global BOOLEAN NOT NULL DEFAULT false,
    cloud_disable_global BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id),
    CONSTRAINT geo_restrictions_mode_check CHECK (mode IN ('whitelist', 'blacklist')),
    UNIQUE KEY geo_restrictions_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS geoip_update_history (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    "status" VARCHAR(20) NOT NULL DEFAULT 'pending',
    trigger_type VARCHAR(20) NOT NULL DEFAULT 'manual',
    started_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    completed_at DATETIME(6),
    duration_ms INT,
    database_version VARCHAR(50),
    country_db_size BIGINT,
    asn_db_size BIGINT,
    error_message TEXT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Slice 2 (Bot Filter): singleton global_bot_filters (enabled OFF by default →
-- zero behavior change on upgrade) + bot_filters.disable_global. Same 3-state,
-- service-layer resolution, templates unchanged. Canonical execution in migration.go.
CREATE TABLE IF NOT EXISTS global_bot_filters (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT false,
    block_bad_bots BOOLEAN DEFAULT true,
    block_ai_bots BOOLEAN DEFAULT false,
    allow_search_engines BOOLEAN DEFAULT true,
    block_suspicious_clients BOOLEAN DEFAULT false,
    custom_blocked_agents TEXT,
    custom_allowed_agents TEXT,
    challenge_suspicious BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_global_bot_filters_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Slice 4 (Cloud Provider): singleton global_cloud_providers (empty blocked list
-- by default → zero behavior change on upgrade) + geo_restrictions.cloud_disable_global
-- (SEPARATE from geo disable_global — a host can inherit geo yet override cloud).
-- No explicit enabled flag: the global default is "active" when blocked_providers
-- is non-empty. Service-layer resolution, templates unchanged. Canonical in migration.go.
CREATE TABLE IF NOT EXISTS global_cloud_providers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    blocked_providers TEXT NOT NULL DEFAULT ('{}'),
    challenge_mode BOOLEAN DEFAULT false,
    allow_search_bots BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_global_cloud_providers_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS global_exploit_rule_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    rule_id VARCHAR(36) NOT NULL,
    uri_pattern TEXT,
    reason TEXT,
    disabled_by VARCHAR(100),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    uri_pattern_key VARCHAR(512) AS (COALESCE(uri_pattern, '')) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_global_exploit_exclusions_rule_uri_unique (rule_id, uri_pattern_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- v2.31.0 (#198): global default + per-host override for security options.
-- Slice 1 (GeoIP): singleton global_geo_restrictions (enabled OFF by default →
-- zero behavior change on upgrade) + geo_restrictions.disable_global for the
-- per-host 3-state (inherit/override/disable). Resolution is service-layer;
-- nginx templates are unchanged. Canonical execution in migration.go upgrades.
CREATE TABLE IF NOT EXISTS global_geo_restrictions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT false,
    mode VARCHAR(20) NOT NULL DEFAULT 'blacklist',
    countries TEXT NOT NULL DEFAULT ('{}'),
    allowed_ips TEXT DEFAULT ('{}'),
    allow_private_ips BOOLEAN DEFAULT true,
    allow_search_bots BOOLEAN DEFAULT false,
    challenge_mode BOOLEAN DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    CONSTRAINT global_geo_restrictions_mode_check CHECK (mode IN ('whitelist', 'blacklist')),
    UNIQUE KEY idx_global_geo_restrictions_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Slice 5 (Rate Limit): singleton global_rate_limits (enabled OFF by default →
-- zero behavior change on upgrade) + rate_limits.disable_global. The nginx
-- limit_req zone stays per-host (unique zone name per host); the global default
-- only supplies the RPS/burst/etc values an inheriting host's zone uses.
-- Service-layer resolution, templates unchanged. Canonical in migration.go.
CREATE TABLE IF NOT EXISTS global_rate_limits (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT false,
    requests_per_second INT DEFAULT 50,
    burst_size INT DEFAULT 100,
    zone_size VARCHAR(10) DEFAULT '10m',
    limit_by VARCHAR(20) DEFAULT 'ip',
    limit_response INT DEFAULT 429,
    whitelist_ips TEXT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_global_rate_limits_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Slice 3 (Security Headers): singleton global_security_headers (enabled OFF by
-- default → zero behavior change on upgrade) + security_headers.disable_global.
-- Same 3-state, service-layer resolution, templates unchanged. Canonical execution
-- in migration.go.
CREATE TABLE IF NOT EXISTS global_security_headers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT false,
    hsts_enabled BOOLEAN DEFAULT true,
    hsts_max_age INT DEFAULT 31536000,
    hsts_include_subdomains BOOLEAN DEFAULT true,
    hsts_preload BOOLEAN DEFAULT false,
    x_frame_options VARCHAR(50) DEFAULT 'SAMEORIGIN',
    x_content_type_options BOOLEAN DEFAULT true,
    x_xss_protection BOOLEAN DEFAULT true,
    referrer_policy VARCHAR(100) DEFAULT 'strict-origin-when-cross-origin',
    content_security_policy TEXT,
    permissions_policy TEXT,
    custom_headers JSON DEFAULT ('{}'),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_global_security_headers_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS global_settings (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    worker_processes INT NOT NULL DEFAULT 0,
    worker_connections INT NOT NULL DEFAULT 8192,
    worker_rlimit_nofile INT,
    multi_accept BOOLEAN NOT NULL DEFAULT true,
    use_epoll BOOLEAN NOT NULL DEFAULT true,
    sendfile BOOLEAN NOT NULL DEFAULT true,
    tcp_nopush BOOLEAN NOT NULL DEFAULT true,
    tcp_nodelay BOOLEAN NOT NULL DEFAULT true,
    keepalive_timeout INT NOT NULL DEFAULT 30,
    keepalive_requests INT NOT NULL DEFAULT 1000,
    types_hash_max_size INT NOT NULL DEFAULT 2048,
    server_tokens BOOLEAN NOT NULL DEFAULT false,
    client_body_buffer_size VARCHAR(20) NOT NULL DEFAULT '16k',
    client_header_buffer_size VARCHAR(20) NOT NULL DEFAULT '4k',
    client_max_body_size VARCHAR(20) NOT NULL DEFAULT '100m',
    large_client_header_buffers VARCHAR(20) NOT NULL DEFAULT '4 16k',
    client_body_timeout INT NOT NULL DEFAULT 60,
    client_header_timeout INT NOT NULL DEFAULT 60,
    send_timeout INT NOT NULL DEFAULT 60,
    proxy_connect_timeout INT NOT NULL DEFAULT 60,
    proxy_send_timeout INT NOT NULL DEFAULT 60,
    proxy_read_timeout INT NOT NULL DEFAULT 60,
    gzip_enabled BOOLEAN NOT NULL DEFAULT true,
    gzip_vary BOOLEAN NOT NULL DEFAULT true,
    gzip_proxied VARCHAR(50) NOT NULL DEFAULT 'any',
    gzip_comp_level INT NOT NULL DEFAULT 6,
    gzip_buffers VARCHAR(20) NOT NULL DEFAULT '16 8k',
    gzip_http_version VARCHAR(10) NOT NULL DEFAULT '1.1',
    gzip_min_length INT NOT NULL DEFAULT 256,
    gzip_types TEXT NOT NULL DEFAULT ('text/plain text/css text/xml text/javascript application/json application/javascript application/xml application/xml+rss application/x-javascript image/svg+xml'),
    ssl_protocols VARCHAR(100) NOT NULL DEFAULT 'TLSv1.2 TLSv1.3',
    ssl_ciphers TEXT NOT NULL DEFAULT ('ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'),
    ssl_prefer_server_ciphers BOOLEAN NOT NULL DEFAULT true,
    ssl_session_cache VARCHAR(50) NOT NULL DEFAULT 'shared:SSL:10m',
    ssl_session_timeout VARCHAR(20) NOT NULL DEFAULT '1d',
    ssl_session_tickets BOOLEAN NOT NULL DEFAULT false,
    ssl_stapling BOOLEAN NOT NULL DEFAULT true,
    ssl_stapling_verify BOOLEAN NOT NULL DEFAULT true,
    ssl_ecdh_curve VARCHAR(255) NOT NULL DEFAULT 'X25519MLKEM768:X25519:secp256r1:secp384r1',
    access_log_enabled BOOLEAN NOT NULL DEFAULT true,
    access_log_strip_query BOOLEAN NOT NULL DEFAULT false,
    error_log_level VARCHAR(20) NOT NULL DEFAULT 'warn',
    resolver VARCHAR(255) DEFAULT '1.1.1.1 8.8.8.8 valid=300s',
    resolver_timeout VARCHAR(20) DEFAULT '5s',
    custom_http_config TEXT DEFAULT (''),
    custom_stream_config TEXT DEFAULT (''),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    brotli_enabled BOOLEAN NOT NULL DEFAULT false,
    brotli_comp_level INT NOT NULL DEFAULT 6,
    brotli_types TEXT NOT NULL DEFAULT ('text/plain text/css text/xml text/javascript application/json application/javascript application/xml application/xml+rss image/svg+xml'),
    direct_ip_access_action VARCHAR(20) DEFAULT 'allow',
    enable_ipv6 BOOLEAN NOT NULL DEFAULT true,
    limit_conn_zone_size VARCHAR(10) DEFAULT '10m',
    limit_conn_per_ip INT DEFAULT 100,
    limit_conn_enabled BOOLEAN DEFAULT false,
    limit_req_zone_size VARCHAR(10) DEFAULT '10m',
    limit_req_rate INT DEFAULT 50,
    limit_req_burst INT DEFAULT 100,
    limit_req_enabled BOOLEAN DEFAULT false,
    reset_timedout_connection BOOLEAN DEFAULT true,
    limit_rate INT DEFAULT 0,
    limit_rate_after VARCHAR(10) DEFAULT '0',
    proxy_buffer_size VARCHAR(20) NOT NULL DEFAULT '8k',
    proxy_buffers VARCHAR(20) NOT NULL DEFAULT '8 32k',
    proxy_busy_buffers_size VARCHAR(20) NOT NULL DEFAULT '128k',
    proxy_max_temp_file_size VARCHAR(20) NOT NULL DEFAULT '1024m',
    proxy_temp_file_write_size VARCHAR(20) NOT NULL DEFAULT '64k',
    proxy_buffering VARCHAR(10) DEFAULT '',
    proxy_request_buffering VARCHAR(10) DEFAULT '',
    open_file_cache_enabled BOOLEAN NOT NULL DEFAULT true,
    open_file_cache_max INT NOT NULL DEFAULT 10000,
    open_file_cache_inactive VARCHAR(20) NOT NULL DEFAULT '60s',
    open_file_cache_valid VARCHAR(20) NOT NULL DEFAULT '30s',
    open_file_cache_min_uses INT NOT NULL DEFAULT 2,
    open_file_cache_errors BOOLEAN NOT NULL DEFAULT true,
    brotli_static BOOLEAN NOT NULL DEFAULT true,
    connection_upgrade_empty VARCHAR(10) NOT NULL DEFAULT '',
    brotli_min_length INT NOT NULL DEFAULT 1000,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS global_uri_blocks (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT true,
    rules JSON DEFAULT ('[]'),
    exception_ips TEXT DEFAULT ('{}'),
    allow_private_ips BOOLEAN DEFAULT true,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_global_uri_blocks_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Slice 6 (WAF mode/paranoia): singleton global_waf (enabled OFF by default →
-- zero behavior change on upgrade) + proxy_hosts.waf_use_global. A host with
-- waf_use_global=true inherits the global enabled/mode/paranoia/threshold; the
-- default false keeps every existing host on its own WAF columns. WAF/ModSecurity
-- changes only take effect after a proxy container restart (reload does not
-- reparse ModSec rules) — same systemic behavior as per-host WAF edits.
-- Service-layer resolution onto the config-time host, templates unchanged.
CREATE TABLE IF NOT EXISTS global_waf (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    enabled BOOLEAN DEFAULT false,
    mode VARCHAR(20) DEFAULT 'detection',
    paranoia_level INT DEFAULT 1,
    anomaly_threshold INT DEFAULT 5,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    singleton_key TINYINT AS (1) VIRTUAL,
    PRIMARY KEY (id),
    CONSTRAINT chk_global_waf_anomaly_threshold CHECK (((anomaly_threshold >= 1) AND (anomaly_threshold <= 100))),
    CONSTRAINT chk_global_waf_paranoia_level CHECK (((paranoia_level >= 1) AND (paranoia_level <= 4))),
    UNIQUE KEY idx_global_waf_singleton (singleton_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS global_waf_policy_history (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    rule_id VARCHAR(20) NOT NULL,
    rule_category VARCHAR(255),
    rule_description TEXT,
    action VARCHAR(20) NOT NULL,
    reason TEXT,
    changed_by VARCHAR(255),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS global_waf_rule_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    rule_id VARCHAR(20) NOT NULL,
    rule_category VARCHAR(255),
    rule_description TEXT,
    reason TEXT,
    disabled_by VARCHAR(255),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY global_waf_rule_exclusions_rule_id_key (rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS host_exploit_rule_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    rule_id VARCHAR(36) NOT NULL,
    uri_pattern TEXT,
    reason TEXT,
    disabled_by VARCHAR(100),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    uri_pattern_key VARCHAR(512) AS (COALESCE(uri_pattern, '')) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY idx_host_exploit_exclusions_host_rule_uri_unique (proxy_host_id, rule_id, uri_pattern_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS ip_ban_history (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    event_type VARCHAR(10) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    proxy_host_id VARCHAR(36),
    domain_name VARCHAR(255),
    reason TEXT,
    source VARCHAR(50) NOT NULL,
    ban_duration INT,
    expires_at DATETIME(6),
    is_permanent BOOLEAN DEFAULT false,
    is_auto BOOLEAN DEFAULT false,
    fail_count INT,
    user_id VARCHAR(36),
    user_email VARCHAR(255),
    metadata JSON,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- v2.33.0: log_filter_presets (saved log filter presets, #210)
CREATE TABLE IF NOT EXISTS log_filter_presets (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name TEXT NOT NULL,
    log_type TEXT NOT NULL DEFAULT ('access'),
    filter JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS log_settings (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    retention_days INT NOT NULL DEFAULT 30,
    max_logs_per_type BIGINT,
    auto_cleanup_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    system_log_retention_days INT NOT NULL DEFAULT 7,
    enable_docker_logs BOOLEAN NOT NULL DEFAULT true,
    filter_health_checks BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS login_attempts (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(255),
    success BOOLEAN NOT NULL DEFAULT false,
    attempted_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS logs (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    log_type ENUM('access', 'error', 'modsec') NOT NULL,
    "timestamp" DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    host TEXT,
    client_ip VARCHAR(45),
    request_method TEXT,
    request_uri TEXT,
    request_protocol TEXT,
    status_code INT,
    body_bytes_sent BIGINT,
    request_time DOUBLE,
    upstream_response_time DOUBLE,
    upstream_addr TEXT,
    upstream_status TEXT,
    http_referer TEXT,
    http_user_agent TEXT,
    http_x_forwarded_for TEXT,
    severity ENUM('debug', 'info', 'notice', 'warn', 'error', 'crit', 'alert', 'emerg'),
    error_message TEXT,
    rule_id BIGINT,
    rule_message TEXT,
    rule_severity TEXT,
    rule_data TEXT,
    attack_type TEXT,
    action_taken TEXT,
    proxy_host_id VARCHAR(36),
    raw_log TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    geo_country TEXT,
    geo_country_code VARCHAR(2),
    geo_city TEXT,
    geo_asn TEXT,
    geo_org TEXT,
    block_reason ENUM('none', 'waf', 'bot_filter', 'rate_limit', 'geo_block', 'exploit_block', 'banned_ip', 'uri_block', 'cloud_provider_challenge', 'cloud_provider_block', 'access_denied', 'filter_subscription') DEFAULT 'none',
    bot_category TEXT,
    exploit_rule VARCHAR(50),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin PAGE_COMPRESSED=1 PAGE_COMPRESSION_LEVEL=1;
CREATE TABLE IF NOT EXISTS logs_partitioned (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    log_type ENUM('access', 'error', 'modsec') NOT NULL,
    "timestamp" DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    host TEXT,
    client_ip VARCHAR(45),
    request_method TEXT,
    request_uri TEXT,
    request_protocol TEXT,
    status_code INT,
    body_bytes_sent BIGINT,
    request_time DOUBLE,
    upstream_response_time DOUBLE,
    upstream_addr TEXT,
    upstream_status TEXT,
    http_referer TEXT,
    http_user_agent TEXT,
    http_x_forwarded_for TEXT,
    severity ENUM('debug', 'info', 'notice', 'warn', 'error', 'crit', 'alert', 'emerg'),
    error_message TEXT,
    rule_id BIGINT,
    rule_message TEXT,
    rule_severity TEXT,
    rule_data TEXT,
    attack_type TEXT,
    action_taken TEXT,
    proxy_host_id VARCHAR(36),
    raw_log TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    geo_country TEXT,
    geo_country_code VARCHAR(2),
    geo_city TEXT,
    geo_asn TEXT,
    geo_org TEXT,
    block_reason ENUM('none', 'waf', 'bot_filter', 'rate_limit', 'geo_block', 'exploit_block', 'banned_ip', 'uri_block', 'cloud_provider_challenge', 'cloud_provider_block', 'access_denied', 'filter_subscription') DEFAULT 'none',
    bot_category TEXT,
    exploit_rule VARCHAR(50),
    PRIMARY KEY (id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin PAGE_COMPRESSED=1 PAGE_COMPRESSION_LEVEL=1
PARTITION BY RANGE COLUMNS(created_at) (
    PARTITION p2025_12 VALUES LESS THAN ('2026-01-01 00:00:00'),
    PARTITION p2026_01 VALUES LESS THAN ('2026-02-01 00:00:00'),
    PARTITION p2026_02 VALUES LESS THAN ('2026-03-01 00:00:00'),
    PARTITION p2026_03 VALUES LESS THAN ('2026-04-01 00:00:00'),
    PARTITION p2026_04 VALUES LESS THAN ('2026-05-01 00:00:00'),
    PARTITION p2026_05 VALUES LESS THAN ('2026-06-01 00:00:00'),
    PARTITION p2026_06 VALUES LESS THAN ('2026-07-01 00:00:00'),
    PARTITION p2026_07 VALUES LESS THAN ('2026-08-01 00:00:00'),
    PARTITION p2026_08 VALUES LESS THAN ('2026-09-01 00:00:00'),
    PARTITION p2026_09 VALUES LESS THAN ('2026-10-01 00:00:00'),
    PARTITION p2026_10 VALUES LESS THAN ('2026-11-01 00:00:00'),
    PARTITION p2026_11 VALUES LESS THAN ('2026-12-01 00:00:00'),
    PARTITION p2026_12 VALUES LESS THAN ('2027-01-01 00:00:00'),
    PARTITION p2027_01 VALUES LESS THAN ('2027-02-01 00:00:00'),
    PARTITION p2027_02 VALUES LESS THAN ('2027-03-01 00:00:00'),
    PARTITION p2027_03 VALUES LESS THAN ('2027-04-01 00:00:00'),
    PARTITION p2027_04 VALUES LESS THAN ('2027-05-01 00:00:00'),
    PARTITION p2027_05 VALUES LESS THAN ('2027-06-01 00:00:00'),
    PARTITION p2027_06 VALUES LESS THAN ('2027-07-01 00:00:00'),
    PARTITION p2027_07 VALUES LESS THAN ('2027-08-01 00:00:00'),
    PARTITION p2027_08 VALUES LESS THAN ('2027-09-01 00:00:00'),
    PARTITION p2027_09 VALUES LESS THAN ('2027-10-01 00:00:00'),
    PARTITION p2027_10 VALUES LESS THAN ('2027-11-01 00:00:00'),
    PARTITION p2027_11 VALUES LESS THAN ('2027-12-01 00:00:00'),
    PARTITION p2027_12 VALUES LESS THAN ('2028-01-01 00:00:00'),
    PARTITION p_max VALUES LESS THAN (MAXVALUE)
);
-- Notifications (#221). notification_channels is configuration; state and outbox
-- are runtime. Foreign keys live in the ALTER section below.
CREATE TABLE IF NOT EXISTS notification_channels (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name VARCHAR(64) NOT NULL,
    type VARCHAR(16) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    config JSON NOT NULL DEFAULT ('{}'),
    events TEXT NOT NULL DEFAULT ('{}'),
    digest_events TEXT NOT NULL DEFAULT ('{}'),
    rich_format BOOLEAN NOT NULL DEFAULT true,
    language VARCHAR(8) NOT NULL DEFAULT 'en',
    dashboard_url TEXT,
    digest_enabled BOOLEAN NOT NULL DEFAULT false,
    digest_hour SMALLINT NOT NULL DEFAULT 9,
    allow_private_target BOOLEAN NOT NULL DEFAULT false,
    template TEXT,
    last_success_at DATETIME(6),
    last_error_at DATETIME(6),
    last_error TEXT,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_digest_on DATE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    name_lower VARCHAR(64) AS (LOWER(name)) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY notification_channels_name_key (name_lower)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS notification_outbox (
    id BIGINT AUTO_INCREMENT NOT NULL,
    channel_id VARCHAR(36) NOT NULL,
    event_key VARCHAR(64) NOT NULL,
    payload JSON NOT NULL,
    "status" VARCHAR(16) NOT NULL DEFAULT 'queued',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_error TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    sent_at DATETIME(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Edge triggering lives here: one row per thing that can be broken, so a failure
-- that repeats every six hours produces one message rather than four a day.
CREATE TABLE IF NOT EXISTS notification_state (
    event_key VARCHAR(64) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    subject_label VARCHAR(255),
    state VARCHAR(16) NOT NULL,
    since DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_detail TEXT,
    PRIMARY KEY (event_key, subject)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS proxy_hosts (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_type VARCHAR(20) NOT NULL DEFAULT 'http',
    domain_names TEXT NOT NULL,
    forward_scheme VARCHAR(10) NOT NULL DEFAULT 'http',
    forward_host VARCHAR(255) NOT NULL,
    forward_port INT NOT NULL DEFAULT 80,
    forward_container_name TEXT,
    forward_container_network TEXT,
    stream_listen_host VARCHAR(255) DEFAULT '',
    stream_listen_port INT DEFAULT 0,
    stream_protocol VARCHAR(10) DEFAULT 'tcp',
    stream_ssl_preread BOOLEAN NOT NULL DEFAULT false,
    stream_accept_proxy_protocol BOOLEAN NOT NULL DEFAULT false,
    stream_send_proxy_protocol BOOLEAN NOT NULL DEFAULT false,
    stream_proxy_connect_timeout INT DEFAULT 0,
    stream_proxy_timeout INT DEFAULT 0,
    ssl_enabled BOOLEAN NOT NULL DEFAULT false,
    ssl_force_https BOOLEAN NOT NULL DEFAULT false,
    ssl_http2 BOOLEAN NOT NULL DEFAULT true,
    certificate_id VARCHAR(36),
    allow_websocket_upgrade BOOLEAN NOT NULL DEFAULT true,
    cache_enabled BOOLEAN NOT NULL DEFAULT false,
    cache_static_only BOOLEAN NOT NULL DEFAULT true,
    cache_ttl VARCHAR(20) NOT NULL DEFAULT '7d',
    block_exploits BOOLEAN NOT NULL DEFAULT true,
    custom_locations JSON DEFAULT ('[]'),
    advanced_config TEXT DEFAULT (''),
    waf_enabled BOOLEAN NOT NULL DEFAULT false,
    waf_mode VARCHAR(20) DEFAULT 'detection',
    access_list_id VARCHAR(36),
    auth_provider_id VARCHAR(36),
    auth_bypass_paths TEXT DEFAULT ('{}'),
    enabled BOOLEAN NOT NULL DEFAULT true,
    meta JSON DEFAULT ('{}'),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    ssl_http3 BOOLEAN NOT NULL DEFAULT false,
    rate_limit_enabled BOOLEAN DEFAULT false,
    fail2ban_enabled BOOLEAN DEFAULT false,
    bot_filter_enabled BOOLEAN DEFAULT false,
    security_headers_enabled BOOLEAN DEFAULT false,
    waf_paranoia_level INT DEFAULT 1,
    waf_anomaly_threshold INT DEFAULT 5,
    block_exploits_exceptions TEXT DEFAULT (''),
    proxy_connect_timeout INT DEFAULT 0,
    proxy_send_timeout INT DEFAULT 0,
    proxy_read_timeout INT DEFAULT 0,
    proxy_buffering VARCHAR(10) DEFAULT '',
    proxy_request_buffering VARCHAR(10) DEFAULT '',
    client_max_body_size VARCHAR(20) DEFAULT '',
    proxy_max_temp_file_size VARCHAR(20) DEFAULT '',
    is_favorite BOOLEAN NOT NULL DEFAULT false,
    config_status VARCHAR(20) NOT NULL DEFAULT 'ok',
    config_error TEXT,
    ddns_enabled BOOLEAN NOT NULL DEFAULT false,
    ddns_provider_id VARCHAR(36),
    ddns_proxied BOOLEAN NOT NULL DEFAULT false,
    waf_use_global BOOLEAN NOT NULL DEFAULT false,
    proxy_hosts_stream_listener_key VARCHAR(768) AS (CASE WHEN proxy_type = 'stream' AND enabled = true AND stream_listen_port > 0 THEN CONCAT_WS('\n', COALESCE(stream_listen_host, ''), COALESCE(CAST(stream_listen_port AS CHAR), ''), COALESCE(stream_protocol, '')) END) VIRTUAL,
    PRIMARY KEY (id),
    CONSTRAINT chk_waf_anomaly_threshold CHECK (((waf_anomaly_threshold >= 1) AND (waf_anomaly_threshold <= 100))),
    CONSTRAINT chk_waf_paranoia_level CHECK (((waf_paranoia_level >= 1) AND (waf_paranoia_level <= 4))),
    UNIQUE KEY idx_proxy_hosts_stream_listener_unique (proxy_hosts_stream_listener_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS rate_limits (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    requests_per_second INT DEFAULT 10,
    burst_size INT DEFAULT 20,
    zone_size VARCHAR(10) DEFAULT '10m',
    limit_by VARCHAR(20) DEFAULT 'ip',
    limit_response INT DEFAULT 429,
    whitelist_ips TEXT,
    disable_global BOOLEAN NOT NULL DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY rate_limits_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS redirect_hosts (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    domain_names TEXT NOT NULL DEFAULT ('{}'),
    forward_scheme VARCHAR(10) NOT NULL DEFAULT 'auto',
    forward_domain_name VARCHAR(255) NOT NULL,
    forward_path VARCHAR(1024) DEFAULT '',
    preserve_path BOOLEAN DEFAULT true,
    redirect_code INT DEFAULT 301,
    ssl_enabled BOOLEAN DEFAULT false,
    certificate_id VARCHAR(36),
    ssl_force_https BOOLEAN DEFAULT true,
    enabled BOOLEAN DEFAULT true,
    block_exploits BOOLEAN DEFAULT false,
    meta JSON DEFAULT ('{}'),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    CONSTRAINT redirect_hosts_redirect_code_check CHECK (redirect_code IN (301, 302, 307, 308))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id VARCHAR(36) NOT NULL,
    permission VARCHAR(64) NOT NULL,
    PRIMARY KEY (role_id, permission)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- RBAC (#222). Roles are named permission sets; role_permissions holds the
-- area:verb strings defined in model/permission.go. Constraints and the FK from
-- users live in the ALTER section below, because a fresh install runs this file
-- top to bottom and users is created before roles.
CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    name VARCHAR(64) NOT NULL,
    description TEXT,
    is_superuser BOOLEAN NOT NULL DEFAULT false,
    is_builtin BOOLEAN NOT NULL DEFAULT false,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    name_lower VARCHAR(64) AS (LOWER(name)) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY roles_name_key (name_lower)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Note: schema_migrations table is created by migration.go, not here
CREATE TABLE IF NOT EXISTS security_headers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    hsts_enabled BOOLEAN DEFAULT true,
    hsts_max_age INT DEFAULT 31536000,
    hsts_include_subdomains BOOLEAN DEFAULT true,
    hsts_preload BOOLEAN DEFAULT false,
    x_frame_options VARCHAR(100) DEFAULT 'SAMEORIGIN',
    x_content_type_options BOOLEAN DEFAULT true,
    x_xss_protection BOOLEAN DEFAULT true,
    referrer_policy VARCHAR(50) DEFAULT 'strict-origin-when-cross-origin',
    content_security_policy TEXT,
    permissions_policy TEXT,
    custom_headers JSON,
    disable_global BOOLEAN NOT NULL DEFAULT false,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY security_headers_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS settings (
    "key" VARCHAR(255) NOT NULL,
    value JSON NOT NULL,
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY ("key")
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- Short-lived CSRF/PKCE state. Server-side rather than a cookie: the panel may
-- be served over plain HTTP on a LAN, where SameSite/Secure cookies are a trap.
CREATE TABLE IF NOT EXISTS sso_login_states (
    state VARCHAR(64) NOT NULL,
    provider_id VARCHAR(36) NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    code_verifier VARCHAR(128) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (state)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- OIDC SSO for the admin panel (#227). Distinct from auth_providers, which
-- protects PROXIED HOSTS with ForwardAuth; these rows let someone sign in to
-- THIS panel. Foreign keys live in the ALTER section below.
CREATE TABLE IF NOT EXISTS sso_providers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    slug VARCHAR(32) NOT NULL,
    name VARCHAR(64) NOT NULL,
    issuer_url TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT ('openid profile email'),
    callback_base_url TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    allow_jit BOOLEAN NOT NULL DEFAULT false,
    allowed_email_domains TEXT NOT NULL DEFAULT ('{}'),
    allowed_emails TEXT NOT NULL DEFAULT ('{}'),
    group_claim VARCHAR(64) NOT NULL DEFAULT 'groups',
    required_group TEXT,
    default_role_id VARCHAR(36),
    group_role_mappings JSON NOT NULL DEFAULT ('[]'),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    slug_lower VARCHAR(32) AS (LOWER(slug)) VIRTUAL,
    PRIMARY KEY (id),
    UNIQUE KEY sso_providers_slug_key (slug_lower)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS system_health (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    recorded_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    nginx_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    nginx_workers INT DEFAULT 0,
    nginx_connections_active INT DEFAULT 0,
    nginx_connections_reading INT DEFAULT 0,
    nginx_connections_writing INT DEFAULT 0,
    nginx_connections_waiting INT DEFAULT 0,
    db_status VARCHAR(20) NOT NULL DEFAULT 'unknown',
    db_connections INT DEFAULT 0,
    cpu_usage DOUBLE DEFAULT 0,
    memory_usage DOUBLE DEFAULT 0,
    disk_usage DOUBLE DEFAULT 0,
    certs_total INT DEFAULT 0,
    certs_expiring_soon INT DEFAULT 0,
    certs_expired INT DEFAULT 0,
    upstreams_total INT DEFAULT 0,
    upstreams_healthy INT DEFAULT 0,
    upstreams_unhealthy INT DEFAULT 0,
    memory_total BIGINT DEFAULT 0,
    memory_used BIGINT DEFAULT 0,
    disk_total BIGINT DEFAULT 0,
    disk_used BIGINT DEFAULT 0,
    disk_path VARCHAR(255) DEFAULT '/',
    network_in BIGINT DEFAULT 0,
    network_out BIGINT DEFAULT 0,
    uptime_seconds BIGINT DEFAULT 0,
    hostname VARCHAR(255) DEFAULT '',
    os VARCHAR(255) DEFAULT '',
    platform VARCHAR(100) DEFAULT '',
    kernel_version VARCHAR(255) DEFAULT '',
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS system_logs (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    source ENUM('docker_api', 'docker_nginx', 'docker_db', 'docker_ui', 'health_check', 'internal', 'scheduler', 'backup', 'certificate', 'audit', 'api_token') NOT NULL,
    level ENUM('debug', 'info', 'warn', 'error', 'fatal') NOT NULL DEFAULT 'info',
    message TEXT NOT NULL,
    details JSON,
    container_name VARCHAR(100),
    component VARCHAR(100),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin PAGE_COMPRESSED=1 PAGE_COMPRESSION_LEVEL=1;
CREATE TABLE IF NOT EXISTS system_settings (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    geoip_enabled BOOLEAN NOT NULL DEFAULT false,
    maxmind_license_key VARCHAR(255) DEFAULT '',
    maxmind_account_id VARCHAR(100) DEFAULT '',
    geoip_auto_update BOOLEAN NOT NULL DEFAULT true,
    geoip_update_interval VARCHAR(20) NOT NULL DEFAULT '7d',
    geoip_last_updated DATETIME(6),
    geoip_database_version VARCHAR(100) DEFAULT '',
    acme_enabled BOOLEAN NOT NULL DEFAULT true,
    acme_email VARCHAR(255) DEFAULT '',
    acme_staging BOOLEAN NOT NULL DEFAULT false,
    acme_auto_renew BOOLEAN NOT NULL DEFAULT true,
    acme_renew_days_before INT NOT NULL DEFAULT 30,
    acme_dns_provider VARCHAR(50) DEFAULT '',
    acme_dns_credentials JSON DEFAULT ('{}'),
    notification_email VARCHAR(255) DEFAULT '',
    notify_cert_expiry BOOLEAN NOT NULL DEFAULT true,
    notify_cert_expiry_days INT NOT NULL DEFAULT 14,
    notify_security_events BOOLEAN NOT NULL DEFAULT true,
    notify_backup_complete BOOLEAN NOT NULL DEFAULT false,
    log_retention_days INT NOT NULL DEFAULT 30,
    stats_retention_days INT NOT NULL DEFAULT 90,
    backup_retention_count INT NOT NULL DEFAULT 10,
    auto_backup_enabled BOOLEAN NOT NULL DEFAULT false,
    auto_backup_schedule VARCHAR(50) DEFAULT '0 2 * * *',
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    access_log_retention_days INT NOT NULL DEFAULT 1095,
    waf_log_retention_days INT NOT NULL DEFAULT 90,
    error_log_retention_days INT NOT NULL DEFAULT 30,
    system_log_retention_days INT NOT NULL DEFAULT 30,
    audit_log_retention_days INT NOT NULL DEFAULT 1095,
    raw_log_enabled BOOLEAN NOT NULL DEFAULT true,
    raw_log_retention_days INT NOT NULL DEFAULT 7,
    raw_log_max_size_mb INT NOT NULL DEFAULT 100,
    raw_log_rotate_count INT NOT NULL DEFAULT 5,
    raw_log_compress_rotated BOOLEAN NOT NULL DEFAULT true,
    bot_filter_default_enabled BOOLEAN DEFAULT false,
    bot_filter_default_block_bad_bots BOOLEAN DEFAULT true,
    bot_filter_default_block_ai_bots BOOLEAN DEFAULT false,
    bot_filter_default_allow_search_engines BOOLEAN DEFAULT true,
    bot_filter_default_challenge_suspicious BOOLEAN DEFAULT false,
    bot_filter_default_custom_blocked_agents TEXT DEFAULT (''),
    bot_list_bad_bots TEXT DEFAULT ('AhrefsBot SemrushBot DotBot MJ12bot BLEXBot DataForSeoBot serpstatbot AspiegelBot BacklinkCrawler Exabot Screaming Frog MegaIndex LinkpadBot Nimbostratus-Bot TurnitinBot PetalBot Seekport Crawler Bytespider MauiBot Sogou web spider YandexBot Baiduspider'),
    bot_list_ai_bots TEXT DEFAULT ('GPTBot ChatGPT-User Claude-Web ClaudeBot anthropic-ai Amazonbot CCBot Google-Extended FacebookBot PerplexityBot YouBot Cohere-ai'),
    bot_list_search_engines TEXT DEFAULT ('Googlebot Bingbot DuckDuckBot Slurp facebot Twitterbot LinkedInBot WhatsApp TelegramBot Discordbot Slackbot Applebot'),
    bot_list_suspicious_clients TEXT DEFAULT ('curl Wget libwww-perl python-requests Python-urllib Python-httpx httpx aiohttp Java Go-http-client Go-http http_requester HttpClient Apache-HttpClient okhttp node-fetch axios got request fetch urllib http.client requests scrapy mechanize phantom headless puppeteer playwright selenium chromedriver geckodriver'),
    bot_filter_default_block_suspicious_clients BOOLEAN DEFAULT false,
    waf_auto_ban_enabled BOOLEAN DEFAULT false,
    waf_auto_ban_threshold INT DEFAULT 10,
    waf_auto_ban_window INT DEFAULT 300,
    waf_auto_ban_duration INT DEFAULT 3600,
    direct_ip_access_action VARCHAR(20) DEFAULT 'allow',
    system_logs_enabled BOOLEAN NOT NULL DEFAULT true,
    system_logs_levels JSON DEFAULT ('{"npm-guard-db": "warn", "npm-guard-ui": "warn", "npm-guard-api": "info", "npm-guard-proxy": "info"}'),
    system_logs_exclude_patterns TEXT DEFAULT ('{"/health","/nginx_status","/.well-known/","HEAD /"}'),
    system_logs_stdout_excluded TEXT DEFAULT ('{"npm-guard-proxy"}'),
    ui_font_family VARCHAR(50) DEFAULT 'system',
    ui_error_page_language VARCHAR(10) DEFAULT 'auto',
    global_block_exploits_exceptions TEXT DEFAULT ('^/wp-json/ ^/api/v1/challenge/ ^/wp-admin/admin-ajax.php ^/webapi/'),
    global_trusted_ips TEXT DEFAULT (''),
    global_trusted_ips_bypass_waf BOOLEAN NOT NULL DEFAULT false,
    ddns_check_interval_minutes INT NOT NULL DEFAULT 5,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS upstream_servers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    upstream_id VARCHAR(36) NOT NULL,
    address VARCHAR(255) NOT NULL,
    port INT DEFAULT 80,
    weight INT DEFAULT 1,
    max_fails INT DEFAULT 3,
    fail_timeout INT DEFAULT 30,
    is_backup BOOLEAN DEFAULT false,
    is_down BOOLEAN DEFAULT false,
    is_healthy BOOLEAN DEFAULT true,
    last_check_at DATETIME(6),
    last_error TEXT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS upstreams (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    scheme VARCHAR(10) NOT NULL DEFAULT 'http',
    servers JSON NOT NULL DEFAULT ('[]'),
    load_balance VARCHAR(20) DEFAULT 'round_robin',
    health_check_enabled BOOLEAN DEFAULT false,
    health_check_interval INT DEFAULT 30,
    health_check_timeout INT DEFAULT 5,
    health_check_path VARCHAR(255) DEFAULT '/',
    health_check_expected_status INT DEFAULT 200,
    keepalive INT DEFAULT 32,
    is_healthy BOOLEAN DEFAULT true,
    last_check_at DATETIME(6),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY upstreams_proxy_host_id_key (proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS uri_blocks (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    rules JSON DEFAULT ('[]'),
    exception_ips TEXT DEFAULT ('{}'),
    allow_private_ips BOOLEAN DEFAULT true,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- One row per (provider, IdP subject). The subject is the stable identifier;
-- email is kept only for display and can change at the IdP.
CREATE TABLE IF NOT EXISTS user_identities (
    provider_id VARCHAR(36) NOT NULL,
    subject TEXT NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    email TEXT,
    last_login_at DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (provider_id, subject(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    username VARCHAR(255) NOT NULL,
    is_initial_setup BOOLEAN NOT NULL DEFAULT true,
    last_login_at DATETIME(6),
    last_login_ip VARCHAR(45),
    login_count INT NOT NULL DEFAULT 0,
    totp_secret VARCHAR(255),
    totp_enabled BOOLEAN NOT NULL DEFAULT false,
    totp_verified_at DATETIME(6),
    backup_codes TEXT,
    language VARCHAR(10) DEFAULT 'ko',
    font_family VARCHAR(100) DEFAULT 'system',
    role_id VARCHAR(36),
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (id),
    UNIQUE KEY users_email_key (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS waf_policy_history (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    rule_id INT NOT NULL,
    rule_category VARCHAR(100),
    rule_description TEXT,
    action VARCHAR(20) NOT NULL,
    reason TEXT,
    changed_by VARCHAR(255),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS waf_rule_change_events (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    rule_id VARCHAR(20) NOT NULL,
    action VARCHAR(20) NOT NULL,
    rule_category VARCHAR(255),
    rule_description TEXT,
    reason TEXT,
    changed_by VARCHAR(255),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS waf_rule_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36) NOT NULL,
    rule_id INT NOT NULL,
    rule_category VARCHAR(100),
    rule_description TEXT,
    reason TEXT,
    disabled_by VARCHAR(255),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id),
    UNIQUE KEY waf_rule_exclusions_proxy_host_id_rule_id_key (proxy_host_id, rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS waf_rule_snapshot_details (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    snapshot_id VARCHAR(36) NOT NULL,
    rule_id VARCHAR(20) NOT NULL,
    rule_category VARCHAR(255),
    rule_description TEXT,
    is_disabled BOOLEAN DEFAULT false,
    reason TEXT,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
CREATE TABLE IF NOT EXISTS waf_rule_snapshots (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()),
    proxy_host_id VARCHAR(36),
    version_number INT NOT NULL,
    snapshot_name VARCHAR(255),
    rule_engine VARCHAR(20),
    paranoia_level INT,
    anomaly_threshold INT,
    total_rules INT DEFAULT 0,
    disabled_rules INT DEFAULT 0,
    change_description TEXT,
    created_by VARCHAR(255),
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- --------------------------------------------------------------------------
-- Indexes
-- --------------------------------------------------------------------------
-- idx_global_bot_filters_singleton is enforced by the singleton_key generated column on global_bot_filters
CREATE UNIQUE INDEX IF NOT EXISTS idx_ddns_records_hostname_provider ON ddns_records (hostname, dns_provider_id);
-- idx_global_cloud_providers_singleton is enforced by the singleton_key generated column on global_cloud_providers
-- idx_global_geo_restrictions_singleton is enforced by the singleton_key generated column on global_geo_restrictions
-- idx_global_rate_limits_singleton is enforced by the singleton_key generated column on global_rate_limits
-- idx_global_waf_singleton is enforced by the singleton_key generated column on global_waf
-- idx_cloudflare_tunnel_singleton is enforced by the singleton_key generated column on cloudflare_tunnel
CREATE INDEX IF NOT EXISTS idx_log_filter_presets_log_type ON log_filter_presets (log_type(191));
-- idx_global_security_headers_singleton is enforced by the singleton_key generated column on global_security_headers
-- roles_name_key is enforced by generated column(s) name_lower on roles
-- sso_providers_slug_key is enforced by generated column(s) slug_lower on sso_providers
CREATE UNIQUE INDEX IF NOT EXISTS user_identities_user_provider_key ON user_identities (user_id, provider_id);
CREATE INDEX IF NOT EXISTS sso_login_states_expires_at_idx ON sso_login_states (expires_at);
-- notification_channels_name_key is enforced by generated column(s) name_lower on notification_channels
CREATE INDEX IF NOT EXISTS notification_outbox_due_idx ON notification_outbox (status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_access_list_items_list_id ON access_list_items (access_list_id);
CREATE INDEX IF NOT EXISTS idx_api_token_usage_created_at ON api_token_usage (created_at);
CREATE INDEX IF NOT EXISTS idx_api_token_usage_token_id ON api_token_usage (token_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_is_active ON api_tokens (is_active);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (is_active = true)
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs (resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON auth_sessions (token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_backups_created ON backups (created_at);
CREATE INDEX IF NOT EXISTS idx_banned_ips_auto ON banned_ips (is_auto_banned, expires_at);
CREATE INDEX IF NOT EXISTS idx_banned_ips_expires ON banned_ips (expires_at);
-- idx_banned_ips_ip_global_unique is enforced by the banned_ips_ip_global_key generated column on banned_ips (WHERE proxy_host_id IS NULL)
-- idx_banned_ips_ip_host_unique is enforced by the banned_ips_ip_host_key generated column on banned_ips (WHERE proxy_host_id IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_banned_ips_lookup ON banned_ips (ip_address, expires_at, is_permanent);
CREATE INDEX IF NOT EXISTS idx_banned_ips_proxy_host ON banned_ips (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_certificates_auto_renew ON certificates (auto_renew);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (auto_renew = true)
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_certificates_domain_names
CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON certificates (expires_at);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates (status);
CREATE INDEX IF NOT EXISTS idx_certificate_history_certificate_id ON certificate_history (certificate_id);
CREATE INDEX IF NOT EXISTS idx_certificate_history_created_at ON certificate_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificate_history_action ON certificate_history (action);
CREATE INDEX IF NOT EXISTS idx_challenge_logs_created ON challenge_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_challenge_logs_ip ON challenge_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_challenge_logs_proxy_host ON challenge_logs (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_expires ON challenge_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_hash ON challenge_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_ip ON challenge_tokens (client_ip);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_proxy_host ON challenge_tokens (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_cloud_providers_enabled ON cloud_providers (enabled);
CREATE INDEX IF NOT EXISTS idx_cloud_providers_region ON cloud_providers (region);
CREATE INDEX IF NOT EXISTS idx_cloud_providers_slug ON cloud_providers (slug);
-- idx_dns_providers_default is enforced by the dns_providers_default_key generated column on dns_providers (WHERE is_default = true)
CREATE INDEX IF NOT EXISTS idx_exploit_rules_category ON exploit_block_rules (category);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_enabled ON exploit_block_rules (enabled);
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_geo_restrictions_blocked_cloud
CREATE INDEX IF NOT EXISTS idx_geo_restrictions_proxy_host ON geo_restrictions (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_geoip_update_history_created_at ON geoip_update_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_geoip_update_history_status ON geoip_update_history (status);
-- idx_global_uri_blocks_singleton is enforced by the singleton_key generated column on global_uri_blocks
CREATE INDEX IF NOT EXISTS idx_global_waf_policy_history_created_at ON global_waf_policy_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_global_waf_policy_history_rule_id ON global_waf_policy_history (rule_id);
CREATE INDEX IF NOT EXISTS idx_global_waf_rule_exclusions_rule_id ON global_waf_rule_exclusions (rule_id);
CREATE INDEX IF NOT EXISTS idx_host_exploit_exclusions_host ON host_exploit_rule_exclusions (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_host_exploit_exclusions_rule ON host_exploit_rule_exclusions (rule_id);
-- idx_global_exploit_exclusions_rule_uri_unique is enforced by generated column(s) uri_pattern_key on global_exploit_rule_exclusions
-- idx_host_exploit_exclusions_host_rule_uri_unique is enforced by generated column(s) uri_pattern_key on host_exploit_rule_exclusions
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_created_at ON ip_ban_history (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_event_type ON ip_ban_history (event_type);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_ip ON ip_ban_history (ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_ip_created ON ip_ban_history (ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_proxy_host ON ip_ban_history (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_source ON ip_ban_history (source);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_user ON ip_ban_history (user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip_address, attempted_at);
CREATE INDEX IF NOT EXISTS idx_logs_access_timestamp ON logs (timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (log_type = 'access'::public.log_type)
CREATE INDEX IF NOT EXISTS idx_logs_block_reason ON logs (block_reason);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (block_reason <> 'none'::public.block_reason)
CREATE INDEX IF NOT EXISTS idx_logs_block_reason_created ON logs (block_reason, created_at DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE ((block_reason IS NOT NULL) AND (block_reason <> 'none'::public.block_reason))
CREATE INDEX IF NOT EXISTS idx_logs_bot_filter ON logs (block_reason, bot_category(191), timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (block_reason = 'bot_filter'::public.block_reason)
CREATE INDEX IF NOT EXISTS idx_logs_client_ip ON logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_logs_created_at_desc ON logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_created_host ON logs (created_at DESC, host(191));  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (host IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_created_ip ON logs (created_at DESC, client_ip);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (client_ip IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_created_status ON logs (created_at DESC, status_code);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (status_code IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_created_type ON logs (created_at DESC, log_type);
CREATE INDEX IF NOT EXISTS idx_logs_exploit_rule ON logs (exploit_rule);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text))
CREATE INDEX IF NOT EXISTS idx_logs_geo_asn ON logs (geo_asn(191));
CREATE INDEX IF NOT EXISTS idx_logs_geo_country ON logs (geo_country_code, created_at DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (geo_country_code IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_geo_country_code ON logs (geo_country_code);
CREATE INDEX IF NOT EXISTS idx_logs_geo_timestamp ON logs (timestamp DESC, geo_country_code);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE ((log_type = 'access'::public.log_type) AND (geo_country_code IS NOT NULL))
CREATE INDEX IF NOT EXISTS idx_logs_host ON logs (host(191));
CREATE INDEX IF NOT EXISTS idx_logs_host_timestamp ON logs (host(191), timestamp DESC);
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_logs_host_trgm
CREATE INDEX IF NOT EXISTS idx_logs_log_type ON logs (log_type);
CREATE INDEX IF NOT EXISTS idx_logs_modsec_created ON logs (created_at DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (log_type = 'modsec'::public.log_type)
CREATE INDEX IF NOT EXISTS idx_logs_part_host ON logs_partitioned (host(191));
CREATE INDEX IF NOT EXISTS idx_logs_part_log_type ON logs_partitioned (log_type);
CREATE INDEX IF NOT EXISTS idx_logs_part_timestamp ON logs_partitioned (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_part_type_timestamp ON logs_partitioned (log_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_partitioned_exploit_rule ON logs_partitioned (exploit_rule);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text))
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_ts ON logs_partitioned (block_reason, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (block_reason != 'none')
CREATE INDEX IF NOT EXISTS idx_logs_part_client_ip ON logs_partitioned (client_ip);
CREATE INDEX IF NOT EXISTS idx_logs_part_created_at ON logs_partitioned (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_part_status_code ON logs_partitioned (status_code);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (status_code IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_part_host_ts ON logs_partitioned (host(191), timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_part_status_ts ON logs_partitioned (status_code, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (status_code IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_part_proxy_host_ts ON logs_partitioned (proxy_host_id, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (proxy_host_id IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_part_geo_ts ON logs_partitioned (geo_country_code, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (geo_country_code IS NOT NULL AND (geo_country_code)::text <> ''::text)
CREATE INDEX IF NOT EXISTS idx_logs_part_type_created ON logs_partitioned (log_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_proxy_host_id ON logs (proxy_host_id);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (proxy_host_id IS NOT NULL)
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_logs_request_uri_trgm
CREATE INDEX IF NOT EXISTS idx_logs_rule_id ON logs (rule_id);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (rule_id IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs (severity);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (severity IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_status_code ON logs (status_code);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (status_code IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type_timestamp ON logs (log_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_created_at ON proxy_hosts (created_at DESC);
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_proxy_hosts_domain_names
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_enabled ON proxy_hosts (enabled);
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_redirect_hosts_domains
CREATE INDEX IF NOT EXISTS idx_stats_daily_bucket ON dashboard_stats_daily (day_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_daily_host_bucket ON dashboard_stats_daily (proxy_host_id, day_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_bucket ON dashboard_stats_hourly (hour_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_host_bucket ON dashboard_stats_hourly (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_part_bucket ON dashboard_stats_hourly_partitioned (hour_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_part_host ON dashboard_stats_hourly_partitioned (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS idx_system_health_recorded ON system_health (recorded_at);
CREATE INDEX IF NOT EXISTS idx_system_logs_container ON system_logs (container_name, created_at DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (container_name IS NOT NULL)
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs (level);
CREATE INDEX IF NOT EXISTS idx_system_logs_source ON system_logs (source);
CREATE INDEX IF NOT EXISTS idx_system_logs_source_created ON system_logs (source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_source_level_created ON system_logs (source, level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_settings_updated ON system_settings (updated_at);
CREATE INDEX IF NOT EXISTS idx_upstream_servers_upstream ON upstream_servers (upstream_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_uri_blocks_proxy_host ON uri_blocks (proxy_host_id);
-- idx_proxy_hosts_stream_listener_unique is enforced by the proxy_hosts_stream_listener_key generated column on proxy_hosts (WHERE proxy_type = 'stream' AND enabled = true AND stream_listen_port > 0)
CREATE INDEX IF NOT EXISTS idx_users_totp_enabled ON users (totp_enabled);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE (totp_enabled = true)
CREATE INDEX IF NOT EXISTS idx_waf_policy_history_proxy_host ON waf_policy_history (proxy_host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_policy_history_rule ON waf_policy_history (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_rule_changes_proxy_host ON waf_rule_change_events (proxy_host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_rule_changes_rule ON waf_rule_change_events (rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_rule_exclusions_proxy_host ON waf_rule_exclusions (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_waf_rule_exclusions_rule_id ON waf_rule_exclusions (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_snapshot_details_snapshot ON waf_rule_snapshot_details (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_waf_snapshots_created_at ON waf_rule_snapshots (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_snapshots_proxy_host_version ON waf_rule_snapshots (proxy_host_id, version_number DESC);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON users (username);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ddns_records_hostname_provider ON ddns_records (hostname, dns_provider_id);
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_logs_part_host_trgm
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_logs_part_uri_trgm
-- skipped (gin 인덱스는 대응물이 없어 건너뜀): idx_logs_part_ua_trgm
CREATE INDEX IF NOT EXISTS idx_logs_part_host_ts ON logs_partitioned (host(191), timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_part_status_ts ON logs_partitioned (status_code, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE status_code IS NOT NULL
CREATE INDEX IF NOT EXISTS idx_logs_part_proxy_host_ts ON logs_partitioned (proxy_host_id, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE proxy_host_id IS NOT NULL
CREATE INDEX IF NOT EXISTS idx_logs_part_geo_ts ON logs_partitioned (geo_country_code, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE geo_country_code IS NOT NULL AND geo_country_code != ''
CREATE INDEX IF NOT EXISTS idx_logs_part_type_created ON logs_partitioned (log_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason ON logs_partitioned (block_reason);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE block_reason != 'none'
CREATE INDEX IF NOT EXISTS idx_logs_part_status_created ON logs_partitioned (status_code, created_at);
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_created ON logs_partitioned (created_at DESC, block_reason);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE block_reason != 'none' AND log_type = 'access'
-- idx_dashboard_stats_hourly_null_host_bucket is enforced by the dashboard_stats_hourly_null_host_bucket_key generated column on dashboard_stats_hourly (WHERE proxy_host_id IS NULL)
-- idx_global_exploit_exclusions_rule_uri_unique is enforced by generated column(s) uri_pattern_key on global_exploit_rule_exclusions
-- idx_host_exploit_exclusions_host_rule_uri_unique is enforced by generated column(s) uri_pattern_key on host_exploit_rule_exclusions
CREATE INDEX IF NOT EXISTS idx_banned_ips_host_banned_at ON banned_ips (proxy_host_id, banned_at DESC);
CREATE INDEX IF NOT EXISTS idx_bot_filters_proxy_host ON bot_filters (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_rate_limits_proxy_host ON rate_limits (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_security_headers_proxy_host ON security_headers (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_challenge_configs_proxy_host ON challenge_configs (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_upstreams_proxy_host ON upstreams (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_fail2ban_configs_proxy_host ON fail2ban_configs (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_created ON logs_partitioned (created_at DESC, block_reason);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE block_reason != 'none' AND log_type = 'access'
-- idx_global_geo_restrictions_singleton is enforced by the singleton_key generated column on global_geo_restrictions
-- idx_global_bot_filters_singleton is enforced by the singleton_key generated column on global_bot_filters
-- idx_global_security_headers_singleton is enforced by the singleton_key generated column on global_security_headers
-- idx_global_cloud_providers_singleton is enforced by the singleton_key generated column on global_cloud_providers
-- idx_global_rate_limits_singleton is enforced by the singleton_key generated column on global_rate_limits
-- idx_global_waf_singleton is enforced by the singleton_key generated column on global_waf
-- idx_proxy_hosts_stream_listener_unique is enforced by the proxy_hosts_stream_listener_key generated column on proxy_hosts (WHERE proxy_type = 'stream' AND enabled = true AND stream_listen_port > 0)
-- idx_cloudflare_tunnel_singleton is enforced by the singleton_key generated column on cloudflare_tunnel
CREATE INDEX IF NOT EXISTS idx_log_filter_presets_log_type ON log_filter_presets (log_type(191));

-- --------------------------------------------------------------------------
-- Foreign keys and deferred constraints
-- --------------------------------------------------------------------------
ALTER TABLE access_list_items ADD CONSTRAINT access_list_items_access_list_id_fkey FOREIGN KEY IF NOT EXISTS (access_list_id) REFERENCES access_lists(id) ON DELETE CASCADE;
ALTER TABLE api_token_usage ADD CONSTRAINT api_token_usage_token_id_fkey FOREIGN KEY IF NOT EXISTS (token_id) REFERENCES api_tokens(id) ON DELETE CASCADE;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY IF NOT EXISTS (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY IF NOT EXISTS (user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_user_id_fkey FOREIGN KEY IF NOT EXISTS (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE banned_ips ADD CONSTRAINT banned_ips_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE bot_filters ADD CONSTRAINT bot_filters_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE certificate_history ADD CONSTRAINT certificate_history_certificate_id_fkey FOREIGN KEY IF NOT EXISTS (certificate_id) REFERENCES certificates(id) ON DELETE CASCADE;
ALTER TABLE certificates ADD CONSTRAINT certificates_dns_provider_id_fkey FOREIGN KEY IF NOT EXISTS (dns_provider_id) REFERENCES dns_providers(id) ON DELETE SET NULL;
ALTER TABLE challenge_configs ADD CONSTRAINT challenge_configs_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE challenge_logs ADD CONSTRAINT challenge_logs_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE challenge_tokens ADD CONSTRAINT challenge_tokens_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE dashboard_stats_daily ADD CONSTRAINT dashboard_stats_daily_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE dashboard_stats_hourly ADD CONSTRAINT dashboard_stats_hourly_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ddns_records ADD CONSTRAINT fk_ddns_records_dns_provider_id FOREIGN KEY IF NOT EXISTS (dns_provider_id) REFERENCES dns_providers(id) ON DELETE CASCADE;
ALTER TABLE ddns_records ADD CONSTRAINT ddns_records_dns_provider_id_fkey FOREIGN KEY IF NOT EXISTS (dns_provider_id) REFERENCES dns_providers(id) ON DELETE CASCADE;
-- skipped (column added by a later upgrade, not by this file): ddns_records_proxy_host_id_fkey
ALTER TABLE fail2ban_configs ADD CONSTRAINT fail2ban_configs_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE filter_subscription_entries ADD CONSTRAINT fk_filter_subscription_entries_subscription_id FOREIGN KEY IF NOT EXISTS (subscription_id) REFERENCES filter_subscriptions(id) ON DELETE CASCADE;
ALTER TABLE filter_subscription_entry_exclusions ADD CONSTRAINT fk_filter_subscription_entry_exclusions_subscription_id FOREIGN KEY IF NOT EXISTS (subscription_id) REFERENCES filter_subscriptions(id) ON DELETE CASCADE;
ALTER TABLE filter_subscription_host_exclusions ADD CONSTRAINT fk_filter_subscription_host_exclusions_subscription_id FOREIGN KEY IF NOT EXISTS (subscription_id) REFERENCES filter_subscriptions(id) ON DELETE CASCADE;
ALTER TABLE filter_subscription_host_exclusions ADD CONSTRAINT fk_filter_subscription_host_exclusions_proxy_host_id FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE geo_restrictions ADD CONSTRAINT geo_restrictions_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE global_exploit_rule_exclusions ADD CONSTRAINT global_exploit_rule_exclusions_rule_id_fkey FOREIGN KEY IF NOT EXISTS (rule_id) REFERENCES exploit_block_rules(id) ON DELETE CASCADE;
ALTER TABLE host_exploit_rule_exclusions ADD CONSTRAINT host_exploit_rule_exclusions_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE host_exploit_rule_exclusions ADD CONSTRAINT host_exploit_rule_exclusions_rule_id_fkey FOREIGN KEY IF NOT EXISTS (rule_id) REFERENCES exploit_block_rules(id) ON DELETE CASCADE;
ALTER TABLE ip_ban_history ADD CONSTRAINT ip_ban_history_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE SET NULL;
ALTER TABLE ip_ban_history ADD CONSTRAINT ip_ban_history_user_id_fkey FOREIGN KEY IF NOT EXISTS (user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE logs ADD CONSTRAINT logs_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE SET NULL;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_channel_id_fkey FOREIGN KEY IF NOT EXISTS (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE;
ALTER TABLE proxy_hosts ADD CONSTRAINT proxy_hosts_certificate_id_fkey FOREIGN KEY IF NOT EXISTS (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL;
ALTER TABLE proxy_hosts ADD CONSTRAINT proxy_hosts_ddns_provider_id_fkey FOREIGN KEY IF NOT EXISTS (ddns_provider_id) REFERENCES dns_providers(id) ON DELETE SET NULL;
ALTER TABLE proxy_hosts ADD CONSTRAINT proxy_hosts_auth_provider_id_fkey FOREIGN KEY IF NOT EXISTS (auth_provider_id) REFERENCES auth_providers(id) ON DELETE SET NULL;
ALTER TABLE rate_limits ADD CONSTRAINT rate_limits_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE redirect_hosts ADD CONSTRAINT redirect_hosts_certificate_id_fkey FOREIGN KEY IF NOT EXISTS (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL;
ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY IF NOT EXISTS (role_id) REFERENCES roles(id) ON DELETE CASCADE;
ALTER TABLE security_headers ADD CONSTRAINT security_headers_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE sso_login_states ADD CONSTRAINT sso_login_states_provider_id_fkey FOREIGN KEY IF NOT EXISTS (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE;
ALTER TABLE sso_providers ADD CONSTRAINT sso_providers_default_role_id_fkey FOREIGN KEY IF NOT EXISTS (default_role_id) REFERENCES roles(id) ON DELETE RESTRICT;
ALTER TABLE upstream_servers ADD CONSTRAINT upstream_servers_upstream_id_fkey FOREIGN KEY IF NOT EXISTS (upstream_id) REFERENCES upstreams(id) ON DELETE CASCADE;
ALTER TABLE upstreams ADD CONSTRAINT upstreams_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE uri_blocks ADD CONSTRAINT uri_blocks_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provider_id_fkey FOREIGN KEY IF NOT EXISTS (provider_id) REFERENCES sso_providers(id) ON DELETE CASCADE;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_user_id_fkey FOREIGN KEY IF NOT EXISTS (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE users ADD CONSTRAINT users_role_id_fkey FOREIGN KEY IF NOT EXISTS (role_id) REFERENCES roles(id) ON DELETE RESTRICT;
ALTER TABLE waf_policy_history ADD CONSTRAINT waf_policy_history_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE waf_rule_change_events ADD CONSTRAINT waf_rule_change_events_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE waf_rule_exclusions ADD CONSTRAINT waf_rule_exclusions_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE waf_rule_snapshot_details ADD CONSTRAINT waf_rule_snapshot_details_snapshot_id_fkey FOREIGN KEY IF NOT EXISTS (snapshot_id) REFERENCES waf_rule_snapshots(id) ON DELETE CASCADE;
ALTER TABLE waf_rule_snapshots ADD CONSTRAINT waf_rule_snapshots_proxy_host_id_fkey FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;

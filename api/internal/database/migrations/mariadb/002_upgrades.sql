-- Nginx Proxy Guard — MariaDB/MySQL 업그레이드 문장
--
-- 생성된 파일입니다. 직접 수정하지 마세요.
-- 원본   : api/internal/database/migration.go (`upgrades` 슬라이스)
-- 재생성 : python3 scripts/pg2mariadb-schema.py
--
-- Replayed on every boot, like its PostgreSQL counterpart: every statement is
-- idempotent, and the runner logs rather than aborts when one fails.

-- skipped (DO $$): Detach orphan chunk inheritance entries (TimescaleDB catalog drift)
-- skipped (ALTER TYPE): block_reason enum: cloud_provider_challenge
-- skipped (ALTER TYPE): block_reason enum: cloud_provider_block
-- skipped (ALTER TYPE): block_reason enum: uri_block
-- skipped (ALTER TYPE): block_reason enum: access_denied
-- skipped (ALTER TYPE): block_reason enum: filter_subscription
-- proxy_hosts.cache_static_only
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS cache_static_only BOOLEAN NOT NULL DEFAULT true;
-- proxy_hosts.cache_ttl
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS cache_ttl VARCHAR(20) NOT NULL DEFAULT '7d';
-- geo_restrictions.allow_search_bots_cloud_providers
ALTER TABLE geo_restrictions ADD COLUMN IF NOT EXISTS allow_search_bots_cloud_providers BOOLEAN DEFAULT false;
-- proxy_hosts.is_favorite
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS is_favorite BOOLEAN NOT NULL DEFAULT false;
-- v1.3.4: proxy_hosts.proxy_connect_timeout
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_connect_timeout INT DEFAULT 0;
-- v1.3.4: proxy_hosts.proxy_send_timeout
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_send_timeout INT DEFAULT 0;
-- v1.3.4: proxy_hosts.proxy_read_timeout
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_read_timeout INT DEFAULT 0;
-- v1.3.4: proxy_hosts.proxy_buffering
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_buffering VARCHAR(10) DEFAULT '';
-- v1.3.4: proxy_hosts.proxy_request_buffering
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_request_buffering VARCHAR(10) DEFAULT '';
-- v1.3.4: proxy_hosts.client_max_body_size
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS client_max_body_size VARCHAR(20) DEFAULT '';
-- v1.3.4: proxy_hosts.proxy_max_temp_file_size
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_max_temp_file_size VARCHAR(20) DEFAULT '';
-- v2.18.0: proxy_hosts.proxy_type
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_type VARCHAR(20) NOT NULL DEFAULT 'http';
-- v2.18.0: proxy_hosts.stream_listen_host
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_listen_host VARCHAR(255) DEFAULT '';
-- v2.18.0: proxy_hosts.stream_listen_port
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_listen_port INT DEFAULT 0;
-- v2.18.0: proxy_hosts.stream_protocol
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_protocol VARCHAR(10) DEFAULT 'tcp';
-- v2.18.0: proxy_hosts.stream_ssl_preread
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_ssl_preread BOOLEAN NOT NULL DEFAULT false;
-- v2.18.0: proxy_hosts.stream_accept_proxy_protocol
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_accept_proxy_protocol BOOLEAN NOT NULL DEFAULT false;
-- v2.18.0: proxy_hosts.stream_send_proxy_protocol
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_send_proxy_protocol BOOLEAN NOT NULL DEFAULT false;
-- v2.18.0: proxy_hosts.stream_proxy_connect_timeout
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_proxy_connect_timeout INT DEFAULT 0;
-- v2.18.0: proxy_hosts.stream_proxy_timeout
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS stream_proxy_timeout INT DEFAULT 0;
-- v2.4.0: global_settings.proxy_buffering
ALTER TABLE global_settings ADD COLUMN IF NOT EXISTS proxy_buffering VARCHAR(10) DEFAULT '';
-- v2.4.0: global_settings.proxy_request_buffering
ALTER TABLE global_settings ADD COLUMN IF NOT EXISTS proxy_request_buffering VARCHAR(10) DEFAULT '';
-- v2.5.0: global_settings.ssl_ecdh_curve
ALTER TABLE global_settings ADD COLUMN IF NOT EXISTS ssl_ecdh_curve VARCHAR(255) NOT NULL DEFAULT 'X25519MLKEM768:X25519:secp256r1:secp384r1';
-- v2.13.2: exploit_block_rules.auto_disabled_at
ALTER TABLE exploit_block_rules ADD COLUMN IF NOT EXISTS auto_disabled_at DATETIME(6);
-- v2.13.2: host_exploit_rule_exclusions.uri_pattern
ALTER TABLE host_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern TEXT;
-- v2.13.2: global_exploit_rule_exclusions.uri_pattern
ALTER TABLE global_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern TEXT;
-- v2.13.2: drop global_exploit_rule_exclusions_rule_id_key
ALTER TABLE global_exploit_rule_exclusions DROP INDEX IF EXISTS global_exploit_rule_exclusions_rule_id_key;
-- v2.13.2: drop host_exploit_rule_exclusions_proxy_host_id_rule_id_key
ALTER TABLE host_exploit_rule_exclusions DROP INDEX IF EXISTS host_exploit_rule_exclusions_proxy_host_id_rule_id_key;
-- skipped (ALTER INDEX): v2.13.2: rename uq_global_exploit_rule_exclusions_rule_uri
-- skipped (ALTER INDEX): v2.13.2: rename uq_host_exploit_rule_exclusions_host_rule_uri
-- skipped (no mechanical translation): v2.13.2: idx_global_exploit_exclusions_rule_uri_unique
-- skipped (no mechanical translation): v2.13.2: idx_host_exploit_exclusions_host_rule_uri_unique
-- seed: exploit_block_rules system defaults
INSERT INTO exploit_block_rules (id, category, name, pattern, pattern_type, description, severity, enabled, is_system, sort_order, auto_disabled_at) VALUES ('4243721e-8f8d-4a2b-8496-0be62d50163f', 'sql_injection', 'SQL Union Select', '(\\"|''|`)(.*)(union)(.*)(select)(\\"|''|`)' , 'query_string', 'Blocks SQL UNION SELECT injection attempts', 'critical', true, true, 1, NULL), ('a5cb921c-2c10-475b-8753-a56e2af1e5ba', 'sql_injection', 'SQL Commands', '(;|\\||`|>|<|\\^|@)', 'query_string', 'Blocks SQL command characters (semicolon, pipe, backtick, redirects) (disabled by default: matches common URL characters like @, <, >; high false-positive rate)', 'warning', false, true, 2, CURRENT_TIMESTAMP(6)), ('41d1f7bf-9179-44cb-b41a-1685ce88d965', 'sql_injection', 'SQL Keywords', '\\b(select|insert|update|delete|drop|truncate|alter|create|exec)\\b', 'query_string', 'Blocks common SQL keywords in query strings (disabled by default: matches plain English words like ''update''/''select'' in search queries; ModSecurity/CRS handles SQL injection detection more precisely)', 'warning', false, true, 3, CURRENT_TIMESTAMP(6)), ('b890779f-757c-4461-a64a-dce59fb469e3', 'xss', 'Script Tags', '<script', 'query_string', 'Blocks script tag injection', 'critical', true, true, 10, NULL), ('27ed45b1-e030-4212-bc34-edc7e13a9695', 'xss', 'Event Handlers', 'on(click|load|error|mouseover|focus|blur|change|submit)=', 'query_string', 'Blocks JavaScript event handler injection', 'critical', true, true, 11, NULL), ('aa90285b-2986-46f9-80e6-99946327cd24', 'xss', 'Special Characters', '(;|<|>|"|%0A|%0D|%22|%3C|%3E|%00)', 'query_string', 'Blocks XSS special characters (semicolon, angle brackets, encoded newlines/quotes/null) (disabled by default: matches common characters in legitimate URL parameters like quotes; CRS provides more precise XSS detection)', 'warning', false, true, 12, CURRENT_TIMESTAMP(6)), ('23b31cc1-0e43-49af-b9c9-4093fd0cbcdc', 'rfi', 'URL Parameter Injection', '[a-zA-Z0-9_]=https?://', 'query_string', 'Blocks URL values in query parameters (RFI)', 'critical', true, true, 20, NULL), ('7db3e194-8731-40c1-afaa-b7555c017a3f', 'rfi', 'Path Traversal Sequences', '[a-zA-Z0-9_]=(\\.\\./)+', 'query_string', 'Blocks path traversal in parameters', 'critical', true, true, 21, NULL), ('650c5e4a-c373-4d99-9cac-9e86b55bcb33', 'rfi', 'Directory Traversal', '\\.\\./', 'query_string', 'Blocks directory traversal patterns', 'warning', true, true, 22, NULL), ('f055a131-0596-419f-944a-cb7fa40f5c59', 'scanner', 'Nikto Scanner', 'nikto', 'user_agent', 'Blocks Nikto vulnerability scanner', 'critical', true, true, 30, NULL), ('f13159ab-0e9a-45ea-aa4b-03fde63bb3e6', 'scanner', 'SQLMap Tool', 'sqlmap', 'user_agent', 'Blocks SQLMap SQL injection tool', 'critical', true, true, 31, NULL), ('a9baaa39-ccd9-4f8a-82c0-e7d85f02cc2f', 'scanner', 'DirBuster', 'dirbuster', 'user_agent', 'Blocks DirBuster directory scanner', 'critical', true, true, 32, NULL), ('8208101f-eb91-4b86-8396-f295cd16d04b', 'scanner', 'Nmap Scanner', 'nmap', 'user_agent', 'Blocks Nmap network scanner', 'warning', true, true, 33, NULL), ('7efe59af-2d2a-405e-bbe8-951757e72ef4', 'scanner', 'Nessus Scanner', 'nessus', 'user_agent', 'Blocks Nessus vulnerability scanner', 'warning', true, true, 34, NULL), ('9a5f6bcb-ceec-47f1-9f8c-dadb815711fa', 'scanner', 'OpenVAS Scanner', 'openvas', 'user_agent', 'Blocks OpenVAS security scanner', 'warning', true, true, 35, NULL), ('ab3b4e85-08fd-49fe-b76d-3dc5cdf5a248', 'scanner', 'W3AF Scanner', 'w3af', 'user_agent', 'Blocks W3AF web scanner', 'warning', true, true, 36, NULL), ('eb60d9dd-1d53-4a42-b571-cef1d1314d4d', 'scanner', 'Acunetix Scanner', 'acunetix', 'user_agent', 'Blocks Acunetix web scanner', 'warning', true, true, 37, NULL), ('86fddcd3-30ca-43d3-bd46-34875e018395', 'scanner', 'Havij Tool', 'havij', 'user_agent', 'Blocks Havij SQL injection tool', 'critical', true, true, 38, NULL), ('bd7eeece-8f91-41a6-b06c-1ad69900512d', 'scanner', 'AppScan', 'appscan', 'user_agent', 'Blocks IBM AppScan', 'warning', true, true, 39, NULL), ('6ee9b160-9472-4584-9c83-8de7b955a4b5', 'scanner', 'WebScarab', 'webscarab', 'user_agent', 'Blocks WebScarab proxy', 'warning', true, true, 40, NULL), ('e78e2ef1-d710-409b-8a44-a03db3999b19', 'scanner', 'WebInspect', 'webinspect', 'user_agent', 'Blocks HP WebInspect', 'warning', true, true, 41, NULL), ('8ec83a35-dea8-4f51-9185-37035f0a4501', 'http_method', 'Dangerous Methods', '^(TRACE|TRACK|DEBUG|CONNECT)$', 'request_method', 'Blocks dangerous HTTP methods', 'warning', true, true, 50, NULL) ON DUPLICATE KEY UPDATE id = id;
-- v2.4.0: idx_logs_part_block_reason_ts
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_ts ON logs_partitioned (block_reason, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE block_reason != 'none'
-- v2.4.0: idx_logs_part_client_ip
CREATE INDEX IF NOT EXISTS idx_logs_part_client_ip ON logs_partitioned (client_ip);
-- v2.4.0: idx_logs_part_created_at
CREATE INDEX IF NOT EXISTS idx_logs_part_created_at ON logs_partitioned (created_at DESC);
-- v2.4.0: idx_logs_part_status_code
CREATE INDEX IF NOT EXISTS idx_logs_part_status_code ON logs_partitioned (status_code);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE status_code IS NOT NULL
-- v2.3.5: proxy_hosts.config_status
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS config_status VARCHAR(20) NOT NULL DEFAULT 'ok';
-- v2.3.5: proxy_hosts.config_error
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS config_error TEXT;
-- skipped (DO $$): v1.3.31: proxy_hosts_access_list_id_fkey
-- v2.7.0: CREATE TABLE filter_subscriptions
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
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_filter_subscriptions_url (url(768))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- v2.7.0: CREATE TABLE filter_subscription_entries
CREATE TABLE IF NOT EXISTS filter_subscription_entries (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    value TEXT NOT NULL,
    reason TEXT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_subscription_id_value (subscription_id, value(731))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
ALTER TABLE filter_subscription_entries ADD CONSTRAINT fk_filter_subscription_entries_subscription_id FOREIGN KEY IF NOT EXISTS (subscription_id) REFERENCES filter_subscriptions(id) ON DELETE CASCADE;
-- skipped (no mechanical translation): v2.7.0: idx_fse_subscription
-- skipped (no mechanical translation): v2.7.0: idx_fse_value
-- v2.7.0: CREATE TABLE filter_subscription_host_exclusions
CREATE TABLE IF NOT EXISTS filter_subscription_host_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    proxy_host_id VARCHAR(36) NOT NULL,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_subscription_id_proxy_host_id (subscription_id, proxy_host_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
ALTER TABLE filter_subscription_host_exclusions ADD CONSTRAINT fk_filter_subscription_host_exclusions_subscription_id FOREIGN KEY IF NOT EXISTS (subscription_id) REFERENCES filter_subscriptions(id) ON DELETE CASCADE;
ALTER TABLE filter_subscription_host_exclusions ADD CONSTRAINT fk_filter_subscription_host_exclusions_proxy_host_id FOREIGN KEY IF NOT EXISTS (proxy_host_id) REFERENCES proxy_hosts(id) ON DELETE CASCADE;
-- skipped (no mechanical translation): v2.7.0: idx_fshe_proxy_host
-- v2.8.0: CREATE TABLE filter_subscription_entry_exclusions
CREATE TABLE IF NOT EXISTS filter_subscription_entry_exclusions (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    subscription_id VARCHAR(36) NOT NULL,
    value TEXT NOT NULL,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_subscription_id_value (subscription_id, value(731))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
ALTER TABLE filter_subscription_entry_exclusions ADD CONSTRAINT fk_filter_subscription_entry_exclusions_subscription_id FOREIGN KEY IF NOT EXISTS (subscription_id) REFERENCES filter_subscriptions(id) ON DELETE CASCADE;
-- skipped (no mechanical translation): v2.8.0: idx_fsee_subscription
-- v2.8.0: filter_subscriptions.exclude_private_ips
ALTER TABLE filter_subscriptions ADD COLUMN IF NOT EXISTS exclude_private_ips BOOLEAN DEFAULT false;
-- v2.7.3: system_settings.global_trusted_ips
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS global_trusted_ips TEXT DEFAULT ('');
-- v2.26.0: system_settings.global_trusted_ips_bypass_waf — opt-in WAF bypass for trusted IPs (#166)
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS global_trusted_ips_bypass_waf BOOLEAN NOT NULL DEFAULT false;
-- v2.8.0: idx_logs_part_host_ts
CREATE INDEX IF NOT EXISTS idx_logs_part_host_ts ON logs_partitioned (host(191), timestamp DESC);
-- v2.8.0: idx_logs_part_status_ts
CREATE INDEX IF NOT EXISTS idx_logs_part_status_ts ON logs_partitioned (status_code, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE status_code IS NOT NULL
-- v2.8.0: idx_logs_part_proxy_host_ts
CREATE INDEX IF NOT EXISTS idx_logs_part_proxy_host_ts ON logs_partitioned (proxy_host_id, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE proxy_host_id IS NOT NULL
-- v2.8.0: idx_logs_part_geo_ts
CREATE INDEX IF NOT EXISTS idx_logs_part_geo_ts ON logs_partitioned (geo_country_code, timestamp DESC);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE geo_country_code IS NOT NULL AND geo_country_code != ''
-- v2.8.0: idx_logs_part_type_created
CREATE INDEX IF NOT EXISTS idx_logs_part_type_created ON logs_partitioned (log_type, created_at DESC);
-- Issue #96: idx_logs_part_block_reason
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason ON logs_partitioned (block_reason);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE block_reason != 'none'
-- Issue #96: idx_logs_part_status_created
CREATE INDEX IF NOT EXISTS idx_logs_part_status_created ON logs_partitioned (status_code, created_at);
-- skipped (DELETE FROM dashboard_stats_hourly a): Issue #96: dedup dashboard_stats_hourly NULL proxy_host_id
-- skipped (partial unique index (generated column in 001_init.sql)): Issue #96: idx_dashboard_stats_hourly_null_host_bucket
-- v2.9.0: global_settings.enable_ipv6
ALTER TABLE global_settings ADD COLUMN IF NOT EXISTS enable_ipv6 BOOLEAN NOT NULL DEFAULT TRUE;
-- system_settings.ui_error_page_language
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ui_error_page_language VARCHAR(10) DEFAULT 'auto';
-- upstreams.scheme
ALTER TABLE upstreams ADD COLUMN IF NOT EXISTS scheme VARCHAR(10) NOT NULL DEFAULT 'http';
-- skipped (DO $$): logs.upstream_addr
-- skipped (DO $$): logs.upstream_status
-- logs_partitioned.upstream_addr
ALTER TABLE logs_partitioned ADD COLUMN IF NOT EXISTS upstream_addr TEXT;
-- logs_partitioned.upstream_status
ALTER TABLE logs_partitioned ADD COLUMN IF NOT EXISTS upstream_status TEXT;
-- exploit_block_rules.auto_disabled_at (defensive)
ALTER TABLE exploit_block_rules ADD COLUMN IF NOT EXISTS auto_disabled_at DATETIME(6);
-- host_exploit_rule_exclusions.uri_pattern (defensive)
ALTER TABLE host_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern TEXT;
-- global_exploit_rule_exclusions.uri_pattern (defensive)
ALTER TABLE global_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern TEXT;
-- skipped (DO $$): logs_unified view rebuild
-- v2.13.7: seed ENV-001 (Dotenv File Access) rule
INSERT INTO exploit_block_rules (id, category, name, pattern, pattern_type, description, severity, enabled, is_system, sort_order, auto_disabled_at) VALUES ( 'c1e7f001-0000-4000-8000-000000000001', 'rfi', 'Dotenv File Access', '/\\.env(\\.|$|/)', 'request_uri', 'Blocks access to .env config files (.env, .env.local, .env.production, ...)', 'critical', true, true, 23, NULL ) ON DUPLICATE KEY UPDATE id = id;
-- v2.13.17: btree index banned_ips(proxy_host_id, banned_at DESC)
CREATE INDEX IF NOT EXISTS idx_banned_ips_host_banned_at ON banned_ips (proxy_host_id, banned_at DESC);
-- v2.13.17: btree index bot_filters(proxy_host_id)
CREATE INDEX IF NOT EXISTS idx_bot_filters_proxy_host ON bot_filters (proxy_host_id);
-- v2.13.17: btree index rate_limits(proxy_host_id)
CREATE INDEX IF NOT EXISTS idx_rate_limits_proxy_host ON rate_limits (proxy_host_id);
-- v2.13.17: btree index security_headers(proxy_host_id)
CREATE INDEX IF NOT EXISTS idx_security_headers_proxy_host ON security_headers (proxy_host_id);
-- v2.13.17: btree index challenge_configs(proxy_host_id)
CREATE INDEX IF NOT EXISTS idx_challenge_configs_proxy_host ON challenge_configs (proxy_host_id);
-- v2.13.17: btree index upstreams(proxy_host_id)
CREATE INDEX IF NOT EXISTS idx_upstreams_proxy_host ON upstreams (proxy_host_id);
-- v2.13.17: btree index fail2ban_configs(proxy_host_id)
CREATE INDEX IF NOT EXISTS idx_fail2ban_configs_proxy_host ON fail2ban_configs (proxy_host_id);
-- v2.13.18: idx_logs_part_block_reason_created
CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_created ON logs_partitioned (created_at DESC, block_reason);  -- 부분 인덱스 술어 제거(최적화 목적일 뿐): WHERE block_reason != 'none' AND log_type = 'access'
-- v2.17.0: global_settings.worker_connections DEFAULT 1024 -> 8192
ALTER TABLE global_settings ALTER COLUMN worker_connections SET DEFAULT 8192;
-- v2.17.0: global_settings.keepalive_timeout DEFAULT 65 -> 30
ALTER TABLE global_settings ALTER COLUMN keepalive_timeout SET DEFAULT 30;
-- v2.17.0: global_settings.keepalive_requests DEFAULT 100 -> 1000
ALTER TABLE global_settings ALTER COLUMN keepalive_requests SET DEFAULT 1000;
-- v2.17.1: system_settings.raw_log_enabled force true on every row
UPDATE system_settings SET raw_log_enabled = true WHERE raw_log_enabled = false;
-- v2.17.1: system_settings.raw_log_enabled DEFAULT true (mandatory since v2.17.1)
ALTER TABLE system_settings ALTER COLUMN raw_log_enabled SET DEFAULT true;
-- skipped (partial unique index (generated column in 001_init.sql)): v2.18.0: proxy_hosts stream listener partial unique index
-- v2.20.0: proxy_hosts.forward_container_name (#150)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS forward_container_name TEXT;
-- v2.20.1: proxy_hosts.forward_container_network (#151)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS forward_container_network TEXT;
-- create ddns_records table (#154)
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
ALTER TABLE ddns_records ADD CONSTRAINT fk_ddns_records_dns_provider_id FOREIGN KEY IF NOT EXISTS (dns_provider_id) REFERENCES dns_providers(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ddns_records_hostname_provider ON ddns_records (hostname, dns_provider_id);
-- skipped (DO $$): v2.23.0: proxy_hosts.ddns_enabled/ddns_provider_id (#157)
-- v2.24.5: proxy_hosts.ddns_proxied default for managed DDNS (#160)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS ddns_proxied BOOLEAN NOT NULL DEFAULT false;
-- skipped (DO $$): v2.23.0: ddns_records.proxy_host_id (#157)
-- v2.23.0: system_settings.ddns_check_interval_minutes (#157)
ALTER TABLE system_settings ADD COLUMN IF NOT EXISTS ddns_check_interval_minutes INT NOT NULL DEFAULT 5;
-- v2.27.0: auth_providers table (#179)
CREATE TABLE IF NOT EXISTS auth_providers (
    id VARCHAR(36) NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL DEFAULT 'custom',
    provider_url TEXT NOT NULL,
    config JSON NOT NULL DEFAULT ('{}'),
    timeout_ms INT NOT NULL DEFAULT 5000,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT auth_providers_type_check CHECK (type IN ('authelia', 'authentik', 'custom'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
-- skipped (DO $$): v2.27.0: proxy_hosts.auth_provider_id/auth_bypass_paths (#179)
-- v2.28.0: auth_providers docker-container target columns (#181)
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS container_name TEXT;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS container_network TEXT;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS container_port INT;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS container_scheme TEXT;
-- v2.28.0: auth_providers container-reconcile health/status (#181 follow-up)
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS last_resolved_ip TEXT;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS last_reconcile_at DATETIME(6);
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS last_reconcile_status TEXT;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS last_reconcile_error TEXT;
ALTER TABLE auth_providers ADD COLUMN IF NOT EXISTS reconcile_fail_count INT NOT NULL DEFAULT 0;
-- v2.30.0: global_settings.access_log_strip_query
ALTER TABLE global_settings ADD COLUMN IF NOT EXISTS access_log_strip_query BOOLEAN NOT NULL DEFAULT false;
-- skipped (no mechanical translation): v2.31.0: global_geo_restrictions singleton + geo_restrictions.disable_global (#198)
-- skipped (no mechanical translation): v2.31.0: global_bot_filters singleton + bot_filters.disable_global (#198 slice 2)
-- skipped (no mechanical translation): v2.31.0: global_security_headers singleton + security_headers.disable_global (#198 slice 3)
-- skipped (no mechanical translation): v2.31.0: global_cloud_providers singleton + geo_restrictions.cloud_disable_global (#198 slice 4)
-- skipped (no mechanical translation): v2.31.0: global_rate_limits singleton + rate_limits.disable_global (#198 slice 5)
-- skipped (no mechanical translation): v2.31.0: global_waf singleton + proxy_hosts.waf_use_global (#198 slice 6)
-- skipped (no mechanical translation): v2.32.0: cloudflare_tunnel singleton (Cloudflare Tunnel Phase 1 token mode)
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
CREATE INDEX IF NOT EXISTS idx_log_filter_presets_log_type ON log_filter_presets (log_type(191));
-- skipped (no mechanical translation): v2.34.0: roles + role_permissions + users.role_id/must_change_password (RBAC, #222)
-- skipped (DO $$): v2.34.0: users.role_id FK -> roles (RBAC, #222)
-- v2.34.0: seed built-in roles and migrate existing accounts to administrator (RBAC, #222)
INSERT INTO roles (id, name, description, is_superuser, is_builtin) VALUES ('00000000-0000-0000-0000-0000000000a1', 'builtin.administrator', 'Full access to every area', true, true), ('00000000-0000-0000-0000-0000000000a2', 'builtin.operator', 'Day-to-day operation without settings or account administration', false, true), ('00000000-0000-0000-0000-0000000000a3', 'builtin.viewer', 'Read-only across the operational areas', false, true) ON DUPLICATE KEY UPDATE id = id;
INSERT INTO role_permissions (role_id, permission) VALUES ('00000000-0000-0000-0000-0000000000a2', 'dashboard:read'), ('00000000-0000-0000-0000-0000000000a2', 'proxy:read'), ('00000000-0000-0000-0000-0000000000a2', 'proxy:write'), ('00000000-0000-0000-0000-0000000000a2', 'redirect:read'), ('00000000-0000-0000-0000-0000000000a2', 'redirect:write'), ('00000000-0000-0000-0000-0000000000a2', 'waf:read'), ('00000000-0000-0000-0000-0000000000a2', 'waf:write'), ('00000000-0000-0000-0000-0000000000a2', 'access:read'), ('00000000-0000-0000-0000-0000000000a2', 'access:write'), ('00000000-0000-0000-0000-0000000000a2', 'authprovider:read'), ('00000000-0000-0000-0000-0000000000a2', 'authprovider:write'), ('00000000-0000-0000-0000-0000000000a2', 'certificate:read'), ('00000000-0000-0000-0000-0000000000a2', 'certificate:write'), ('00000000-0000-0000-0000-0000000000a2', 'ddns:read'), ('00000000-0000-0000-0000-0000000000a2', 'ddns:write'), ('00000000-0000-0000-0000-0000000000a2', 'logs:read'), ('00000000-0000-0000-0000-0000000000a2', 'backup:read'), ('00000000-0000-0000-0000-0000000000a3', 'dashboard:read'), ('00000000-0000-0000-0000-0000000000a3', 'proxy:read'), ('00000000-0000-0000-0000-0000000000a3', 'redirect:read'), ('00000000-0000-0000-0000-0000000000a3', 'waf:read'), ('00000000-0000-0000-0000-0000000000a3', 'access:read'), ('00000000-0000-0000-0000-0000000000a3', 'authprovider:read'), ('00000000-0000-0000-0000-0000000000a3', 'certificate:read'), ('00000000-0000-0000-0000-0000000000a3', 'ddns:read'), ('00000000-0000-0000-0000-0000000000a3', 'logs:read') ON CONFLICT (role_id, permission) DO NOTHING;
UPDATE users SET role_id = '00000000-0000-0000-0000-0000000000a1' WHERE role_id IS NULL;
-- v2.34.0: grant dnsprovider permissions to built-in roles (RBAC area split, #222)
INSERT INTO role_permissions (role_id, permission) VALUES ('00000000-0000-0000-0000-0000000000a2', 'dnsprovider:read'), ('00000000-0000-0000-0000-0000000000a2', 'dnsprovider:write'), ('00000000-0000-0000-0000-0000000000a3', 'dnsprovider:read') ON CONFLICT (role_id, permission) DO NOTHING;
-- skipped (no mechanical translation): v2.35.0: sso_providers + user_identities + sso_login_states (OIDC SSO, #227)
-- skipped (DO $$): v2.35.0: SSO foreign keys (OIDC SSO, #227)
-- skipped (no mechanical translation): v2.36.0: notification_channels + notification_state + notification_outbox (#221)
-- skipped (DO $$): v2.36.0: notification_outbox FK -> notification_channels (#221)
-- v2.36.0: per-event delivery mode and platform-native formatting (#221)
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS digest_events TEXT NOT NULL DEFAULT ('{}');
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS rich_format BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS language VARCHAR(8) NOT NULL DEFAULT 'en';
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS dashboard_url TEXT;
-- v2.36.0: readable subject label on notification state (#221)
ALTER TABLE notification_state ADD COLUMN IF NOT EXISTS subject_label VARCHAR(255);

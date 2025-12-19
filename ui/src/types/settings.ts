// Global Settings Types
export interface GlobalSettings {
  id: string;

  // Worker settings
  worker_processes: number;
  worker_connections: number;
  worker_rlimit_nofile?: number;

  // Event settings
  multi_accept: boolean;
  use_epoll: boolean;

  // HTTP settings
  sendfile: boolean;
  tcp_nopush: boolean;
  tcp_nodelay: boolean;
  keepalive_timeout: number;
  keepalive_requests: number;
  types_hash_max_size: number;
  server_tokens: boolean;

  // Client Buffer settings
  client_body_buffer_size: string;
  client_header_buffer_size: string;
  client_max_body_size: string;
  large_client_header_buffers: string;

  // Proxy Buffer settings
  proxy_buffer_size?: string;
  proxy_buffers?: string;
  proxy_busy_buffers_size?: string;
  proxy_max_temp_file_size?: string;
  proxy_temp_file_write_size?: string;

  // Open File Cache settings
  open_file_cache_enabled?: boolean;
  open_file_cache_max?: number;
  open_file_cache_inactive?: string;
  open_file_cache_valid?: string;
  open_file_cache_min_uses?: number;
  open_file_cache_errors?: boolean;

  // Timeout settings
  client_body_timeout: number;
  client_header_timeout: number;
  send_timeout: number;
  proxy_connect_timeout: number;
  proxy_send_timeout: number;
  proxy_read_timeout: number;

  // Gzip settings
  gzip_enabled: boolean;
  gzip_vary: boolean;
  gzip_proxied: string;
  gzip_comp_level: number;
  gzip_buffers: string;
  gzip_http_version: string;
  gzip_min_length: number;
  gzip_types: string;

  // Brotli settings
  brotli_enabled: boolean;
  brotli_static: boolean;
  brotli_comp_level: number;
  brotli_min_length: number;
  brotli_types: string;

  // SSL/TLS settings
  ssl_protocols: string;
  ssl_ciphers: string;
  ssl_prefer_server_ciphers: boolean;
  ssl_session_cache: string;
  ssl_session_timeout: string;
  ssl_session_tickets: boolean;
  ssl_stapling: boolean;
  ssl_stapling_verify: boolean;

  // Logging settings
  access_log_enabled: boolean;
  error_log_level: string;

  // Resolver settings
  resolver?: string;
  resolver_timeout?: string;

  // Custom config
  custom_http_config?: string;
  custom_stream_config?: string;

  // Direct IP Access settings
  direct_ip_access_action: 'allow' | 'block_403' | 'block_444';

  // DDoS Protection - Connection limiting
  limit_conn_enabled: boolean;
  limit_conn_zone_size: string;
  limit_conn_per_ip: number;

  // DDoS Protection - Request rate limiting (global)
  limit_req_enabled: boolean;
  limit_req_zone_size: string;
  limit_req_rate: number;
  limit_req_burst: number;

  // DDoS Protection - Timeout/Connection reset
  reset_timedout_connection: boolean;

  // DDoS Protection - Response rate limiting (bandwidth throttling)
  limit_rate: number;
  limit_rate_after: string;

  created_at: string;
  updated_at: string;
}

export interface UpdateSettingsRequest {
  worker_processes?: number;
  worker_connections?: number;
  keepalive_timeout?: number;
  client_max_body_size?: string;
  gzip_enabled?: boolean;
  gzip_comp_level?: number;
  brotli_enabled?: boolean;
  brotli_static?: boolean;
  brotli_comp_level?: number;
  brotli_min_length?: number;
  brotli_types?: string;
  ssl_protocols?: string;
  server_tokens?: boolean;
  direct_ip_access_action?: 'allow' | 'block_403' | 'block_444';
  // DDoS Protection
  limit_conn_enabled?: boolean;
  limit_conn_zone_size?: string;
  limit_conn_per_ip?: number;
  limit_req_enabled?: boolean;
  limit_req_zone_size?: string;
  limit_req_rate?: number;
  limit_req_burst?: number;
  reset_timedout_connection?: boolean;
  limit_rate?: number;
  limit_rate_after?: string;
}

// Dashboard Types
export interface SystemHealth {
  id?: string;
  recorded_at: string;
  nginx_status: string;
  nginx_workers: number;
  nginx_connections_active: number;
  nginx_connections_reading: number;
  nginx_connections_writing: number;
  nginx_connections_waiting: number;
  db_status: string;
  db_connections: number;
  // Host resource metrics
  cpu_usage: number;
  memory_usage: number;
  memory_total: number;
  memory_used: number;
  disk_usage: number;
  disk_total: number;
  disk_used: number;
  disk_path: string;
  uptime_seconds: number;
  // Host system info
  hostname: string;
  os: string;
  platform: string;
  kernel_version: string;
  // Network I/O
  network_in: number;
  network_out: number;
  // Certificate status
  certs_total: number;
  certs_expiring_soon: number;
  certs_expired: number;
  upstreams_total: number;
  upstreams_healthy: number;
  upstreams_unhealthy: number;
}

export interface ChartDataPoint {
  timestamp: string;
  value: number;
}

export interface StatusCodePoint {
  timestamp: string;
  status_2xx: number;
  status_3xx: number;
  status_4xx: number;
  status_5xx: number;
}

export interface SecurityChartPoint {
  timestamp: string;
  waf_blocked: number;
  rate_limited: number;
  bot_blocked: number;
}

export interface HostStat {
  host_id: string;
  domain: string;
  requests: number;
}

export interface CountryStat {
  country: string;
  count: number;
}

export interface IPStat {
  ip: string;
  count: number;
}

export interface UserAgentStat {
  user_agent: string;
  count: number;
  category: 'search_engine' | 'ai_bot' | 'bad_bot' | 'monitoring' | 'cli_tool' | 'browser' | 'mobile' | 'other';
}

export interface DashboardSummary {
  system_health: SystemHealth;
  total_requests_24h: number;
  total_bandwidth_24h: number;
  avg_response_time_24h: number;
  error_rate_24h: number;
  waf_blocked_24h: number;
  rate_limited_24h: number;
  bot_blocked_24h: number;
  banned_ips: number;
  blocked_requests_24h: number;
  blocked_unique_ips_24h: number;
  total_proxy_hosts: number;
  active_proxy_hosts: number;
  total_redirect_hosts: number;
  total_certificates: number;
  expiring_certificates: number;
  requests_chart: ChartDataPoint[];
  bandwidth_chart: ChartDataPoint[];
  status_code_chart: StatusCodePoint[];
  security_chart: SecurityChartPoint[];
  top_hosts: HostStat[];
  top_countries: CountryStat[];
  top_ips: IPStat[];
  top_user_agents: UserAgentStat[];
}

// Backup Types
export interface Backup {
  id: string;
  filename: string;
  file_size: number;
  file_path: string;
  includes_config: boolean;
  includes_certificates: boolean;
  includes_database: boolean;
  backup_type: string;
  description?: string;
  status: string;
  error_message?: string;
  checksum_sha256?: string;
  created_at: string;
  completed_at?: string;
}

export interface BackupListResponse {
  data: Backup[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface BackupStats {
  total_backups: number;
  total_size: number;
  last_backup?: string;
  last_successful?: string;
  scheduled_enabled: boolean;
  schedule_interval?: string;
  retention_days: number;
}

export interface CreateBackupRequest {
  includes_config: boolean;
  includes_certificates: boolean;
  includes_database: boolean;
  description?: string;
}

// Docker Container Stats Types
export interface ContainerStats {
  container_id: string;
  container_name: string;
  cpu_percent: number;
  memory_usage: number;
  memory_limit: number;
  memory_percent: number;
  net_i: number;
  net_o: number;
  block_i: number;
  block_o: number;
  pids: number;
  status: string;
}

export interface DockerStatsSummary {
  containers: ContainerStats[];
  total_cpu_percent: number;
  total_memory_usage: number;
  total_memory_limit: number;
  container_count: number;
  healthy_count: number;
  updated_at: string;
}

// System Settings Types (GeoIP, ACME, etc.)
export interface SystemSettings {
  id: string;

  // GeoIP Settings
  geoip_enabled: boolean;
  maxmind_license_key: string; // Masked in response
  maxmind_account_id: string;
  geoip_auto_update: boolean;
  geoip_update_interval: string;
  geoip_last_updated?: string;
  geoip_database_version: string;
  geoip_status: 'active' | 'inactive' | 'pending' | 'error';

  // ACME / Let's Encrypt Settings
  acme_enabled: boolean;
  acme_email: string;
  acme_staging: boolean;
  acme_auto_renew: boolean;
  acme_renew_days_before: number;
  acme_dns_provider: string;
  acme_dns_configured: boolean;

  // Notification Settings
  notification_email: string;
  notify_cert_expiry: boolean;
  notify_cert_expiry_days: number;
  notify_security_events: boolean;
  notify_backup_complete: boolean;

  // Maintenance Settings
  log_retention_days: number;
  stats_retention_days: number;
  backup_retention_count: number;
  auto_backup_enabled: boolean;
  auto_backup_schedule: string;

  // Log Retention Settings (per log type)
  access_log_retention_days: number; // Default: 1095 (3 years)
  waf_log_retention_days: number; // Default: 90 (3 months)
  error_log_retention_days: number; // Default: 30 (1 month)
  system_log_retention_days: number; // Default: 30 (1 month)
  audit_log_retention_days: number; // Default: 1095 (3 years)

  // Raw Log File Settings
  raw_log_enabled: boolean;
  raw_log_retention_days: number;
  raw_log_max_size_mb: number;
  raw_log_rotate_count: number;
  raw_log_compress_rotated: boolean;

  // Bot Filter Default Settings
  bot_filter_default_enabled: boolean;
  bot_filter_default_block_bad_bots: boolean;
  bot_filter_default_block_ai_bots: boolean;
  bot_filter_default_allow_search_engines: boolean;
  bot_filter_default_block_suspicious_clients: boolean;
  bot_filter_default_challenge_suspicious: boolean;
  bot_filter_default_custom_blocked_agents: string;

  // Bot Lists (global)
  bot_list_bad_bots: string;
  bot_list_ai_bots: string;
  bot_list_search_engines: string;
  bot_list_suspicious_clients: string;

  // WAF Auto-Ban Settings
  waf_auto_ban_enabled: boolean;
  waf_auto_ban_threshold: number;
  waf_auto_ban_window: number;
  waf_auto_ban_duration: number;

  // Direct IP Access Settings
  direct_ip_access_action: 'allow' | 'block_403' | 'block_444';

  // Global Block Exploits Exceptions
  global_block_exploits_exceptions: string;

  updated_at: string;
}

export interface UpdateSystemSettingsRequest {
  // GeoIP Settings
  geoip_enabled?: boolean;
  maxmind_license_key?: string;
  maxmind_account_id?: string;
  geoip_auto_update?: boolean;
  geoip_update_interval?: string;

  // ACME Settings
  acme_enabled?: boolean;
  acme_email?: string;
  acme_staging?: boolean;
  acme_auto_renew?: boolean;
  acme_renew_days_before?: number;
  acme_dns_provider?: string;
  acme_dns_credentials?: object;

  // Notification Settings
  notification_email?: string;
  notify_cert_expiry?: boolean;
  notify_cert_expiry_days?: number;
  notify_security_events?: boolean;
  notify_backup_complete?: boolean;

  // Maintenance Settings
  log_retention_days?: number;
  stats_retention_days?: number;
  backup_retention_count?: number;
  auto_backup_enabled?: boolean;
  auto_backup_schedule?: string;

  // Log Retention Settings (per log type)
  access_log_retention_days?: number;
  waf_log_retention_days?: number;
  error_log_retention_days?: number;
  system_log_retention_days?: number;
  audit_log_retention_days?: number;

  // Raw Log File Settings
  raw_log_enabled?: boolean;
  raw_log_retention_days?: number;
  raw_log_max_size_mb?: number;
  raw_log_rotate_count?: number;
  raw_log_compress_rotated?: boolean;

  // Bot Filter Default Settings
  bot_filter_default_enabled?: boolean;
  bot_filter_default_block_bad_bots?: boolean;
  bot_filter_default_block_ai_bots?: boolean;
  bot_filter_default_allow_search_engines?: boolean;
  bot_filter_default_block_suspicious_clients?: boolean;
  bot_filter_default_challenge_suspicious?: boolean;
  bot_filter_default_custom_blocked_agents?: string;

  // Bot Lists (global)
  bot_list_bad_bots?: string;
  bot_list_ai_bots?: string;
  bot_list_search_engines?: string;
  bot_list_suspicious_clients?: string;

  // WAF Auto-Ban Settings
  waf_auto_ban_enabled?: boolean;
  waf_auto_ban_threshold?: number;
  waf_auto_ban_window?: number;
  waf_auto_ban_duration?: number;

  // Direct IP Access Settings
  direct_ip_access_action?: 'allow' | 'block_403' | 'block_444';

  // Global Block Exploits Exceptions
  global_block_exploits_exceptions?: string;

  // UI Settings (global)
  ui_font_family?: string;
}

export interface GeoIPStatus {
  enabled: boolean;
  status: 'active' | 'inactive' | 'updating' | 'error';
  country_db: boolean;
  asn_db: boolean;
  last_updated?: string;
  database_version: string;
  next_update?: string;
  error_message?: string;
}

// Log File Management Types
export interface LogFileInfo {
  name: string;
  size: number;
  modified_at: string;
  is_compressed: boolean;
  log_type: 'access' | 'error' | 'unknown';
}

export interface LogFilesResponse {
  files: LogFileInfo[];
  total_size: number;
  total_count: number;
  raw_log_enabled: boolean;
}

export interface LogFileViewResponse {
  filename: string;
  lines: number;
  content: string;
}

// System Log Configuration
export interface SystemLogConfig {
  enabled: boolean;
  levels: Record<string, string>;
  exclude_patterns: string[];
  stdout_excluded: string[];
}

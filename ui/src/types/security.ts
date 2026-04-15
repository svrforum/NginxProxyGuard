// Rate Limit types
export interface RateLimit {
  id: string;
  proxy_host_id: string;
  enabled: boolean;
  requests_per_second: number;
  burst_size: number;
  zone_size: string;
  limit_by: 'ip' | 'uri' | 'ip_uri';
  limit_response: number;
  whitelist_ips?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateRateLimitRequest {
  enabled?: boolean;
  requests_per_second?: number;
  burst_size?: number;
  zone_size?: string;
  limit_by?: string;
  limit_response?: number;
  whitelist_ips?: string;
}

// Fail2ban types
export interface Fail2banConfig {
  id: string;
  proxy_host_id: string;
  enabled: boolean;
  max_retries: number;
  find_time: number;
  ban_time: number;
  fail_codes: string;
  action: 'block' | 'log' | 'notify';
  created_at: string;
  updated_at: string;
}

export interface CreateFail2banRequest {
  enabled?: boolean;
  max_retries?: number;
  find_time?: number;
  ban_time?: number;
  fail_codes?: string;
  action?: string;
}

// Banned IP types
export interface BannedIP {
  id: string;
  proxy_host_id?: string;
  ip_address: string;
  reason?: string;
  fail_count: number;
  banned_at: string;
  expires_at?: string;
  is_permanent: boolean;
  created_at: string;
}

export interface BannedIPListResponse {
  data: BannedIP[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface BanIPRequest {
  proxy_host_id?: string;
  ip_address: string;
  reason?: string;
  ban_time?: number;
}

// IP Ban History types
export type BanEventType = 'ban' | 'unban';
export type BanSource = 'fail2ban' | 'waf_auto_ban' | 'manual' | 'api' | 'expired';

export interface IPBanHistory {
  id: string;
  event_type: BanEventType;
  ip_address: string;
  proxy_host_id?: string;
  domain_name?: string;
  reason?: string;
  source: BanSource;
  ban_duration?: number;
  expires_at?: string;
  is_permanent: boolean;
  is_auto: boolean;
  fail_count?: number;
  user_id?: string;
  user_email?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface IPBanHistoryListResponse {
  data: IPBanHistory[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface IPBanHistoryFilter {
  ip_address?: string;
  event_type?: BanEventType;
  source?: BanSource;
  proxy_host_id?: string;
  start_date?: string;
  end_date?: string;
  page?: number;
  per_page?: number;
}

export interface IPBanCount {
  ip_address: string;
  ban_count: number;
}

export interface IPBanHistoryStats {
  total_bans: number;
  total_unbans: number;
  active_bans: number;
  bans_by_source: Record<string, number>;
  top_banned_ips: IPBanCount[];
}

// Bot Filter types
export interface BotFilter {
  id: string;
  proxy_host_id: string;
  enabled: boolean;
  block_bad_bots: boolean;
  block_ai_bots: boolean;
  allow_search_engines: boolean;
  block_suspicious_clients: boolean;
  custom_blocked_agents?: string;
  custom_allowed_agents?: string;
  challenge_suspicious: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateBotFilterRequest {
  enabled?: boolean;
  block_bad_bots?: boolean;
  block_ai_bots?: boolean;
  allow_search_engines?: boolean;
  block_suspicious_clients?: boolean;
  custom_blocked_agents?: string;
  custom_allowed_agents?: string;
  challenge_suspicious?: boolean;
}

export interface KnownBots {
  bad_bots: string[];
  ai_bots: string[];
  search_engine_bots: string[];
}

// Security Headers types
export interface SecurityHeaders {
  id: string;
  proxy_host_id: string;
  enabled: boolean;
  hsts_enabled: boolean;
  hsts_max_age: number;
  hsts_include_subdomains: boolean;
  hsts_preload: boolean;
  x_frame_options: string;
  x_content_type_options: boolean;
  x_xss_protection: boolean;
  referrer_policy: string;
  content_security_policy?: string;
  permissions_policy?: string;
  custom_headers?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface CreateSecurityHeadersRequest {
  enabled?: boolean;
  hsts_enabled?: boolean;
  hsts_max_age?: number;
  hsts_include_subdomains?: boolean;
  hsts_preload?: boolean;
  x_frame_options?: string;
  x_content_type_options?: boolean;
  x_xss_protection?: boolean;
  referrer_policy?: string;
  content_security_policy?: string;
  permissions_policy?: string;
  custom_headers?: Record<string, string>;
}

// Upstream types
export interface UpstreamServer {
  id?: string;
  upstream_id?: string;
  address: string;
  port: number;
  weight: number;
  max_fails: number;
  fail_timeout: number;
  is_backup: boolean;
  is_down: boolean;
  is_healthy: boolean;
  last_check_at?: string;
  last_error?: string;
}

export interface Upstream {
  id: string;
  proxy_host_id: string;
  name: string;
  scheme: 'http' | 'https';
  servers: UpstreamServer[];
  load_balance: 'round_robin' | 'least_conn' | 'ip_hash' | 'random';
  health_check_enabled: boolean;
  health_check_interval: number;
  health_check_timeout: number;
  health_check_path: string;
  health_check_expected_status: number;
  keepalive: number;
  is_healthy: boolean;
  last_check_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateUpstreamRequest {
  name?: string;
  scheme?: 'http' | 'https';
  servers?: {
    address: string;
    port?: number;
    weight?: number;
    max_fails?: number;
    fail_timeout?: number;
    is_backup?: boolean;
    is_down?: boolean;
  }[];
  load_balance?: string;
  health_check_enabled?: boolean;
  health_check_interval?: number;
  health_check_timeout?: number;
  health_check_path?: string;
  health_check_expected_status?: number;
  keepalive?: number;
}

export interface ServerHealthStatus {
  address: string;
  port: number;
  is_healthy: boolean;
  is_backup: boolean;
  is_down: boolean;
  last_check_at?: string;
  last_error?: string;
  response_time_ms?: number;
}

export interface UpstreamHealthStatus {
  upstream_id: string;
  name: string;
  is_healthy: boolean;
  healthy_count: number;
  unhealthy_count: number;
  last_check_at?: string;
  servers: ServerHealthStatus[];
}

// URI Block types
export type URIMatchType = 'exact' | 'prefix' | 'regex';

export interface URIBlockRule {
  id: string;
  pattern: string;
  match_type: URIMatchType;
  description?: string;
  enabled: boolean;
}

export interface URIBlock {
  id: string;
  proxy_host_id: string;
  enabled: boolean;
  rules: URIBlockRule[];
  exception_ips: string[];
  allow_private_ips: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateURIBlockRequest {
  enabled?: boolean;
  rules?: URIBlockRule[];
  exception_ips?: string[];
  allow_private_ips?: boolean;
}

export interface AddURIBlockRuleRequest {
  pattern: string;
  match_type: URIMatchType;
  description?: string;
  enabled?: boolean;
}

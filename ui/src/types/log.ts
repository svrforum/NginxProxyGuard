export type LogType = "access" | "error" | "modsec";

export type LogSeverity =
  | "debug"
  | "info"
  | "notice"
  | "warn"
  | "error"
  | "crit"
  | "alert"
  | "emerg";

export type BlockReason =
  | "none"
  | "waf"
  | "bot_filter"
  | "rate_limit"
  | "geo_block"
  | "exploit_block"
  | "banned_ip"
  | "uri_block"
  | "cloud_provider_challenge"
  | "cloud_provider_block"
  | "access_denied";

export type BotCategory = "bad_bot" | "ai_bot" | "suspicious" | "search_engine";

export interface Log {
  id: string;
  log_type: LogType;
  timestamp: string;
  host?: string;
  client_ip?: string;

  // GeoIP fields
  geo_country?: string;
  geo_country_code?: string;
  geo_city?: string;
  geo_asn?: string;
  geo_org?: string;

  // Access log fields
  request_method?: string;
  request_uri?: string;
  request_protocol?: string;
  status_code?: number;
  body_bytes_sent?: number;
  request_time?: number;
  upstream_response_time?: number;
  http_referer?: string;
  http_user_agent?: string;
  http_x_forwarded_for?: string;

  // Error log fields
  severity?: LogSeverity;
  error_message?: string;

  // ModSecurity WAF fields
  rule_id?: number;
  rule_message?: string;
  rule_severity?: string;
  rule_data?: string;
  attack_type?: string;
  action_taken?: string;

  // Metadata
  proxy_host_id?: string;
  raw_log?: string;

  // Block reason fields
  block_reason?: BlockReason;
  bot_category?: BotCategory;
  exploit_rule?: string;

  created_at: string;
}

export interface LogFilter {
  log_type?: LogType;
  // Array filters for multi-select support
  hosts?: string[];
  client_ips?: string[];
  uris?: string[];
  user_agents?: string[];
  // Legacy single-value filters (for backward compatibility)
  host?: string;
  client_ip?: string;
  uri?: string;
  user_agent?: string;

  status_code?: number;
  severity?: LogSeverity;
  rule_id?: number;
  proxy_host_id?: string;
  start_time?: string;
  end_time?: string;
  search?: string;

  // Extended filters
  method?: string;
  geo_country_code?: string;
  status_codes?: number[];
  min_size?: number;
  max_size?: number;
  min_request_time?: number;

  // Block reason filters
  block_reason?: BlockReason;
  bot_category?: BotCategory;
  exploit_rule?: string;

  // Exclude filters
  exclude_ips?: string[];
  exclude_user_agents?: string[];
  exclude_uris?: string[];
  exclude_hosts?: string[];
  exclude_countries?: string[];

  // Sorting
  sort_by?:
    | "timestamp"
    | "body_bytes_sent"
    | "request_time"
    | "status_code"
    | "client_ip"
    | "host";
  sort_order?: "asc" | "desc";
}

export interface LogListResponse {
  data: Log[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface LogStats {
  total_logs: number;
  access_logs: number;
  error_logs: number;
  modsec_logs: number;
  top_status_codes?: { status_code: number; count: number }[];
  top_client_ips?: { client_ip: string; count: number }[];
  top_user_agents?: { user_agent: string; count: number }[];
  top_attacked_uris?: { uri: string; count: number }[];
  top_rule_ids?: { rule_id: number; message: string; count: number }[];
  top_countries?: CountryStat[];
}

export interface LogSettings {
  id: string;
  retention_days: number;
  max_logs_per_type?: number;
  auto_cleanup_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CountryStat {
  country_code: string;
  country: string;
  count: number;
}

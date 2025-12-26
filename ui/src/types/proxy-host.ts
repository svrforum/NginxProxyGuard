export interface ProxyHost {
  id: string
  domain_names: string[]
  forward_scheme: 'http' | 'https'
  forward_host: string
  forward_port: number
  ssl_enabled: boolean
  ssl_force_https: boolean
  ssl_http2: boolean
  ssl_http3: boolean
  certificate_id?: string
  allow_websocket_upgrade: boolean
  cache_enabled: boolean
  cache_static_only: boolean
  cache_ttl: string
  block_exploits: boolean
  block_exploits_exceptions?: string
  custom_locations?: unknown[]
  advanced_config?: string
  // Host-level proxy settings (override global)
  proxy_connect_timeout?: number
  proxy_send_timeout?: number
  proxy_read_timeout?: number
  proxy_buffering?: string
  client_max_body_size?: string
  proxy_max_temp_file_size?: string
  waf_enabled: boolean
  waf_mode: string
  waf_paranoia_level: number
  waf_anomaly_threshold: number
  access_list_id?: string
  enabled: boolean
  meta?: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface CreateProxyHostRequest {
  domain_names: string[]
  forward_scheme: 'http' | 'https'
  forward_host: string
  forward_port: number
  ssl_enabled?: boolean
  ssl_force_https?: boolean
  ssl_http2?: boolean
  ssl_http3?: boolean
  certificate_id?: string
  access_list_id?: string
  allow_websocket_upgrade?: boolean
  cache_enabled?: boolean
  cache_static_only?: boolean
  cache_ttl?: string
  block_exploits?: boolean
  block_exploits_exceptions?: string
  // Host-level proxy settings (override global)
  proxy_connect_timeout?: number
  proxy_send_timeout?: number
  proxy_read_timeout?: number
  proxy_buffering?: string
  client_max_body_size?: string
  proxy_max_temp_file_size?: string
  waf_enabled?: boolean
  waf_mode?: 'blocking' | 'detection'
  waf_paranoia_level?: number
  waf_anomaly_threshold?: number
  advanced_config?: string
  enabled?: boolean
}

export interface UpdateProxyHostRequest {
  domain_names?: string[]
  forward_scheme?: 'http' | 'https'
  forward_host?: string
  forward_port?: number
  ssl_enabled?: boolean
  ssl_force_https?: boolean
  ssl_http2?: boolean
  ssl_http3?: boolean
  certificate_id?: string
  allow_websocket_upgrade?: boolean
  cache_enabled?: boolean
  cache_static_only?: boolean
  cache_ttl?: string
  block_exploits?: boolean
  block_exploits_exceptions?: string
  // Host-level proxy settings (override global)
  proxy_connect_timeout?: number
  proxy_send_timeout?: number
  proxy_read_timeout?: number
  proxy_buffering?: string
  client_max_body_size?: string
  proxy_max_temp_file_size?: string
  waf_enabled?: boolean
  waf_mode?: 'blocking' | 'detection'
  waf_paranoia_level?: number
  waf_anomaly_threshold?: number
  advanced_config?: string
  enabled?: boolean
}

export interface ProxyHostListResponse {
  data: ProxyHost[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// Test result types
export interface ProxyHostTestResult {
  domain: string
  tested_at: string
  success: boolean
  response_time_ms: number
  status_code?: number
  error?: string
  ssl?: SSLTestResult
  http?: HTTPTestResult
  cache?: CacheTestResult
  security?: SecurityTestResult
  headers?: Record<string, string>
}

export interface SSLTestResult {
  enabled: boolean
  valid: boolean
  protocol?: string
  cipher?: string
  issuer?: string
  subject?: string
  not_before?: string
  not_after?: string
  days_remaining?: number
  error?: string
}

export interface HTTPTestResult {
  http2_enabled: boolean
  http3_enabled: boolean
  alt_svc_header?: string
  protocol?: string
}

export interface CacheTestResult {
  enabled: boolean
  cache_status?: string
  cache_control?: string
  expires?: string
  etag?: string
  last_modified?: string
}

export interface SecurityTestResult {
  hsts: boolean
  hsts_value?: string
  x_frame_options?: string
  x_content_type_options?: string
  content_security_policy?: string
  xss_protection?: string
  referrer_policy?: string
  permissions_policy?: string
  server_header?: string
}

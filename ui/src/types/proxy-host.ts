export type ProxyType = 'http' | 'stream'
export type ForwardScheme = 'http' | 'https' | 'tcp' | 'udp'
export type StreamProtocol = 'tcp' | 'udp'

export interface ProxyHost {
  id: string
  proxy_type: ProxyType
  domain_names: string[]
  forward_scheme: ForwardScheme
  forward_host: string
  forward_container_name?: string | null
  forward_container_network?: string | null
  forward_port: number
  stream_listen_host?: string
  stream_listen_port?: number
  stream_protocol?: StreamProtocol
  stream_ssl_preread?: boolean
  stream_accept_proxy_protocol?: boolean
  stream_send_proxy_protocol?: boolean
  stream_proxy_connect_timeout?: number
  stream_proxy_timeout?: number
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
  proxy_request_buffering?: string
  client_max_body_size?: string
  proxy_max_temp_file_size?: string
  waf_enabled: boolean
  waf_mode: string
  waf_paranoia_level: number
  waf_anomaly_threshold: number
  access_list_id?: string
  ddns_enabled?: boolean
  ddns_provider_id?: string
  ddns_proxied?: boolean
  enabled: boolean
  is_favorite: boolean
  config_status: string
  config_error?: string
  meta?: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface CreateProxyHostRequest {
  proxy_type?: ProxyType
  domain_names: string[]
  forward_scheme: ForwardScheme
  forward_host: string
  forward_container_name?: string | null
  forward_container_network?: string | null
  forward_port: number
  stream_listen_host?: string
  stream_listen_port?: number
  stream_protocol?: StreamProtocol
  stream_ssl_preread?: boolean
  stream_accept_proxy_protocol?: boolean
  stream_send_proxy_protocol?: boolean
  stream_proxy_connect_timeout?: number
  stream_proxy_timeout?: number
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
  proxy_request_buffering?: string
  client_max_body_size?: string
  proxy_max_temp_file_size?: string
  waf_enabled?: boolean
  waf_mode?: 'blocking' | 'detection'
  waf_paranoia_level?: number
  waf_anomaly_threshold?: number
  advanced_config?: string
  ddns_enabled?: boolean
  ddns_provider_id?: string
  ddns_proxied?: boolean
  enabled?: boolean
}

export interface UpdateProxyHostRequest {
  proxy_type?: ProxyType
  domain_names?: string[]
  forward_scheme?: ForwardScheme
  forward_host?: string
  forward_container_name?: string | null
  forward_container_network?: string | null
  forward_port?: number
  stream_listen_host?: string
  stream_listen_port?: number
  stream_protocol?: StreamProtocol
  stream_ssl_preread?: boolean
  stream_accept_proxy_protocol?: boolean
  stream_send_proxy_protocol?: boolean
  stream_proxy_connect_timeout?: number
  stream_proxy_timeout?: number
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
  proxy_request_buffering?: string
  client_max_body_size?: string
  proxy_max_temp_file_size?: string
  waf_enabled?: boolean
  waf_mode?: 'blocking' | 'detection'
  waf_paranoia_level?: number
  waf_anomaly_threshold?: number
  access_list_id?: string
  advanced_config?: string
  ddns_enabled?: boolean
  ddns_provider_id?: string
  ddns_proxied?: boolean
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
  stream?: StreamTestResult
  ssl?: SSLTestResult
  http?: HTTPTestResult
  cache?: CacheTestResult
  security?: SecurityTestResult
  ddns?: DDNSTestResult
  headers?: Record<string, string>
}

export interface DDNSTestResult {
  enabled: boolean
  provider_name?: string
  provider_type?: string
  credentials_valid: boolean
  credential_error?: string
  last_status?: string
  last_ip?: string
  last_synced_at?: string
}

export interface StreamTestResult {
  protocol: StreamProtocol
  target_address: string
  upstream_address?: string
  ssl_preread: boolean
  proxy_protocol_in: boolean
  proxy_protocol_out: boolean
  remote_address_note?: string
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

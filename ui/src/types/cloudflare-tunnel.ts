export interface CloudflareTunnelSettings {
  id: string
  enabled: boolean
  mode: 'token' | 'managed'
  has_token: boolean
  token_masked: string
  has_api_token: boolean
  api_token_masked: string
  catchall_enabled: boolean
  origin_service_url: string
  origin_service_url_http: string
  created_at: string
  updated_at: string
}

export interface UpdateCloudflareTunnelRequest {
  enabled?: boolean
  token?: string
  mode?: 'token' | 'managed'
  // Omit to keep the stored API token; '' clears it (only valid when leaving
  // managed mode).
  api_token?: string
  catchall_enabled?: boolean
}

// Managed mode's remote catch-all state (#267): mirrors the server's decision
// table — applied / not_applied / conflict / invalid_remote / unreachable.
export type CatchallState =
  | 'applied'
  | 'not_applied'
  | 'conflict'
  | 'invalid_remote'
  | 'unreachable'

export interface TunnelStatus {
  state: 'disabled' | 'starting' | 'connected' | 'error'
  connections: number
  catchall_state?: CatchallState
  catchall_detail?: string
}

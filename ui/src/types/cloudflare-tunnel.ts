export interface CloudflareTunnelSettings {
  id: string
  enabled: boolean
  mode: 'token' | 'managed'
  has_token: boolean
  token_masked: string
  created_at: string
  updated_at: string
}

export interface UpdateCloudflareTunnelRequest {
  enabled?: boolean
  token?: string
}

export interface TunnelStatus {
  state: 'disabled' | 'starting' | 'connected' | 'error'
  connections: number
}

import { apiGet, apiPut } from './client'
import type {
  CloudflareTunnelSettings,
  UpdateCloudflareTunnelRequest,
  TunnelStatus,
} from '../types/cloudflare-tunnel'

export async function fetchCloudflareTunnel(): Promise<CloudflareTunnelSettings> {
  return apiGet<CloudflareTunnelSettings>('/api/v1/settings/cloudflare-tunnel')
}

// Token semantics: omit `token` to keep the stored one — the masked value from
// GET must never be sent back.
export async function updateCloudflareTunnel(
  data: UpdateCloudflareTunnelRequest
): Promise<CloudflareTunnelSettings> {
  return apiPut<CloudflareTunnelSettings>('/api/v1/settings/cloudflare-tunnel', data)
}

export async function fetchTunnelStatus(): Promise<TunnelStatus> {
  return apiGet<TunnelStatus>('/api/v1/settings/cloudflare-tunnel/status')
}

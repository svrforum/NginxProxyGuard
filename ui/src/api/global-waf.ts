import { apiGet, apiPut } from './client'

/**
 * Global WAF default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-waf`. Hosts with per-host WAF set to
 * "inherit" (waf_use_global=true) follow this default's enabled/mode/paranoia/
 * threshold; updating it regenerates all inheriting hosts server-side. WAF/
 * ModSecurity changes take effect only after a proxy container restart.
 */
export interface GlobalWAF {
  id?: string
  enabled: boolean
  mode: string
  paranoia_level: number
  anomaly_threshold: number
  created_at?: string
  updated_at?: string
}

export interface UpdateGlobalWAFRequest {
  enabled?: boolean
  mode?: string
  paranoia_level?: number
  anomaly_threshold?: number
}

export async function getGlobalWAF(): Promise<GlobalWAF> {
  return apiGet<GlobalWAF>('/api/v1/settings/global-waf')
}

export async function updateGlobalWAF(req: UpdateGlobalWAFRequest): Promise<GlobalWAF> {
  return apiPut<GlobalWAF>('/api/v1/settings/global-waf', req)
}

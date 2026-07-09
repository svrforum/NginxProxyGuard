import { apiGet, apiPut } from './client'

/**
 * Global GeoIP restriction default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-geo`. Hosts with per-host geo set to
 * "inherit" fall back to this default; updating it regenerates all
 * inheriting hosts server-side.
 */
export interface GlobalGeoRestriction {
  id?: string
  enabled: boolean
  mode: 'whitelist' | 'blacklist'
  countries: string[]
  allowed_ips: string[]
  allow_private_ips: boolean
  allow_search_bots: boolean
  challenge_mode: boolean
  created_at?: string
  updated_at?: string
}

export async function getGlobalGeo(): Promise<GlobalGeoRestriction> {
  return apiGet<GlobalGeoRestriction>('/api/v1/settings/global-geo')
}

export async function updateGlobalGeo(
  req: Partial<GlobalGeoRestriction>,
): Promise<GlobalGeoRestriction> {
  return apiPut<GlobalGeoRestriction>('/api/v1/settings/global-geo', req)
}

import { apiGet, apiPut } from './client'

/**
 * Global cloud-provider blocking default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-cloud-providers`. Hosts with per-host cloud
 * blocking set to "inherit" fall back to this default; updating it regenerates
 * all inheriting hosts server-side. No explicit enabled flag — the default is
 * "active" when blocked_providers is non-empty.
 */
export interface GlobalCloudProviders {
  id?: string
  blocked_providers: string[]
  challenge_mode: boolean
  allow_search_bots: boolean
  created_at?: string
  updated_at?: string
}

export async function getGlobalCloudProviders(): Promise<GlobalCloudProviders> {
  return apiGet<GlobalCloudProviders>('/api/v1/settings/global-cloud-providers')
}

export async function updateGlobalCloudProviders(
  req: Pick<GlobalCloudProviders, 'blocked_providers' | 'challenge_mode' | 'allow_search_bots'>,
): Promise<GlobalCloudProviders> {
  return apiPut<GlobalCloudProviders>('/api/v1/settings/global-cloud-providers', req)
}

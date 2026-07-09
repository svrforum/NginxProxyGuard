import { apiGet, apiPut } from './client'

/**
 * Global bot-filter default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-bot-filter`. Hosts with per-host bot filter
 * set to "inherit" fall back to this default; updating it regenerates all
 * inheriting hosts server-side.
 */
export interface GlobalBotFilter {
  id?: string
  enabled: boolean
  block_bad_bots: boolean
  block_ai_bots: boolean
  allow_search_engines: boolean
  block_suspicious_clients: boolean
  custom_blocked_agents?: string
  custom_allowed_agents?: string
  challenge_suspicious: boolean
  created_at?: string
  updated_at?: string
}

export async function getGlobalBotFilter(): Promise<GlobalBotFilter> {
  return apiGet<GlobalBotFilter>('/api/v1/settings/global-bot-filter')
}

export async function updateGlobalBotFilter(
  req: Partial<GlobalBotFilter>,
): Promise<GlobalBotFilter> {
  return apiPut<GlobalBotFilter>('/api/v1/settings/global-bot-filter', req)
}

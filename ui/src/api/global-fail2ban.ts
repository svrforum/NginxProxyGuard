import { apiGet, apiPut } from './client'
import type { GlobalFail2ban, UpdateGlobalFail2banRequest } from '../types/security'

/**
 * Global fail2ban jail. Mirrors `GET/PUT /api/v1/settings/global-fail2ban`.
 *
 * Unlike the per-host jails, this one counts failures on requests that matched
 * NO configured host — the catch-all traffic a per-host jail structurally
 * cannot see. Bans it creates apply to every host, so the server refuses to
 * enable it while Trusted Proxies are unconfigured.
 */
export async function getGlobalFail2ban(): Promise<GlobalFail2ban> {
  return apiGet<GlobalFail2ban>('/api/v1/settings/global-fail2ban')
}

export async function updateGlobalFail2ban(
  req: UpdateGlobalFail2banRequest,
): Promise<GlobalFail2ban> {
  return apiPut<GlobalFail2ban>('/api/v1/settings/global-fail2ban', req)
}

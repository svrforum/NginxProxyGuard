import { apiGet, apiPut } from './client'
import type { GlobalRateLimit, UpdateGlobalRateLimitRequest } from '../types/security'

/**
 * Global rate-limit default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-rate-limit`. Hosts with per-host rate limit
 * set to "inherit" fall back to this default; updating it regenerates all
 * inheriting hosts server-side. The nginx limit_req zone stays per-host — only
 * the values are inherited.
 */
export async function getGlobalRateLimit(): Promise<GlobalRateLimit> {
  return apiGet<GlobalRateLimit>('/api/v1/settings/global-rate-limit')
}

export async function updateGlobalRateLimit(
  req: UpdateGlobalRateLimitRequest,
): Promise<GlobalRateLimit> {
  return apiPut<GlobalRateLimit>('/api/v1/settings/global-rate-limit', req)
}

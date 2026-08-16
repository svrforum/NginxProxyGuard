import { apiGet, apiPost, apiPut, apiDelete } from './client'

interface BannedIP {
  id: string
  proxy_host_id?: string
  ip_address: string
  reason?: string
  fail_count: number
  banned_at: string
  expires_at?: string
  is_permanent: boolean
  is_auto_banned?: boolean
  created_at: string
}

interface BannedIPListResponse {
  data: BannedIP[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

interface ProxyHostListResponse {
  data: { id: string; domain_names: string[]; enabled: boolean }[]
  total: number
}

interface LogEntry {
  id: string
  log_type: string
  timestamp: string
  host?: string
  client_ip?: string
  request_method?: string
  request_uri?: string
  status_code?: number
  rule_id?: number
  rule_message?: string
  severity?: string
}

interface LogListResponse {
  data: LogEntry[]
  total: number
}

export type { BannedIP, BannedIPListResponse, ProxyHostListResponse, LogEntry, LogListResponse }

const API_BASE = '/api/v1'

export async function fetchBannedIPs(page = 1, perPage = 50, proxyHostId?: string, filter?: string): Promise<BannedIPListResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    per_page: perPage.toString(),
  })
  if (filter) params.set('filter', filter)
  if (proxyHostId) params.set('proxy_host_id', proxyHostId)
  return apiGet<BannedIPListResponse>(`${API_BASE}/banned-ips?${params}`)
}

export async function fetchProxyHostsForBan(): Promise<ProxyHostListResponse> {
  return apiGet<ProxyHostListResponse>(`${API_BASE}/proxy-hosts?page=1&per_page=100`)
}

/** Re-dates an existing ban. Seconds count from NOW, 0 means permanent —
 *  "give this one another day" is the operation, not "recompute from when it
 *  started". (#252) */
export async function updateBanDuration(id: string, banTime: number): Promise<BannedIP> {
  return apiPut<BannedIP>(`${API_BASE}/banned-ips/${id}/duration`, { ban_time: banTime })
}

export async function unbanIP(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/banned-ips/${id}`)
}

export async function unbanIPsBulk(ids: string[]): Promise<{ deleted: number }> {
  return apiPost<{ deleted: number }>(`${API_BASE}/banned-ips/bulk-unban`, { ids })
}

export async function banIP(data: {
  ip_address: string
  reason?: string
  ban_time?: number
  proxy_host_id?: string
}): Promise<BannedIP> {
  return apiPost<BannedIP>(`${API_BASE}/banned-ips`, data)
}

export async function fetchIPLogs(ip: string): Promise<LogListResponse> {
  const params = new URLSearchParams({ client_ip: ip, per_page: '100' })
  return apiGet<LogListResponse>(`${API_BASE}/logs?${params}`)
}

/** Windows the server accepts. Anything else is rejected with 400. (#242) */
export const BANNED_IP_STATS_WINDOWS = [1, 7, 30] as const
export type BannedIPStatsWindow = (typeof BANNED_IP_STATS_WINDOWS)[number]

interface BannedIPTarget {
  name: string
  count: number
}

interface BannedIPStats {
  ip_address: string
  window_days: number
  country?: string
  country_code?: string
  /** Traffic inside the window. Ban history below spans all time. */
  total_requests: number
  blocked_requests: number
  first_seen?: string
  last_seen?: string
  top_hosts: BannedIPTarget[]
  top_uris: BannedIPTarget[]
  ban_count: number
  first_ban_at?: string
  last_ban_at?: string
}

export type { BannedIPStats, BannedIPTarget }

export async function fetchBannedIPStats(ip: string, days: BannedIPStatsWindow): Promise<BannedIPStats> {
  return apiGet<BannedIPStats>(`${API_BASE}/banned-ips/stats/ip/${encodeURIComponent(ip)}?days=${days}`)
}

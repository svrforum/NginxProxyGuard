import { apiGet, apiPost, apiDelete } from './client'

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

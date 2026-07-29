import type {
  ProxyHost,
  CreateProxyHostRequest,
  UpdateProxyHostRequest,
  ProxyHostListResponse,
  ProxyHostTestResult,
} from '../types/proxy-host'
import { apiGet, apiPost, apiPut, apiDelete } from './client'

const API_BASE = '/api/v1'

export async function fetchProxyHosts(
  page = 1,
  perPage = 20,
  search = '',
  sortBy = '',
  sortOrder = ''
): Promise<ProxyHostListResponse> {
  const params = new URLSearchParams({
    page: page.toString(),
    per_page: perPage.toString(),
  })
  if (search.trim()) {
    params.append('search', search.trim())
  }
  if (sortBy) {
    params.append('sort_by', sortBy)
  }
  if (sortOrder) {
    params.append('sort_order', sortOrder)
  }
  return apiGet<ProxyHostListResponse>(
    `${API_BASE}/proxy-hosts?${params.toString()}`
  )
}

export async function fetchProxyHost(id: string): Promise<ProxyHost> {
  return apiGet<ProxyHost>(`${API_BASE}/proxy-hosts/${id}`)
}

export async function createProxyHost(
  data: CreateProxyHostRequest
): Promise<ProxyHost> {
  return apiPost<ProxyHost>(`${API_BASE}/proxy-hosts`, data)
}

// ddnsRemoveProvider answers "also delete the managed DDNS records at the DNS
// provider?" when DDNS is switched off. Omitted means no — the server keeps the
// historical DB-only behavior. (#219)
export async function updateProxyHost(
  id: string,
  data: UpdateProxyHostRequest,
  skipNginx = false,
  ddnsRemoveProvider = false
): Promise<ProxyHost> {
  const params = new URLSearchParams()
  if (skipNginx) params.set('skip_nginx', 'true')
  if (ddnsRemoveProvider) params.set('ddns_remove_provider', 'true')
  const query = params.toString()
  return apiPut<ProxyHost>(`${API_BASE}/proxy-hosts/${id}${query ? `?${query}` : ''}`, data)
}

export async function deleteProxyHost(id: string, ddnsRemoveProvider = false): Promise<void> {
  const query = ddnsRemoveProvider ? '?ddns_remove_provider=true' : ''
  return apiDelete(`${API_BASE}/proxy-hosts/${id}${query}`)
}

export async function testProxyHost(
  id: string
): Promise<{ status: string; host: ProxyHost }> {
  return apiPost<{ status: string; host: ProxyHost }>(
    `${API_BASE}/test/proxy-host/${id}`
  )
}

export async function testNginxConfig(): Promise<{ status: string; message: string }> {
  return apiPost<{ status: string; message: string }>(
    `${API_BASE}/test/nginx-config`
  )
}

export async function syncAllConfigs(): Promise<{ message: string }> {
  return apiPost<{ message: string }>(`${API_BASE}/proxy-hosts/sync`)
}

export async function regenerateHostConfig(id: string): Promise<{ message: string }> {
  return apiPost<{ message: string }>(`${API_BASE}/proxy-hosts/${id}/regenerate`)
}

export async function testProxyHostConfig(
  id: string,
  targetUrl?: string
): Promise<ProxyHostTestResult> {
  const params = targetUrl ? `?url=${encodeURIComponent(targetUrl)}` : ''
  return apiPost<ProxyHostTestResult>(
    `${API_BASE}/proxy-hosts/${id}/test${params}`
  )
}

export interface CloneProxyHostRequest {
  domain_names: string[]
  certificate_id?: string      // If provided, use this existing certificate
  cert_provider?: string       // 'letsencrypt' or 'selfsigned' - create new certificate
  dns_provider_id?: string     // DNS provider ID for Let's Encrypt DNS challenge
  forward_scheme?: string      // http/https or tcp/udp for stream
  forward_host?: string
  forward_port?: number
  forward_container_name?: string
  forward_container_network?: string
  stream_listen_host?: string
  stream_listen_port?: number
  stream_protocol?: string
}

export async function toggleProxyHostFavorite(id: string): Promise<ProxyHost> {
  return apiPut<ProxyHost>(`${API_BASE}/proxy-hosts/${id}/favorite`, {})
}

export async function cloneProxyHost(
  id: string,
  data: CloneProxyHostRequest
): Promise<ProxyHost> {
  return apiPost<ProxyHost>(`${API_BASE}/proxy-hosts/${id}/clone`, data)
}

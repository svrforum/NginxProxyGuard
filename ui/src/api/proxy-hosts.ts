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

export async function updateProxyHost(
  id: string,
  data: UpdateProxyHostRequest
): Promise<ProxyHost> {
  return apiPut<ProxyHost>(`${API_BASE}/proxy-hosts/${id}`, data)
}

export async function deleteProxyHost(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/proxy-hosts/${id}`)
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
  forward_scheme?: string      // http or https
  forward_host?: string
  forward_port?: number
}

export async function cloneProxyHost(
  id: string,
  data: CloneProxyHostRequest
): Promise<ProxyHost> {
  return apiPost<ProxyHost>(`${API_BASE}/proxy-hosts/${id}/clone`, data)
}

import { apiGet, apiPost, apiPut, apiDelete } from './client'
import type { PublicSSOProvider, SSODiscoveryResult, SSOProvider, SSOProviderRequest } from '../types/sso'

const API_BASE = '/api/v1'

/** The login screen's provider buttons. Unauthenticated — the server returns
 *  only id, slug and name. (#227) */
export async function fetchPublicSSOProviders(): Promise<{ data: PublicSSOProvider[] }> {
  return apiGet<{ data: PublicSSOProvider[] }>(`${API_BASE}/auth/sso/providers`)
}

/** Where the browser goes to begin a sign-in. A full page navigation, not fetch:
 *  the flow is a chain of redirects that ends back at this app. */
export function ssoStartURL(slug: string): string {
  return `${API_BASE}/auth/sso/${encodeURIComponent(slug)}/start`
}

export async function listSSOProviders(): Promise<{ data: SSOProvider[] }> {
  return apiGet<{ data: SSOProvider[] }>(`${API_BASE}/sso-providers`)
}

export async function createSSOProvider(data: SSOProviderRequest): Promise<SSOProvider> {
  return apiPost<SSOProvider>(`${API_BASE}/sso-providers`, data)
}

export async function updateSSOProvider(id: string, data: SSOProviderRequest): Promise<SSOProvider> {
  return apiPut<SSOProvider>(`${API_BASE}/sso-providers/${id}`, data)
}

export async function deleteSSOProvider(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/sso-providers/${id}`)
}

/** Probes an issuer before the provider is saved, so a typo surfaces while the
 *  operator is still looking at the form rather than at someone's first login. */
export async function testSSODiscovery(issuer_url: string, scopes: string): Promise<SSODiscoveryResult> {
  return apiPost<SSODiscoveryResult>(`${API_BASE}/sso-providers/test`, { issuer_url, scopes })
}

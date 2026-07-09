import { apiGet, apiPut } from './client'

/**
 * Global security-headers default. Mirrors the backend contract at
 * `GET/PUT /api/v1/settings/global-security-headers`. Hosts with per-host
 * security headers set to "inherit" fall back to this default; updating it
 * regenerates all inheriting hosts server-side.
 */
export interface GlobalSecurityHeaders {
  id?: string
  enabled: boolean
  hsts_enabled: boolean
  hsts_max_age: number
  hsts_include_subdomains: boolean
  hsts_preload: boolean
  x_frame_options: string
  x_content_type_options: boolean
  x_xss_protection: boolean
  referrer_policy: string
  content_security_policy?: string
  permissions_policy?: string
  custom_headers?: Record<string, string>
  created_at?: string
  updated_at?: string
}

export async function getGlobalSecurityHeaders(): Promise<GlobalSecurityHeaders> {
  return apiGet<GlobalSecurityHeaders>('/api/v1/settings/global-security-headers')
}

export async function updateGlobalSecurityHeaders(
  req: Partial<GlobalSecurityHeaders>,
): Promise<GlobalSecurityHeaders> {
  return apiPut<GlobalSecurityHeaders>('/api/v1/settings/global-security-headers', req)
}

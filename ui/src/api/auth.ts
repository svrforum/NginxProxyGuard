const API_BASE = '/api/v1'

export interface User {
  id: string
  username: string
  role: string
  /** RBAC role id and the forced-change flag for admin-created accounts (#222). */
  role_id?: string
  must_change_password?: boolean
  is_initial_setup: boolean
  totp_enabled: boolean
  last_login_at?: string
  last_login_ip?: string
  login_count: number
  created_at: string
  updated_at: string
}

export interface LoginRequest {
  username: string
  password: string
  totp_code?: string
}

export interface LoginResponse {
  token?: string
  user?: User
  is_initial_setup: boolean
  requires_2fa?: boolean
  temp_token?: string
}

export interface Verify2FARequest {
  temp_token: string
  totp_code: string
}

export interface AccountInfo {
  id: string
  username: string
  role: string
  language: string
  font_family: string
  totp_enabled: boolean
  last_login_at?: string
  last_login_ip?: string
  login_count: number
  created_at: string
}

export interface LanguageResponse {
  language: string
}

export interface FontFamilyResponse {
  font_family: string
}

export interface Setup2FAResponse {
  secret: string
  qr_code_url: string
  backup_codes: string[]
}

export interface Enable2FARequest {
  totp_code: string
}

export interface Disable2FARequest {
  password: string
  totp_code: string
}

export interface AuthStatus {
  authenticated: boolean
  is_initial_setup: boolean
  user?: User
}

export interface ChangeCredentialsRequest {
  current_password: string
  new_username: string
  new_password: string
  new_password_confirm: string
  /** Optional. Without it the account keeps <username>@localhost, which no
   *  identity provider can ever match when linking an SSO sign-in. (#240) */
  new_email?: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
  new_password_confirm: string
}

export interface ChangeUsernameRequest {
  current_password: string
  new_username: string
}

export interface ChangeUsernameResponse {
  message: string
  username: string
}

// Token storage
const TOKEN_KEY = 'npg_token'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

// Auth header helper
export function getAuthHeaders(): HeadersInit {
  const token = getToken()
  if (token) {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    }
  }
  return {
    'Content-Type': 'application/json'
  }
}

// Helper function to safely parse JSON response
async function safeJsonParse(res: Response): Promise<{ data?: unknown; error?: string }> {
  const contentType = res.headers.get('content-type')
  if (!contentType || !contentType.includes('application/json')) {
    // Non-JSON response (e.g., nginx HTML error page when API is down)
    if (res.status === 502 || res.status === 503 || res.status === 504) {
      return { error: 'Server is not available. Please try again later.' }
    }
    return { error: `Unexpected response (${res.status})` }
  }
  try {
    const data = await res.json()
    return { data }
  } catch {
    return { error: 'Invalid response from server' }
  }
}

// API functions
export async function login(request: LoginRequest): Promise<LoginResponse> {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const { data, error } = await safeJsonParse(res)
    if (error) {
      throw new Error(error)
    }
    const errorData = data as { error?: string }
    throw new Error(errorData?.error || 'Login failed')
  }

  const { data, error } = await safeJsonParse(res)
  if (error) {
    throw new Error(error)
  }
  const loginData = data as LoginResponse
  // Only set token if login completed (not requiring 2FA)
  if (loginData.token) {
    setToken(loginData.token)
  }
  return loginData
}

export async function logout(): Promise<void> {
  const token = getToken()
  if (token) {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: getAuthHeaders()
      })
    } catch {
      // Ignore errors on logout
    }
  }
  clearToken()
}

export async function getAuthStatus(): Promise<AuthStatus> {
  const res = await fetch(`${API_BASE}/auth/status`, {
    headers: getAuthHeaders()
  })

  if (!res.ok) {
    const { error } = await safeJsonParse(res)
    throw new Error(error || 'Failed to get auth status')
  }

  const { data, error } = await safeJsonParse(res)
  if (error) {
    throw new Error(error)
  }
  return data as AuthStatus
}

export async function getCurrentUser(): Promise<User> {
  const res = await fetch(`${API_BASE}/auth/me`, {
    headers: getAuthHeaders()
  })

  if (!res.ok) {
    if (res.status === 401) {
      clearToken()
      throw new Error('Session expired')
    }
    throw new Error('Failed to get user')
  }

  return res.json()
}

export async function changeCredentials(request: ChangeCredentialsRequest): Promise<void> {
  const res = await fetch(`${API_BASE}/auth/change-credentials`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to change credentials')
  }

  // Clear token after credentials change - user needs to re-login
  clearToken()
}

export async function changePassword(request: ChangePasswordRequest): Promise<void> {
  const res = await fetch(`${API_BASE}/auth/change-password`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to change password')
  }
}

export async function changeUsername(request: ChangeUsernameRequest): Promise<ChangeUsernameResponse> {
  const res = await fetch(`${API_BASE}/auth/change-username`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to change username')
  }

  return res.json()
}

export async function verify2FA(request: Verify2FARequest): Promise<LoginResponse> {
  const res = await fetch(`${API_BASE}/auth/verify-2fa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const { data, error } = await safeJsonParse(res)
    if (error) {
      throw new Error(error)
    }
    const errorData = data as { error?: string }
    throw new Error(errorData?.error || '2FA verification failed')
  }

  const { data, error } = await safeJsonParse(res)
  if (error) {
    throw new Error(error)
  }
  const loginData = data as LoginResponse
  if (loginData.token) {
    setToken(loginData.token)
  }
  return loginData
}

export async function getAccountInfo(): Promise<AccountInfo> {
  const res = await fetch(`${API_BASE}/auth/account`, {
    headers: getAuthHeaders()
  })

  if (!res.ok) {
    if (res.status === 401) {
      clearToken()
      throw new Error('Session expired')
    }
    throw new Error('Failed to get account info')
  }

  return res.json()
}

export async function setup2FA(): Promise<Setup2FAResponse> {
  const res = await fetch(`${API_BASE}/auth/2fa/setup`, {
    method: 'POST',
    headers: getAuthHeaders()
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to setup 2FA')
  }

  return res.json()
}

export async function enable2FA(request: Enable2FARequest): Promise<void> {
  const res = await fetch(`${API_BASE}/auth/2fa/enable`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to enable 2FA')
  }
}

export async function disable2FA(request: Disable2FARequest): Promise<void> {
  const res = await fetch(`${API_BASE}/auth/2fa/disable`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request)
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to disable 2FA')
  }
}

// Language settings
export async function getLanguage(): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/language`, {
    headers: getAuthHeaders()
  })

  if (!res.ok) {
    throw new Error('Failed to get language')
  }

  const data: LanguageResponse = await res.json()
  return data.language
}

export async function setLanguage(language: string): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/language`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify({ language })
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to set language')
  }

  const data: LanguageResponse = await res.json()
  return data.language
}

// Font family settings
export async function getFontFamily(): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/font`, {
    headers: getAuthHeaders()
  })

  if (!res.ok) {
    throw new Error('Failed to get font family')
  }

  const data: FontFamilyResponse = await res.json()
  return data.font_family
}

export async function setFontFamily(fontFamily: string): Promise<string> {
  const res = await fetch(`${API_BASE}/auth/font`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify({ font_family: fontFamily })
  })

  if (!res.ok) {
    const error = await res.json()
    throw new Error(error.error || 'Failed to set font family')
  }

  const data: FontFamilyResponse = await res.json()
  return data.font_family
}

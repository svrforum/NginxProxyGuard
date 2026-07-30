import { getToken, clearToken } from './auth'

export function getAuthHeaders(): HeadersInit {
  const token = getToken()
  const headers: HeadersInit = {
    'Content-Type': 'application/json'
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  return headers
}

// Custom error class to include details from server
export class ApiError extends Error {
  details?: string
  status: number

  constructor(message: string, status: number, details?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.details = details
  }
}

export async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    if (response.status === 401) {
      clearToken()
      window.location.reload()
    }
    // Gateway errors return HTML (nginx error page), not JSON
    if (response.status === 502 || response.status === 503 || response.status === 504) {
      throw new ApiError(
        response.status === 504
          ? 'Request timed out - the server is taking too long to respond'
          : 'Server temporarily unavailable - please try again',
        response.status
      )
    }
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
    const message = errorData.error || `HTTP ${response.status}`
    const details = errorData.details
    // 403 now means "your role does not allow this" far more often than anything
    // else, and the server's wording is aimed at API clients ("insufficient
    // permissions", "required: proxy:write"). Say it in terms an operator can act
    // on, keeping the raw requirement as details. (#222)
    if (response.status === 403) {
      const code = (errorData as { code?: string }).code
      if (code === 'must_change_password') {
        throw new ApiError('You must change your password before using the application.', 403, details)
      }
      if (code === 'initial_setup_required') {
        throw new ApiError(message, 403, details)
      }
      const required = (errorData as { required?: string }).required
      throw new ApiError(
        'Your role does not allow this action. Ask an administrator to grant it.',
        403,
        required ? `Required permission: ${required}` : details
      )
    }
    throw new ApiError(message, response.status, details)
  }
  // Handle empty responses (204 No Content)
  if (response.status === 204) {
    return {} as T
  }
  return response.json().catch(() => ({} as T))
}

export async function apiGet<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    headers: getAuthHeaders()
  })
  return handleResponse<T>(response)
}

export async function apiPost<T>(url: string, data?: unknown): Promise<T> {
  const response = await fetch(url, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: data ? JSON.stringify(data) : undefined
  })
  return handleResponse<T>(response)
}

export async function apiPut<T>(url: string, data: unknown): Promise<T> {
  const response = await fetch(url, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data)
  })
  return handleResponse<T>(response)
}

export async function apiDelete(url: string): Promise<void> {
  const response = await fetch(url, {
    method: 'DELETE',
    headers: getAuthHeaders()
  })
  if (!response.ok) {
    if (response.status === 401) {
      clearToken()
      window.location.reload()
    }
    if (response.status === 502 || response.status === 503 || response.status === 504) {
      throw new ApiError(
        response.status === 504
          ? 'Request timed out - the server is taking too long to respond'
          : 'Server temporarily unavailable - please try again',
        response.status
      )
    }
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new ApiError(error.error || `HTTP ${response.status}`, response.status, error.details)
  }
}

// Convenience wrapper for api calls
export const api = {
  get: apiGet,
  post: apiPost,
  put: apiPut,
  delete: apiDelete,
}

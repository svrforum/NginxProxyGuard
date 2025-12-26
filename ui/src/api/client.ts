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
    const errorData = await response.json().catch(() => ({ error: 'Unknown error' }))
    const message = errorData.error || `HTTP ${response.status}`
    const details = errorData.details
    throw new ApiError(message, response.status, details)
  }
  return response.json()
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
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP ${response.status}`)
  }
}

// Convenience wrapper for api calls
export const api = {
  get: apiGet,
  post: apiPost,
  put: apiPut,
  delete: apiDelete,
}

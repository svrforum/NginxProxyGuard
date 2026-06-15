import { AuthProvider, CreateAuthProviderRequest } from '../types/auth-provider';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

export async function getAuthProviders(page = 1, perPage = 100): Promise<{ data: AuthProvider[]; total: number }> {
  const res = await fetch(`${API_BASE}/auth-providers?page=${page}&per_page=${perPage}`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch auth providers');
  return res.json();
}

export async function getAuthProvider(id: string): Promise<AuthProvider> {
  const res = await fetch(`${API_BASE}/auth-providers/${id}`, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to fetch auth provider');
  return res.json();
}

export async function createAuthProvider(data: CreateAuthProviderRequest): Promise<AuthProvider> {
  const res = await fetch(`${API_BASE}/auth-providers`, { method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(data) });
  if (!res.ok) { const e = await res.json(); throw new Error(e.error || 'Failed to create auth provider'); }
  return res.json();
}

export async function updateAuthProvider(id: string, data: Partial<CreateAuthProviderRequest>): Promise<AuthProvider> {
  const res = await fetch(`${API_BASE}/auth-providers/${id}`, { method: 'PUT', headers: getAuthHeaders(), body: JSON.stringify(data) });
  if (!res.ok) { const e = await res.json(); throw new Error(e.error || 'Failed to update auth provider'); }
  return res.json();
}

export async function deleteAuthProvider(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/auth-providers/${id}`, { method: 'DELETE', headers: getAuthHeaders() });
  if (!res.ok) throw new Error('Failed to delete auth provider');
}

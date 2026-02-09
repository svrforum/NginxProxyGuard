import type {
  DNSProvider,
  CreateDNSProviderRequest,
  DNSProviderListResponse,
} from '../types/certificate';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function listDNSProviders(page = 1, perPage = 20): Promise<DNSProviderListResponse> {
  const response = await fetch(`${API_BASE}/dns-providers?page=${page}&per_page=${perPage}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<DNSProviderListResponse>(response);
}

export async function getDNSProvider(id: string): Promise<DNSProvider> {
  const response = await fetch(`${API_BASE}/dns-providers/${id}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<DNSProvider>(response);
}

export async function getDefaultDNSProvider(): Promise<DNSProvider | null> {
  try {
    const response = await fetch(`${API_BASE}/dns-providers/default`, {
      headers: getAuthHeaders(),
    });
    if (!response.ok) return null;
    return response.json();
  } catch {
    return null;
  }
}

export async function createDNSProvider(data: CreateDNSProviderRequest): Promise<DNSProvider> {
  const response = await fetch(`${API_BASE}/dns-providers`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse<DNSProvider>(response);
}

export async function updateDNSProvider(
  id: string,
  data: Partial<CreateDNSProviderRequest>
): Promise<DNSProvider> {
  const response = await fetch(`${API_BASE}/dns-providers/${id}`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse<DNSProvider>(response);
}

export async function deleteDNSProvider(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/dns-providers/${id}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }
}

export async function testDNSProvider(data: CreateDNSProviderRequest): Promise<{ success: boolean; error?: string }> {
  try {
    const response = await fetch(`${API_BASE}/dns-providers/test`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    const result = await response.json();
    if (response.ok) {
      return { success: true };
    }
    return { success: false, error: result.error || 'Connection test failed' };
  } catch {
    return { success: false, error: 'Failed to connect to server' };
  }
}

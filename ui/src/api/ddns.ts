import type {
  DDNSRecord,
  CreateDDNSRecordRequest,
  UpdateDDNSRecordRequest,
  DDNSRecordListResponse,
} from '../types/ddns';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function listDDNSRecords(page = 1, perPage = 20): Promise<DDNSRecordListResponse> {
  const response = await fetch(`${API_BASE}/ddns-records?page=${page}&per_page=${perPage}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<DDNSRecordListResponse>(response);
}

export async function getDDNSRecord(id: string): Promise<DDNSRecord> {
  const response = await fetch(`${API_BASE}/ddns-records/${id}`, {
    headers: getAuthHeaders(),
  });
  return handleResponse<DDNSRecord>(response);
}

export async function createDDNSRecord(data: CreateDDNSRecordRequest): Promise<DDNSRecord> {
  const response = await fetch(`${API_BASE}/ddns-records`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse<DDNSRecord>(response);
}

export async function updateDDNSRecord(
  id: string,
  data: UpdateDDNSRecordRequest
): Promise<DDNSRecord> {
  const response = await fetch(`${API_BASE}/ddns-records/${id}`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  return handleResponse<DDNSRecord>(response);
}

export async function deleteDDNSRecord(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/ddns-records/${id}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP ${response.status}`);
  }
}

export async function syncDDNSRecord(id: string): Promise<{ success: boolean; message: string }> {
  const response = await fetch(`${API_BASE}/ddns-records/${id}/sync`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  return handleResponse<{ success: boolean; message: string }>(response);
}

export async function syncAllDDNSRecords(): Promise<{ success: boolean; message: string }> {
  const response = await fetch(`${API_BASE}/ddns-records/sync`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  return handleResponse<{ success: boolean; message: string }>(response);
}

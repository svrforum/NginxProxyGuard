import type {
  GlobalSettings,
  UpdateSettingsRequest,
  DashboardSummary,
  SystemHealth,
  Backup,
  BackupListResponse,
  BackupStats,
  CreateBackupRequest,
  DockerStatsSummary,
  SystemSettings,
  UpdateSystemSettingsRequest,
  GeoIPStatus,
  SystemLogConfig,
  LogFilesResponse,
  LogFileViewResponse,
} from '../types/settings';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

// Global Settings API
export async function getGlobalSettings(): Promise<GlobalSettings> {
  const res = await fetch(`${API_BASE}/settings`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch settings');
  return res.json();
}

export async function updateGlobalSettings(data: UpdateSettingsRequest): Promise<GlobalSettings> {
  const res = await fetch(`${API_BASE}/settings`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Failed to update settings' }));
    throw new Error(error.error || 'Failed to update settings');
  }
  return res.json();
}

export async function resetGlobalSettings(): Promise<GlobalSettings> {
  const res = await fetch(`${API_BASE}/settings/reset`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to reset settings');
  return res.json();
}

export async function getSettingsPresets(): Promise<Record<string, Partial<GlobalSettings>>> {
  const res = await fetch(`${API_BASE}/settings/presets`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch presets');
  return res.json();
}

export async function applySettingsPreset(preset: string): Promise<GlobalSettings> {
  const res = await fetch(`${API_BASE}/settings/preset/${preset}`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to apply preset');
  return res.json();
}

// Dashboard API
export async function getDashboard(): Promise<DashboardSummary> {
  const res = await fetch(`${API_BASE}/dashboard`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch dashboard');
  return res.json();
}

export async function getSystemHealth(): Promise<SystemHealth> {
  const res = await fetch(`${API_BASE}/dashboard/health`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch system health');
  return res.json();
}

// System Health History for charts
export interface SystemHealthHistoryResponse {
  data: SystemHealth[];
  total: number;
  since: string;
  limit: number;
}

export async function getSystemHealthHistory(hours = 1, limit = 100): Promise<SystemHealthHistoryResponse> {
  const res = await fetch(`${API_BASE}/dashboard/health/history?hours=${hours}&limit=${limit}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch system health history');
  return res.json();
}

export async function getContainerStats(): Promise<DockerStatsSummary> {
  const res = await fetch(`${API_BASE}/dashboard/containers`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch container stats');
  return res.json();
}

// GeoIP Stats for Globe Visualization
export interface GeoIPStat {
  country_code: string;
  country: string;
  count: number;
  percentage: number;
  lat: number;
  lng: number;
}

export interface GeoIPStatsResponse {
  data: GeoIPStat[];
  total_count: number;
}

export async function getGeoIPStats(hours = 24): Promise<GeoIPStatsResponse> {
  const res = await fetch(`${API_BASE}/dashboard/geoip-stats?hours=${hours}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch GeoIP stats');
  return res.json();
}

// Backup API
export async function listBackups(page = 1, perPage = 20): Promise<BackupListResponse> {
  const res = await fetch(`${API_BASE}/backups?page=${page}&per_page=${perPage}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch backups');
  return res.json();
}

export async function getBackup(id: string): Promise<Backup> {
  const res = await fetch(`${API_BASE}/backups/${id}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch backup');
  return res.json();
}

export async function createBackup(data: CreateBackupRequest): Promise<Backup> {
  const res = await fetch(`${API_BASE}/backups`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create backup');
  return res.json();
}

export async function deleteBackup(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/backups/${id}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to delete backup');
}

export async function restoreBackup(id: string): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/backups/${id}/restore`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to restore backup');
  return res.json();
}

export async function getBackupStats(): Promise<BackupStats> {
  const res = await fetch(`${API_BASE}/backups/stats`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch backup stats');
  return res.json();
}

export function getBackupDownloadUrl(id: string): string {
  return `${API_BASE}/backups/${id}/download`;
}

export async function downloadBackup(id: string, filename: string): Promise<void> {
  const res = await fetch(`${API_BASE}/backups/${id}/download`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to download backup');

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

export async function uploadAndRestoreBackup(file: File): Promise<{ status: string; message: string; backup: Backup }> {
  const formData = new FormData();
  formData.append('backup', file);

  const token = localStorage.getItem('npg_token');
  const res = await fetch(`${API_BASE}/backups/upload-restore`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: formData,
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Failed to upload and restore backup' }));
    throw new Error(error.details || error.error || 'Failed to upload and restore backup');
  }
  return res.json();
}

// Self Check Result Type
export interface SelfCheckResult {
  status: string;
  checks: Record<string, {
    status: string;
    message?: string;
    latency?: number;
  }>;
  timestamp?: string;
}

// Test Endpoints
export async function runSelfCheck(): Promise<SelfCheckResult> {
  const res = await fetch(`${API_BASE}/test/system/self-check`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to run self-check');
  return res.json();
}

// Update check (#190) — display + guidance only; NPG does not update itself.
export interface UpdateInfo {
  current_version: string;
  latest_version: string;
  update_available: boolean;
  release_url: string;
  published_at: string;
  checked_at: string;
  check_failed: boolean;
}

export async function checkUpdate(force = false): Promise<UpdateInfo> {
  const res = await fetch(`${API_BASE}/system-settings/update/check${force ? '?force=true' : ''}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to check for updates');
  return res.json();
}

// System Settings API (GeoIP, ACME, etc.)
export async function getSystemSettings(): Promise<SystemSettings> {
  const res = await fetch(`${API_BASE}/system-settings`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch system settings');
  return res.json();
}

export async function updateSystemSettings(data: UpdateSystemSettingsRequest): Promise<SystemSettings> {
  const res = await fetch(`${API_BASE}/system-settings`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update system settings');
  return res.json();
}

export async function getGeoIPStatus(): Promise<GeoIPStatus> {
  const res = await fetch(`${API_BASE}/system-settings/geoip/status`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch GeoIP status');
  return res.json();
}

export async function triggerGeoIPUpdate(force = false): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/system-settings/geoip/update`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ force }),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Failed to trigger GeoIP update' }));
    throw new Error(error.error || 'Failed to trigger GeoIP update');
  }
  return res.json();
}

export interface GeoIPUpdateHistory {
  id: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  trigger_type: 'manual' | 'auto';
  started_at: string;
  completed_at?: string;
  duration_ms?: number;
  database_version?: string;
  country_db_size?: number;
  asn_db_size?: number;
  error_message?: string;
  created_at: string;
}

export interface GeoIPHistoryResponse {
  data: GeoIPUpdateHistory[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export async function getGeoIPHistory(page = 1, perPage = 10): Promise<GeoIPHistoryResponse> {
  const res = await fetch(`${API_BASE}/system-settings/geoip/history?page=${page}&per_page=${perPage}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch GeoIP update history');
  return res.json();
}

export async function testACME(): Promise<{ acme_enabled: boolean; acme_email: string; acme_staging: boolean; status: string; message: string }> {
  const res = await fetch(`${API_BASE}/system-settings/acme/test`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to test ACME');
  return res.json();
}

// Log Files Management API

export async function getLogFiles(): Promise<LogFilesResponse> {
  const res = await fetch(`${API_BASE}/system-settings/log-files`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch log files');
  return res.json();
}

export async function viewLogFile(filename: string, lines = 100): Promise<LogFileViewResponse> {
  const res = await fetch(`${API_BASE}/system-settings/log-files/${encodeURIComponent(filename)}/view?lines=${lines}`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to view log file');
  return res.json();
}

export async function downloadLogFile(filename: string): Promise<void> {
  const res = await fetch(`${API_BASE}/system-settings/log-files/${encodeURIComponent(filename)}/download`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to download log file');

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

export async function deleteLogFile(filename: string): Promise<void> {
  const res = await fetch(`${API_BASE}/system-settings/log-files/${encodeURIComponent(filename)}`, {
    method: 'DELETE',
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Failed to delete log file' }));
    throw new Error(error.error || 'Failed to delete log file');
  }
}

export async function triggerLogRotation(): Promise<{ status: string; message: string }> {
  const res = await fetch(`${API_BASE}/system-settings/log-files/rotate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ error: 'Failed to trigger log rotation' }));
    throw new Error(error.error || 'Failed to trigger log rotation');
  }
  return res.json();
}

export async function getSystemLogConfig(): Promise<SystemLogConfig> {
  const res = await fetch(`${API_BASE}/system-settings/logs`, {
    headers: getAuthHeaders(),
  });
  if (!res.ok) throw new Error('Failed to fetch system log config');
  return res.json();
}

export async function updateSystemLogConfig(data: SystemLogConfig): Promise<SystemLogConfig> {
  const res = await fetch(`${API_BASE}/system-settings/logs`, {
    method: 'PUT',
    headers: getAuthHeaders(),
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update system log config');
  return res.json();
}

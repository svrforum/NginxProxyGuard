// Shared pieces of the raw log files page (Logs -> Raw log files).

/**
 * Ranges the server accepts for the raw log settings
 * (api/internal/model/system_settings_rawlog.go). Kept identical so the form
 * never offers a value the server refuses.
 */
export const RAW_LOG_LIMITS = {
  raw_log_retention_days: { min: 1, max: 3650 },
  raw_log_max_size_mb: { min: 10, max: 10240 },
} as const;

export type RawLogLimitedField = keyof typeof RAW_LOG_LIMITS;

/** True when an edited value is a whole number inside the server's range. */
export function inRawLogRange(field: RawLogLimitedField, value: unknown): boolean {
  const { min, max } = RAW_LOG_LIMITS[field];
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

export function formatFileSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export type RawLogMessage = { type: 'success' | 'error' | 'info'; text: string };

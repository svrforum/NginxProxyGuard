// Shared pieces of the raw log files page (Logs -> Raw log files).

import type { RawLogArchiveStatus } from '../../types/rawLogFiles';

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

/** Archive retention range (raw_log_archive_retention_days). */
export const RAW_LOG_ARCHIVE_RETENTION = { min: 1, max: 3650 } as const;

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

/** Files per page in the raw log list (long retentions create tens of thousands). */
export const RAW_LOG_PAGE_SIZE = 100;

export type RawLogMessage = { type: 'success' | 'error' | 'info'; text: string };

/**
 * The archive status the archive card shows: the answer to Check or "Use this
 * directory" until the page's list brings a status measured at or after it
 * (both carry checked_at from the server's clock). The list's is the live one:
 * a stall, a full or unmounted archive, the last move and the files waiting to
 * move show only there.
 */
export function shownArchiveStatus(
  probe: RawLogArchiveStatus | null,
  live: RawLogArchiveStatus | undefined,
): RawLogArchiveStatus | undefined {
  if (!probe) return live;
  if (!live?.checked_at) return probe;
  if (!probe.checked_at) return live;
  return Date.parse(live.checked_at) >= Date.parse(probe.checked_at) ? live : probe;
}

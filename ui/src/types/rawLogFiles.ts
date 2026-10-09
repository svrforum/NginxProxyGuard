// Raw nginx log files (Logs -> Raw log files): types that GET
// /system-settings/log-files adds beside the file list.

/**
 * Disk use of the raw logs, measured from the files themselves. The page
 * projects it with the retention being edited:
 * avg_daily_bytes × retention + live_bytes + pending_bytes.
 */
export interface RawLogUsage {
  /** none: no rotated file has finished yet, so there is nothing to average. */
  basis: 'last_7_days' | 'history' | 'none';
  basis_days: number;
  avg_daily_bytes: number;
  /** access_raw.log and error_raw.log now. */
  live_bytes: number;
  /** Rotated files not finished yet (with compression, the newest one). */
  pending_bytes: number;
  local_bytes: number;
  local_files: number;
  archive_bytes: number;
  archive_files: number;
  retention_days: number;
  compressed: boolean;
  archive_enabled: boolean;
  archive_retention_days?: number;
  /** Server-side projection with the saved settings. */
  projected_local_bytes: number;
  projected_archive_bytes: number;
  /** The log directory's filesystem; absent when it could not be measured. */
  local_fs_type?: string;
  local_total_bytes?: number;
  local_free_bytes?: number;
  archive_total_bytes?: number;
  archive_free_bytes?: number;
}

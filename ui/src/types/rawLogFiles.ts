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

/** Archive directory states (see the API's RawLogArchiveStatus). */
export type RawLogArchiveState =
  | 'disabled'
  | 'not_mounted'
  | 'not_initialized'
  | 'foreign'
  | 'unwritable'
  | 'insufficient_space'
  | 'stalled'
  | 'ready';

/**
 * The raw log archive directory: another disk or a NAS share bound into the
 * API container. Nothing is written to it before "Use this directory"; when
 * it is missing, not ours, unwritable, full or hung, rotated files stay local.
 */
export interface RawLogArchiveStatus {
  enabled: boolean;
  /** The directory inside the API container (NPG_RAW_LOG_ARCHIVE_DIR). */
  dir: string;
  status: RawLogArchiveState;
  /** The directory exists in the API container (the marker tells whether the share is really there). */
  mounted: boolean;
  marker?: 'missing' | 'ours' | 'foreign' | 'unreadable';
  /** Write test result (check and init only). */
  writable?: boolean;
  fs_type?: string;
  total_bytes?: number;
  free_bytes?: number;
  detail?: string;
  retention_days: number;
  checked_at?: string;
  last_move_at?: string;
  last_moved: number;
  last_pruned: number;
  last_error?: string;
  /** Settled local files waiting to move. */
  pending_files: number;
  stalled_since?: string;
  running: boolean;
}

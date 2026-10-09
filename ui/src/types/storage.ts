// DiskGuard's view of the disks NPG writes to (D1-D4), as GET /dashboard
// returns it in `storage`. Never cached server-side; absent until the first
// measurement (about a minute after the API starts) and when the guard is
// disabled.

export type StorageLevel = 'ok' | 'low' | 'critical';

/** What a filesystem holds for NPG, most important first. */
export type StorageRole = 'db' | 'nginx_logs' | 'archive' | 'backups' | 'docker';

export interface StorageThresholds {
  warn_percent: number;
  critical_percent: number;
  recover_percent: number;
}

export interface FilesystemUsage {
  /** Most important role on this filesystem; also the alert subject. */
  key: string;
  roles: StorageRole[];
  /** "npg-db:/var/lib/postgresql/data" for the database, else a path in the API container. */
  path: string;
  source: 'statfs' | 'docker_exec' | 'docker_exec_df';
  total_bytes: number;
  used_bytes: number;
  /** Free to non-root writers, as df's "Available". */
  avail_bytes: number;
  /** used / (used + avail), as df prints it. */
  used_percent: number;
  level: StorageLevel;
  /** Net change over the last 24 hours; absent until there is a day of history. */
  growth_per_day_bytes?: number;
  days_to_full?: number;
  measured_at: string;
}

/** A filesystem that stopped answering (a hung network mount). */
export interface StalledFilesystem {
  role: StorageRole;
  path: string;
  since: string;
}

export interface DatabaseDiskInfo {
  measured: boolean;
  container?: string;
  data_dir?: string;
  reason?: 'db_container_not_found' | 'db_external' | 'db_exec_failed' | 'docker_unavailable';
}

/** Early compression of closed log chunks while the database disk is critical. */
export interface EmergencyCompressionStatus {
  mode: 'on' | 'off' | 'dryrun';
  state: 'idle' | 'running' | 'done' | 'blocked';
  reason?: string;
  chunks_done: number;
  chunks_total: number;
  freed_bytes: number;
  started_at?: string;
  finished_at?: string;
}

export interface StorageStatus {
  /** The worst filesystem's level. */
  level: StorageLevel;
  thresholds: StorageThresholds;
  /** Fullest first. */
  filesystems: FilesystemUsage[];
  stalled?: StalledFilesystem[];
  database: DatabaseDiskInfo;
  emergency?: EmergencyCompressionStatus;
  measured_at: string;
}

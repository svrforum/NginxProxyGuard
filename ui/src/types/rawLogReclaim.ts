// The raw log reclaim (Settings > Maintenance): an opt-in job that removes the
// raw_log copies of access and error lines kept inside old compressed log
// history, one day at a time. GET /system-settings/log-storage/raw-reclaim.

export type RawLogReclaimJobStatus = 'idle' | 'running' | 'paused' | 'done' | 'failed';

export type RawLogReclaimStep =
  | 'waiting_disk' // the database disk is critical: emergency compression goes first
  | 'waiting_lock' // another job is rewriting chunks
  | 'nulling' // removing the raw_log copies
  | 'waiting' // for transactions older than the removal to end
  | 'vacuum' // VACUUM FULL: queries on that day wait meanwhile
  | 'pausing'; // the pause between days

export type RawLogReclaimUnsupportedReason =
  | 'timescaledb_missing'
  | 'catalog_changed'
  | 'not_hypertable'
  | 'compression_disabled'
  | 'segmentby_without_log_type';

export interface RawLogReclaimChunkProgress {
  range_start: string;
  range_end: string;
  step: RawLogReclaimStep;
  since: string;
}

export interface LogRawReclaimStatus {
  status: RawLogReclaimJobStatus;
  supported: boolean;
  unsupported_reason?: RawLogReclaimUnsupportedReason;
  requested_at?: string;
  requested_by?: string;
  started_at?: string;
  finished_at?: string;
  max_chunks?: number;
  /** Set while a run interrupted by an API restart waits to resume. */
  resume_at?: string;

  chunks_total: number;
  chunks_done: number;
  chunks_pending: number;
  chunks_skipped: number;
  chunks_failed: number;

  bytes_before: number;
  bytes_after: number;
  reclaimed_bytes: number;
  remaining_raw_bytes: number;

  /** From ?estimate=1 (cached up to 10 minutes on the server). */
  estimated_reclaimable_bytes?: number;
  modsec_raw_bytes?: number;
  estimate_chunks?: number;
  estimated_at?: string;

  current_chunk?: RawLogReclaimChunkProgress;

  /** Absent when the database disk cannot be measured. */
  free_bytes?: number;
  required_free_bytes: number;
  last_error?: string;
}

export interface StartRawLogReclaimRequest {
  max_chunks?: number;
}

/** `code` of a 409/412 answer from POST .../start. */
export type RawLogReclaimStartErrorCode =
  | 'already_running'
  | 'unsupported'
  | 'free_space_unknown'
  | 'insufficient_space';

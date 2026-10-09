import { apiGet, apiPost } from './client';
import type { LogRawReclaimStatus, StartRawLogReclaimRequest } from '../types/rawLogReclaim';

const BASE = '/api/v1/system-settings/log-storage/raw-reclaim';

/**
 * estimate=true also measures what is left to reclaim and the database disk's
 * free space (cached server-side for up to 10 minutes). Leave it off while the
 * job runs and the card polls.
 */
export async function getRawLogReclaimStatus(estimate = false): Promise<LogRawReclaimStatus> {
  return apiGet<LogRawReclaimStatus>(estimate ? `${BASE}?estimate=1` : BASE);
}

/** 202 with the status; 409 already running; 412 with a `code` (see RawLogReclaimStartErrorCode). */
export async function startRawLogReclaim(req: StartRawLogReclaimRequest = {}): Promise<LogRawReclaimStatus> {
  return apiPost<LogRawReclaimStatus>(`${BASE}/start`, req);
}

export async function stopRawLogReclaim(): Promise<LogRawReclaimStatus> {
  return apiPost<LogRawReclaimStatus>(`${BASE}/stop`);
}

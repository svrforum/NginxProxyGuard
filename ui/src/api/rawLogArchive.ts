// Raw log archive directory (Logs -> Raw log files -> Archive).
import type { RawLogArchiveStatus } from '../types/rawLogFiles';
import { getAuthHeaders } from './auth';

const API_BASE = '/api/v1';

/** A failed archive request: the server's sentence, plus the archive status it sent. */
export class RawLogArchiveError extends Error {
  archive?: RawLogArchiveStatus;
  constructor(message: string, archive?: RawLogArchiveStatus) {
    super(message);
    this.name = 'RawLogArchiveError';
    this.archive = archive;
  }
}

async function archivePost(path: string, fallback: string): Promise<RawLogArchiveStatus> {
  const res = await fetch(`${API_BASE}/system-settings/log-files/archive/${path}`, {
    method: 'POST',
    headers: getAuthHeaders(),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new RawLogArchiveError(body.error || fallback, body.archive);
  return body as RawLogArchiveStatus;
}

/** Probe the directory (mounted, filesystem, marker, write test). Writes no marker. */
export const checkRawLogArchive = () => archivePost('check', 'Failed to check the archive directory');

/** Claim the directory for this install: write test, then the marker file. */
export const initRawLogArchive = () => archivePost('init', 'Failed to initialise the archive directory');

/** Ask for a move pass now; answers at once with the current status. */
export const runRawLogArchive = () => archivePost('run', 'Failed to start an archive pass');

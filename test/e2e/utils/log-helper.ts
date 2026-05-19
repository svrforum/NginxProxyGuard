// Helpers for the block_reason end-to-end regression spec.
//
// The block_reason pipeline spans nginx (template renders `set $block_reason_var ...`)
// → access log → log_collector parser → DB → /api/v1/logs response. This file gives
// the spec two primitives:
//
//   triggerRequest()  — fire a curl request against the e2e proxy (port 18080),
//                       spoofing Host/XFF/UA/method so we can exercise individual
//                       security paths in isolation.
//   pollForLog()      — repeatedly poll /api/v1/logs until a row matching the
//                       supplied predicate appears, or fail with a diagnostic.
//
// We shell out to curl via execFileSync (NOT exec) — the harness security hook
// rejects exec, and execFileSync also avoids shell expansion on the spoofed
// values (Host headers and X-Forwarded-For are user-controlled in this context).

import { execFileSync } from 'child_process';
import type { APIHelper, LogRow } from './api-helper';

export interface TriggerRequestOptions {
  /** Virtual host the proxy should route to. */
  host: string;
  /** Path + query string starting with "/". */
  path?: string;
  /** HTTP method. Defaults to GET. */
  method?: string;
  /** User-Agent header. Defaults to a benign curl identifier. */
  userAgent?: string;
  /** Spoofed client IP. nginx's set_real_ip_from trusts 127.0.0.1 so this becomes $remote_addr. */
  xForwardedFor?: string;
  /** Additional headers to set, in `Header: value` form. */
  extraHeaders?: string[];
  /** Override the host:port the curl connects to. Defaults to 127.0.0.1:18080. */
  origin?: string;
  /** Timeout in seconds passed to curl --max-time. Defaults to 5. */
  timeoutSec?: number;
}

export interface TriggerRequestResult {
  status: number;
  body: string;
}

const DEFAULT_ORIGIN = '127.0.0.1:18080';
const DEFAULT_USER_AGENT = 'npg-e2e/block-reason-spec';

/**
 * Fire a single HTTP request against the e2e proxy and return the response status + body.
 *
 * The combination of curl(127.0.0.1) + X-Forwarded-For makes nginx's real_ip module
 * substitute $remote_addr — which is what the security template inspects. This is the
 * only practical way to test per-IP rules (geo, banned-ip, access-list) from the host.
 */
export function triggerRequest(opts: TriggerRequestOptions): TriggerRequestResult {
  const origin = opts.origin ?? DEFAULT_ORIGIN;
  const path = opts.path ?? '/';
  const method = opts.method ?? 'GET';
  const ua = opts.userAgent ?? DEFAULT_USER_AGENT;
  const timeoutSec = opts.timeoutSec ?? 5;

  const args: string[] = [
    '-sk',
    '-o', '/tmp/npg-e2e-body.txt',
    '-w', '%{http_code}',
    '--max-time', String(timeoutSec),
    '-X', method,
    '-H', `Host: ${opts.host}`,
    '-H', `User-Agent: ${ua}`,
  ];

  if (opts.xForwardedFor) {
    args.push('-H', `X-Forwarded-For: ${opts.xForwardedFor}`);
  }
  if (opts.extraHeaders) {
    for (const h of opts.extraHeaders) {
      args.push('-H', h);
    }
  }

  // Build URL — leave path encoding alone, the caller controls it. Use http:// because
  // the test proxy listens on 18080 (HTTP). Tests that need TLS use port 18443 + ssl.
  args.push(`http://${origin}${path}`);

  let statusStr: string;
  try {
    statusStr = execFileSync('curl', args, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (err: unknown) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    // curl exits non-zero on connection failure; surface what we have for diagnostics
    throw new Error(
      `triggerRequest curl failed (exit ${e.status ?? '?'}): ${e.stderr ?? ''} ${e.stdout ?? ''}`.trim()
    );
  }

  const status = parseInt(statusStr.trim(), 10);
  let body = '';
  try {
    body = execFileSync('cat', ['/tmp/npg-e2e-body.txt'], { encoding: 'utf-8' });
  } catch {
    body = '';
  }

  return { status, body };
}

export interface LogMatchCriteria {
  /**
   * Filter by domain name (preferred — the log_collector caches host→ID lookups
   * for 60s, so a freshly-created host's rows may have NULL proxy_host_id.
   * The `host` field is always populated from the nginx access log line).
   */
  host?: string;
  /** Filter by proxy_host_id. Only reliable after the domain→ID cache refreshes. */
  hostId?: string;
  expectedBlockReason?: string;
  expectedStatus?: number;
  expectedLogType?: string;
  /** If provided, the row's request_uri must contain this substring. */
  uriContains?: string;
  /** Timeout in ms. Defaults to 12000. */
  timeoutMs?: number;
  /** Poll interval in ms. Defaults to 300. */
  intervalMs?: number;
}

export type { LogRow };

/**
 * Repeatedly query /api/v1/logs for the host until a row matching the predicate appears.
 *
 * The log_collector runs out-of-band — log lines may take 1-5s to land in DB after the
 * request was served. We poll instead of waiting a fixed timeout to keep tests snappy
 * on fast machines.
 */
export async function pollForLog(api: APIHelper, criteria: LogMatchCriteria): Promise<LogRow> {
  const deadline = Date.now() + (criteria.timeoutMs ?? 12000);
  const interval = criteria.intervalMs ?? 300;

  let lastSnapshot: LogRow[] = [];

  while (Date.now() < deadline) {
    let rows: LogRow[] = [];
    try {
      rows = await api.getLogs({
        host_id: criteria.hostId,
        host: criteria.host,
        limit: 50,
      });
    } catch {
      // Transient API hiccup — retry until deadline.
    }
    lastSnapshot = rows;

    for (const row of rows) {
      if (criteria.expectedBlockReason !== undefined && row.block_reason !== criteria.expectedBlockReason) {
        continue;
      }
      if (criteria.expectedStatus !== undefined && row.status_code !== criteria.expectedStatus) {
        continue;
      }
      if (criteria.expectedLogType !== undefined && row.log_type !== criteria.expectedLogType) {
        continue;
      }
      if (criteria.uriContains !== undefined) {
        const uri = row.request_uri ?? '';
        if (!uri.includes(criteria.uriContains)) {
          continue;
        }
      }
      return row;
    }

    await new Promise(res => setTimeout(res, interval));
  }

  // Build a diagnostic message that surfaces what we *did* see — the most common failure
  // mode is "block_reason is 'none' / wrong value" which is the regression we're guarding.
  const sample = lastSnapshot.slice(0, 5).map(r =>
    `  status=${r.status_code} block_reason=${r.block_reason ?? '∅'} uri=${r.request_uri} ua=${r.http_user_agent}`
  ).join('\n');
  throw new Error(
    `pollForLog timed out after ${criteria.timeoutMs ?? 12000}ms.\n` +
    `Expected: ${JSON.stringify({
      block_reason: criteria.expectedBlockReason,
      status: criteria.expectedStatus,
      log_type: criteria.expectedLogType,
      uri_contains: criteria.uriContains,
    })}\n` +
    `Most recent rows for host=${criteria.host ?? '∅'} hostId=${criteria.hostId ?? '∅'}:\n${sample || '  (none)'}`
  );
}

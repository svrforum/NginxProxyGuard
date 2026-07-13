import { test, expect } from '@playwright/test';
import { execFileSync, spawnSync } from 'child_process';
import { APIHelper } from '../../utils/api-helper';

const PROXY = 'npg-test-proxy';
function dockerExec(args: string[]): string {
  return execFileSync('docker', ['exec', PROXY, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

// The fake token makes cloudflared exit sub-second (auth failure) before the
// supervisor retries with backoff, so pgrep-based "is it running" polls are
// racy. The supervisor prefixes every connector line with [cloudflared] on the
// container's stdout — polling `docker logs --since <save time>` for that
// prefix is the stable "connector started" signal. pgrep stays only where
// absence is the assertion (the disable test), which is stable.
function cloudflaredLogsSince(sinceIso: string): string {
  try {
    const out = execFileSync('docker', ['logs', PROXY, '--since', sinceIso], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return out
      .split('\n')
      .filter((line) => line.includes('[cloudflared]'))
      .join('\n');
  } catch {
    return '';
  }
}

// The supervisor's own three fixed messages carry the [cloudflared] prefix too,
// and "token file changed; (re)starting connector" is printed BEFORE the binary
// executes — matching any [cloudflared] line would pass without cloudflared ever
// running. "Connector started" therefore means: a [cloudflared] line that is NOT
// one of the supervisor's messages, i.e. output from the binary itself (the fake
// token reliably prints "Provided Tunnel token is not valid."). This also makes
// the poll immune to a previous test's teardown line ("token removed; stopping
// connector") landing inside this test's --since window on the supervisor's next
// 5s tick.
//
// Timing: while the connector crash-loops (fake token), the supervisor's
// backoff doubles-then-clamps to a 60s cap (5→10→20→40→60) and sleeps in <=5s
// slices that re-check the token file each slice — a save during backoff is
// picked up within ~10s worst case (5s slice + 5s tick loop) instead of a full
// backoff sleep. The generous 105s poll budgets predate that fix (worst case
// was ~84s with the old un-clamped 80s max sleep) and are KEPT as safety
// margin for slow CI. Verified empirically back then: 15s polls flaked exactly
// when a prior test had escalated the backoff.
//
// COUPLING: SUPERVISOR_PHRASES must match the three supervisor echo messages
// in nginx/scripts/docker-entrypoint.sh verbatim (reciprocal comment there).
const SUPERVISOR_PHRASES = ['token file changed', 'connector not running', 'token removed'];
function connectorOutputSince(sinceIso: string): string {
  return cloudflaredLogsSince(sinceIso)
    .split('\n')
    .filter((line) => line && !SUPERVISOR_PHRASES.some((p) => line.includes(p)))
    .join('\n');
}

// Unfiltered container logs, BOTH streams (docker logs prints the container's
// stdout on stdout and its stderr on stderr) — for asserting the token value
// never reaches the logs anywhere, not just on supervisor-prefixed stdout lines.
function allDockerLogsSince(sinceIso: string): string {
  const r = spawnSync('docker', ['logs', PROXY, '--since', sinceIso], { encoding: 'utf-8' });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

// Spec §7. Serial: mutates a global singleton + a real process in the proxy
// container. Fake token: supervisor starts cloudflared, which fails upstream
// auth and backs off — exactly the error-path we assert. No real CF account
// is used; live connectivity is verified manually on a dev host (spec §7).
test.describe.serial('Cloudflare Tunnel settings (Phase 1 token mode)', () => {
  let apiHelper: APIHelper;
  const FAKE_TOKEN = 'eyJhFAKE_E2E_TUNNEL_TOKEN_abc123DEF456';

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.setCloudflareTunnel({ enabled: false, token: '' }).catch(() => {});
  });

  test('saving a token writes the 0600 token file and starts the connector', async () => {
    test.setTimeout(150_000); // 0600 poll (15s) + connector-start poll (105s, see helper comment)
    // Skew guard: docker log timestamps come from the daemon clock.
    const since = new Date(Date.now() - 2_000).toISOString();
    const saved = await apiHelper.setCloudflareTunnel({ enabled: true, token: FAKE_TOKEN });
    expect(saved.has_token).toBe(true);
    expect(saved.token_masked).toBe('eyJh****');
    expect(saved.token_masked).not.toContain('FAKE'); // masked, not echoed

    await expect.poll(() => {
      try { return dockerExec(['ls', '-la', '/etc/nginx/cloudflared/token']); } catch { return ''; }
    }, { timeout: 15_000 }).toContain('-rw-------');
    // Connector started = the cloudflared binary itself produced output
    // (supervisor-prefixed lines minus the supervisor's own fixed messages).
    // Sliced backoff picks up the save within ~10s; 105s budget kept as safety
    // margin (see helper comment).
    await expect.poll(() => connectorOutputSince(since), { timeout: 105_000, intervals: [2_000] }).not.toBe('');
    // The token value itself must never reach the container logs — any line,
    // either stream, unfiltered.
    expect(allDockerLogsSince(since)).not.toContain('FAKE_E2E_TUNNEL_TOKEN');
  });

  test('invalid token (control chars) is rejected with 400', async () => {
    await expect(apiHelper.setCloudflareTunnel({ enabled: true, token: 'abc;rm -rf /' }))
      .rejects.toThrow(/400/);
  });

  test('status degrades to error for a bogus token, nginx unaffected', async () => {
    test.setTimeout(150_000);
    await apiHelper.setCloudflareTunnel({ enabled: true, token: FAKE_TOKEN });
    // grace window is 60s → within it: starting; after: error (never connected)
    const first = await apiHelper.getTunnelStatus();
    expect(['starting', 'error']).toContain(first.state);
    // Worst case ≈ 85s (60s grace + 15s status cache TTL + 5s supervisor tick);
    // 110s leaves slack for slow CI.
    await expect.poll(async () => (await apiHelper.getTunnelStatus()).state, { timeout: 110_000, intervals: [5_000] })
      .toBe('error');
    // proxy keeps serving throughout — nginx -t exits 0 (execFileSync throws otherwise)
    expect(() => dockerExec(['nginx', '-t'])).not.toThrow();
  });

  test('disabling removes the token file and stops the connector', async () => {
    test.setTimeout(150_000); // connector-start poll (105s) + file/process polls (15s each)
    // Since-mark taken BEFORE the save; the exclusion matcher additionally
    // guards against the previous test's teardown line drifting into the window.
    const since = new Date(Date.now() - 2_000).toISOString();
    await apiHelper.setCloudflareTunnel({ enabled: true, token: FAKE_TOKEN });
    // Test 3 escalated the backoff to its 60s cap, but the sliced sleep notices
    // this save within ~10s; 105s budget kept as safety margin (see helper comment).
    await expect.poll(() => connectorOutputSince(since), { timeout: 105_000, intervals: [2_000] }).not.toBe('');

    await apiHelper.setCloudflareTunnel({ enabled: false });
    await expect.poll(() => {
      try { dockerExec(['ls', '/etc/nginx/cloudflared/token']); return 'exists'; } catch { return 'gone'; }
    }, { timeout: 15_000 }).toBe('gone');
    await expect.poll(() => {
      try { return dockerExec(['pgrep', '-x', 'cloudflared']); } catch { return ''; }
    }, { timeout: 15_000 }).toBe('');
  });
});

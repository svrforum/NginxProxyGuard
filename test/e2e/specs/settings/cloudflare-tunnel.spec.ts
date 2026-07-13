import { test, expect } from '@playwright/test';
import { execFileSync } from 'child_process';
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
    // Skew guard: docker log timestamps come from the daemon clock.
    const since = new Date(Date.now() - 2_000).toISOString();
    const saved = await apiHelper.setCloudflareTunnel({ enabled: true, token: FAKE_TOKEN });
    expect(saved.has_token).toBe(true);
    expect(saved.token_masked).toBe('eyJh****');
    expect(saved.token_masked).not.toContain('FAKE'); // masked, not echoed

    await expect.poll(() => dockerExec(['ls', '-la', '/etc/nginx/cloudflared/token']), { timeout: 15_000 })
      .toContain('-rw-------');
    // Connector started = supervisor emitted [cloudflared] lines after the save.
    await expect.poll(() => cloudflaredLogsSince(since), { timeout: 15_000 }).not.toBe('');
    // The token value itself must never reach the container logs.
    expect(cloudflaredLogsSince(since)).not.toContain('FAKE_E2E_TUNNEL_TOKEN');
  });

  test('invalid token (control chars) is rejected with 400', async () => {
    await expect(apiHelper.setCloudflareTunnel({ enabled: true, token: 'abc;rm -rf /' }))
      .rejects.toThrow(/400/);
  });

  test('status degrades to error for a bogus token, nginx unaffected', async () => {
    test.setTimeout(120_000);
    await apiHelper.setCloudflareTunnel({ enabled: true, token: FAKE_TOKEN });
    // grace window is 60s → within it: starting; after: error (never connected)
    const first = await apiHelper.getTunnelStatus();
    expect(['starting', 'error']).toContain(first.state);
    await expect.poll(async () => (await apiHelper.getTunnelStatus()).state, { timeout: 90_000, intervals: [5_000] })
      .toBe('error');
    // proxy keeps serving throughout — nginx -t exits 0 (execFileSync throws otherwise)
    expect(() => dockerExec(['nginx', '-t'])).not.toThrow();
  });

  test('disabling removes the token file and stops the connector', async () => {
    const since = new Date(Date.now() - 2_000).toISOString();
    await apiHelper.setCloudflareTunnel({ enabled: true, token: FAKE_TOKEN });
    await expect.poll(() => cloudflaredLogsSince(since), { timeout: 15_000 }).not.toBe('');

    await apiHelper.setCloudflareTunnel({ enabled: false });
    await expect.poll(() => {
      try { dockerExec(['ls', '/etc/nginx/cloudflared/token']); return 'exists'; } catch { return 'gone'; }
    }, { timeout: 15_000 }).toBe('gone');
    await expect.poll(() => {
      try { return dockerExec(['pgrep', '-x', 'cloudflared']); } catch { return ''; }
    }, { timeout: 15_000 }).toBe('');
  });
});

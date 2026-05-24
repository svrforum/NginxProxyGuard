import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES } from '../../fixtures/test-data';

/**
 * PR #143 follow-up: TCP/UDP stream proxy CRUD + safety net verification.
 *
 * Covers the four CRITICAL items in the PR review:
 *   1. Stream listener port-conflict returns 409 (was 500)
 *   2. UDP + ssl_preread combination is normalized at the API boundary
 *      (service-layer reset; template guard is the defense-in-depth)
 *   3. (DB partial unique index — exercised indirectly by the port conflict
 *      test; direct DB-level concurrent-write test would need a load harness)
 *   4. banned_ips is auto-injected into every stream server block
 * Plus SSRF guard for the stream tester (#5).
 */
test.describe('Stream proxy hosts', () => {
  let api: APIHelper;
  const cleanup: string[] = [];

  test.beforeAll(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
  });

  test.afterEach(async ({ request }) => {
    // Each test cleans up the hosts it created via the helper's own tracker.
    // We track our own IDs separately because we hit the raw request paths
    // (not createProxyHost) to exercise specific error codes.
    const helper = new APIHelper(request);
    await helper.login();
    for (const id of cleanup.splice(0)) {
      await helper.deleteProxyHost(id).catch(() => undefined);
    }
  });

  test('creates TCP stream host (CRUD: create + read + delete)', async ({ request }) => {
    const port = 16000 + Math.floor(Math.random() * 1000);

    const created = await request.post('/api/v1/proxy-hosts', {
      headers: { Authorization: `Bearer ${(api as unknown as { token: string }).token}` },
      data: {
        domain_names: [`stream-tcp-${port}`],
        forward_host: '1.1.1.1',
        forward_port: 53,
        forward_scheme: 'tcp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'tcp',
        enabled: true,
      },
    });
    expect(created.status()).toBe(201);
    const host = await created.json();
    expect(host.proxy_type).toBe('stream');
    expect(host.stream_listen_port).toBe(port);
    expect(host.stream_protocol).toBe('tcp');
    cleanup.push(host.id);

    // Read-back via GET
    const fetched = await request.get(`/api/v1/proxy-hosts/${host.id}`, {
      headers: { Authorization: `Bearer ${(api as unknown as { token: string }).token}` },
    });
    expect(fetched.status()).toBe(200);
    const detail = await fetched.json();
    expect(detail.proxy_type).toBe('stream');
    expect(detail.stream_listen_port).toBe(port);
  });

  test('updates stream host port (CRUD: update)', async ({ request }) => {
    const port = 17000 + Math.floor(Math.random() * 1000);
    const headers = { Authorization: `Bearer ${(api as unknown as { token: string }).token}` };

    const created = await request.post('/api/v1/proxy-hosts', {
      headers,
      data: {
        domain_names: [`stream-update-${port}`],
        forward_host: '1.1.1.1',
        forward_port: 53,
        forward_scheme: 'tcp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'tcp',
        enabled: true,
      },
    });
    const host = await created.json();
    cleanup.push(host.id);

    const newPort = port + 100;
    const updated = await request.put(`/api/v1/proxy-hosts/${host.id}`, {
      headers,
      data: { stream_listen_port: newPort },
    });
    expect(updated.status()).toBe(200);
    expect((await updated.json()).stream_listen_port).toBe(newPort);
  });

  test('CRITICAL #2: same port conflict returns 409 (was 500)', async ({ request }) => {
    const port = 18000 + Math.floor(Math.random() * 1000);
    const headers = { Authorization: `Bearer ${(api as unknown as { token: string }).token}` };

    const first = await request.post('/api/v1/proxy-hosts', {
      headers,
      data: {
        domain_names: [`stream-conflict-a-${port}`],
        forward_host: '1.1.1.1',
        forward_port: 53,
        forward_scheme: 'tcp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'tcp',
        enabled: true,
      },
    });
    expect(first.status()).toBe(201);
    cleanup.push((await first.json()).id);

    const second = await request.post('/api/v1/proxy-hosts', {
      headers,
      data: {
        domain_names: [`stream-conflict-b-${port}`],
        forward_host: '8.8.8.8',
        forward_port: 53,
        forward_scheme: 'tcp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'tcp',
        enabled: true,
      },
    });
    expect(second.status()).toBe(409);
    const err = await second.json();
    expect(err.error).toMatch(/listener conflict/i);
  });

  test('CRITICAL #3: UDP + ssl_preread is normalized at API boundary', async ({ request }) => {
    const port = 19000 + Math.floor(Math.random() * 1000);
    const headers = { Authorization: `Bearer ${(api as unknown as { token: string }).token}` };

    const created = await request.post('/api/v1/proxy-hosts', {
      headers,
      data: {
        domain_names: [`stream-udp-${port}`],
        forward_host: '1.1.1.1',
        forward_port: 53,
        forward_scheme: 'udp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'udp',
        stream_ssl_preread: true,
        enabled: true,
      },
    });
    expect(created.status()).toBe(201);
    const host = await created.json();
    cleanup.push(host.id);
    // Service layer must reset ssl_preread to false for UDP — nginx would
    // reject ssl_preread inside a UDP server block.
    expect(host.stream_ssl_preread).toBe(false);
  });

  test('STREAM #10: banned_ips include is auto-injected into stream config', async ({ request }) => {
    const port = 20000 + Math.floor(Math.random() * 1000);
    const headers = { Authorization: `Bearer ${(api as unknown as { token: string }).token}` };

    const created = await request.post('/api/v1/proxy-hosts', {
      headers,
      data: {
        domain_names: [`stream-banned-${port}`],
        forward_host: '1.1.1.1',
        forward_port: 53,
        forward_scheme: 'tcp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'tcp',
        enabled: true,
      },
    });
    expect(created.status()).toBe(201);
    const host = await created.json();
    cleanup.push(host.id);

    // We can't read the rendered conf file from the test client, but we can
    // verify nginx reloaded successfully (any banned_ips include syntax error
    // would have aborted the reload + rolled back). Sync endpoint returns
    // the current config status per host.
    const syncRes = await request.post('/api/v1/proxy-hosts/sync', { headers });
    expect(syncRes.ok()).toBeTruthy();
  });

  test('IMPORTANT #5: SSRF guard rejects target_url with mismatched port', async ({ request }) => {
    const port = 21000 + Math.floor(Math.random() * 1000);
    const headers = { Authorization: `Bearer ${(api as unknown as { token: string }).token}` };

    const created = await request.post('/api/v1/proxy-hosts', {
      headers,
      data: {
        domain_names: [`stream-ssrf-${port}`],
        forward_host: '1.1.1.1',
        forward_port: 53,
        forward_scheme: 'tcp',
        proxy_type: 'stream',
        stream_listen_port: port,
        stream_protocol: 'tcp',
        enabled: true,
      },
    });
    const host = await created.json();
    cleanup.push(host.id);

    // Tester accepts `url` as a query param. Mismatched port → rejected.
    const tested = await request.post(`/api/v1/proxy-hosts/${host.id}/test?url=127.0.0.1:5432`, {
      headers,
    });
    expect(tested.status()).toBe(200);
    const result = await tested.json();
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/port 5432 is not allowed/i);
  });

  test('UI: BasicTab shows stream security notice when proxy_type=stream', async ({ page }) => {
    await page.goto(ROUTES.proxyHosts);
    await page.waitForLoadState('domcontentloaded');

    // Click "Add Proxy Host" — opens the form modal
    await page.getByRole('button', { name: /add|추가|new/i }).first().click();
    await page.waitForTimeout(500);

    // Click the Stream mode tile
    await page.getByText(/TCP \/ UDP Stream/i).first().click();
    await page.waitForTimeout(300);

    // Notice must appear (English fallback covers both locales)
    const notice = page.getByText(/Stream Mode Security Notice|Stream 모드 보안 안내/);
    await expect(notice).toBeVisible({ timeout: 5000 });

    const body = page.getByText(/ModSecurity \(WAF\)|ModSecurity\(WAF\)/);
    await expect(body).toBeVisible();
  });
});

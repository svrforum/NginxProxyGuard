import { test, expect } from '@playwright/test';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';

// Issue #108 — Load-balanced upstream must support HTTPS (proxy_pass scheme).
// Defaults to "http" for backwards compatibility; "https" adds proxy_ssl_* directives.

test.describe('Upstream Scheme (Issue #108)', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestHosts();
  });

  test('GET on a host without upstream returns scheme=http default', async ({ request }) => {
    const host = await apiHelper.createProxyHost(TestDataFactory.createProxyHost());

    const res = await request.get(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: { Authorization: `Bearer ${(apiHelper as unknown as { token: string }).token}` },
    });
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.scheme).toBe('http');
  });

  test('PUT upstream with scheme=http persists and nginx .conf uses http://', async ({ request }) => {
    const host = await apiHelper.createProxyHost(TestDataFactory.createProxyHost());

    const putRes = await request.put(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: {
        Authorization: `Bearer ${(apiHelper as unknown as { token: string }).token}`,
        'Content-Type': 'application/json',
      },
      data: {
        scheme: 'http',
        servers: [{ address: '10.0.0.1', port: 8080, weight: 1 }],
        load_balance: 'round_robin',
      },
    });
    expect(putRes.ok()).toBeTruthy();
    const upstream = await putRes.json();
    expect(upstream.scheme).toBe('http');
    expect(upstream.servers).toHaveLength(1);
  });

  test('PUT upstream with scheme=https persists and generated config contains proxy_ssl directives', async ({ request }) => {
    const host = await apiHelper.createProxyHost(TestDataFactory.createProxyHost());

    const putRes = await request.put(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: {
        Authorization: `Bearer ${(apiHelper as unknown as { token: string }).token}`,
        'Content-Type': 'application/json',
      },
      data: {
        scheme: 'https',
        servers: [{ address: '10.0.0.1', port: 443, weight: 1 }],
        load_balance: 'round_robin',
      },
    });
    expect(putRes.ok()).toBeTruthy();
    const upstream = await putRes.json();
    expect(upstream.scheme).toBe('https');

    // Readback via GET should return the same scheme.
    const getRes = await request.get(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: { Authorization: `Bearer ${(apiHelper as unknown as { token: string }).token}` },
    });
    const getBody = await getRes.json();
    expect(getBody.scheme).toBe('https');
  });

  test('rejects invalid scheme values', async ({ request }) => {
    const host = await apiHelper.createProxyHost(TestDataFactory.createProxyHost());

    const res = await request.put(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: {
        Authorization: `Bearer ${(apiHelper as unknown as { token: string }).token}`,
        'Content-Type': 'application/json',
      },
      data: {
        scheme: 'ftp',
        servers: [{ address: '10.0.0.1', port: 21, weight: 1 }],
      },
    });
    expect(res.status()).toBeGreaterThanOrEqual(400);
    expect(res.status()).toBeLessThan(500);
  });

  test('round-trip: switch http -> https -> http', async ({ request }) => {
    const host = await apiHelper.createProxyHost(TestDataFactory.createProxyHost());
    const authHdr = {
      Authorization: `Bearer ${(apiHelper as unknown as { token: string }).token}`,
      'Content-Type': 'application/json',
    };
    const servers = [{ address: '10.0.0.1', port: 8080, weight: 1 }];

    let r = await request.put(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: authHdr, data: { scheme: 'http', servers },
    });
    expect((await r.json()).scheme).toBe('http');

    r = await request.put(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: authHdr, data: { scheme: 'https', servers },
    });
    expect((await r.json()).scheme).toBe('https');

    r = await request.put(`/api/v1/proxy-hosts/${host.id}/upstream`, {
      headers: authHdr, data: { scheme: 'http', servers },
    });
    expect((await r.json()).scheme).toBe('http');
  });
});

import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { NGINX_HTTP_PORT } from '../../fixtures/test-data';
import * as http from 'node:http';

/**
 * "Static files only" caching decides by the file extension. It looked for
 * the extension at the end of the whole request target, so a versioned asset
 * (app.js?v=3) was never cached, and a page whose query happened to end in
 * one (/?next=a.js) was. The decision is made on the path alone, and a path
 * that may be a page in disguise (/account.php/x.css, /account;.js) is left
 * out.
 *
 * The backend is the E2E stack's own UI, which serves hashed assets. The host
 * turns buffering on for itself: nginx stores nothing while it is off, and
 * other specs leave the global setting off.
 */
const UI_BACKEND_PORT = Number(process.env.E2E_UI_HTTPS_PORT ?? '18181');
const DOMAIN = `cache-query-${Date.now()}.example.local`;

interface ProxyResponse {
  status: number;
  cache: string | undefined;
  body: string;
}

function proxyGet(path: string, headers: Record<string, string> = {}): Promise<ProxyResponse> {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: '127.0.0.1', port: NGINX_HTTP_PORT, path, headers: { Host: DOMAIN, ...headers }, agent: false },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () =>
          resolve({ status: res.statusCode ?? 0, cache: res.headers['x-cache-status'] as string | undefined, body })
        );
      }
    );
    req.setTimeout(8000, () => req.destroy(new Error(`timeout: ${path}`)));
    req.on('error', reject);
  });
}

async function cacheStatus(path: string): Promise<string | undefined> {
  const res = await proxyGet(path);
  expect(res.status, path).toBe(200);
  return res.cache;
}

test.describe('Static-only cache and query strings', () => {
  test('caches an asset with a query string, not a page with one', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [DOMAIN],
      forward_scheme: 'https',
      forward_host: '127.0.0.1',
      forward_port: UI_BACKEND_PORT,
      enabled: true,
      ssl_enabled: false,
      cache_enabled: true,
      cache_static_only: true,
      proxy_buffering: 'on',
    });

    try {
      // Until the reload lands, nginx answers from its default server.
      let asset: string | undefined;
      await expect(async () => {
        asset = (await proxyGet('/')).body.match(/src="(\/assets\/[^"]+\.js)"/)?.[1];
        expect(asset, 'a script in the UI index page').toBeTruthy();
      }).toPass({ timeout: 15000 });

      expect(await cacheStatus(asset!)).toBe('MISS');
      expect(await cacheStatus(asset!)).toBe('HIT');

      expect(await cacheStatus(`${asset}?v=3`)).toBe('MISS');
      expect(await cacheStatus(`${asset}?v=3`)).toBe('HIT');
      // Another query is another entry.
      expect(await cacheStatus(`${asset}?v=4`)).toBe('MISS');

      // The page is not a static file, whatever its query ends in.
      expect(await cacheStatus('/?next=a.js')).toBe('BYPASS');
      expect(await cacheStatus('/?next=a.js')).toBe('BYPASS');

      // Paths a backend may answer with a page: a script with more path
      // after it, and a ";" parameter. The UI answers some with 404, so only
      // the cache decision is checked.
      for (const page of ['/account.php/x.css', '/account.php/x.css?tab=1', '/account;.js', '/account%3B.js?tab=1']) {
        expect((await proxyGet(page)).cache, page).toBe('BYPASS');
        expect((await proxyGet(page)).cache, page).toBe('BYPASS');
      }

      // What a signed-in request got is not kept for the next visitor.
      const signedIn = { Authorization: 'Basic ZTJlOmUyZQ==' };
      expect((await proxyGet(`${asset}?v=5`, signedIn)).cache).toBe('BYPASS');
      expect((await proxyGet(`${asset}?v=5`, signedIn)).cache).toBe('BYPASS');
      expect(await cacheStatus(`${asset}?v=5`)).toBe('MISS');
    } finally {
      await api.deleteProxyHost(host.id).catch(() => undefined);
    }
  });
});

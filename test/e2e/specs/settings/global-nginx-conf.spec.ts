import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { execFileSync } from 'node:child_process';

/**
 * Regression: issue #121
 *
 * The Global Settings UI could persist values to `global_settings` (brotli,
 * gzip, keepalive_timeout, custom_http_config, custom_stream_config, …), but
 * nginx.conf was a static file baked into the image — so none of those
 * settings ever reached the running nginx. The user saw:
 *   - UI brotli toggle "off" while nginx.conf still had `brotli on;`
 *   - custom_http_config and custom_stream_config silently discarded
 *
 * These tests save values through the API, then assert that the live
 * nginx.conf inside the proxy container reflects them. nginx.conf is now
 * regenerated on every Global Settings save + at startup.
 */

// readProxyNginxConf shells out to `docker exec` (via sudo in this
// environment) to pull nginx.conf directly from the running container, so the
// test asserts on the real file nginx is consuming — not a best-effort
// reconstruction from API responses.
function readProxyNginxConf(): string {
  // execFileSync keeps args as an array, so no shell interpolation happens.
  return execFileSync(
    'sudo',
    ['docker', 'exec', 'npg-test-proxy', 'cat', '/etc/nginx/nginx.conf'],
    { encoding: 'utf8' }
  );
}

// Run these tests serially so the brotli / custom_http / custom_stream mutations
// don't stomp on each other in the shared global_settings row. Parallel runs
// still happen across spec files; the regression cases just need to be atomic.
test.describe.configure({ mode: 'serial' });

test.describe('Global Settings are applied to nginx.conf (#121)', () => {
  let originalBrotli: boolean | undefined;
  let originalCustomHTTP: string | undefined;
  let originalCustomStream: string | undefined;

  test.beforeAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const apiHelper = new APIHelper(ctx);
    try {
      await apiHelper.login();
      const s = await apiHelper.getGlobalSettings();
      originalBrotli = s.brotli_enabled;
      originalCustomHTTP = s.custom_http_config ?? '';
      originalCustomStream = s.custom_stream_config ?? '';
    } finally {
      await ctx.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const apiHelper = new APIHelper(ctx);
    try {
      await apiHelper.login();
      await apiHelper.updateGlobalSettings({
        brotli_enabled: originalBrotli,
        custom_http_config: originalCustomHTTP,
        custom_stream_config: originalCustomStream,
      });
    } finally {
      await ctx.dispose();
    }
  });

  test('toggling brotli in Global Settings flips `brotli` directive in nginx.conf', async ({ request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    await apiHelper.updateGlobalSettings({ brotli_enabled: false });
    let conf = readProxyNginxConf();
    expect(conf).toContain('brotli off;');
    expect(conf).not.toMatch(/^\s*brotli on;/m);

    await apiHelper.updateGlobalSettings({ brotli_enabled: true });
    conf = readProxyNginxConf();
    expect(conf).toContain('brotli on;');
    expect(conf).not.toMatch(/^\s*brotli off;/m);
  });

  test('custom_http_config is injected inside http { } in nginx.conf', async ({ request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    // A reload-safe directive that isn't emitted by the template elsewhere,
    // so finding it proves custom_http_config was injected verbatim.
    const marker = 'proxy_headers_hash_max_size 1024;';
    await apiHelper.updateGlobalSettings({ custom_http_config: marker });
    expect(readProxyNginxConf()).toContain(marker);

    await apiHelper.updateGlobalSettings({ custom_http_config: '' });
    expect(readProxyNginxConf()).not.toContain(marker);
  });

  test('custom_stream_config produces a top-level stream { } block', async ({ request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    const streamBlock = 'server { listen 5557; proxy_pass 127.0.0.1:19080; }';
    await apiHelper.updateGlobalSettings({ custom_stream_config: streamBlock });
    let conf = readProxyNginxConf();
    expect(conf).toContain('stream {');
    expect(conf).toContain('listen 5557;');

    await apiHelper.updateGlobalSettings({ custom_stream_config: '' });
    conf = readProxyNginxConf();
    expect(conf).not.toContain('listen 5557;');
  });
});

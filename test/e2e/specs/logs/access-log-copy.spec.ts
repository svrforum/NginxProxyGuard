// "Enable Access Log" (Global Settings -> Advanced) used to render an
// http-level `access_log off;` when switched off. nginx treats `off` as
// cancelling every access_log on that level — including the
// conf.d/00-raw-logging.conf one that writes access_raw.log, the file the log
// collector tails. Switching the docker-logs copy off therefore stopped all
// access logging in the database while `nginx -t` kept passing (A5).
//
// The switch now controls only the docker-logs copy. This spec turns it off,
// sends a request through the proxy and requires the access-log row to reach
// /api/v1/logs anyway. The original value is restored even on failure.

import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { pollForLog, triggerUntil } from '../../utils/log-helper';
import { TestDataFactory } from '../../utils/test-data-factory';

// The switch is global: no other spec may flip it while this one runs.
test.describe.configure({ mode: 'serial' });

test.describe('Access log docker-logs copy (A5)', () => {
  let api: APIHelper;

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
  });

  test.afterEach(async () => {
    await api.cleanupTestHosts();
  });

  test('switching the docker-logs copy off keeps access logs flowing into the database', async () => {
    const before = await api.getGlobalSettings();
    const original = before.access_log_enabled ?? true;

    try {
      const saved = await api.updateGlobalSettings({ access_log_enabled: false });
      expect(saved.access_log_enabled).toBe(false);

      const host = TestDataFactory.generateDomain('access-copy-off');
      await api.createProxyHost({
        domain_names: [host],
        forward_host: '127.0.0.1',
        forward_port: 19080,
        forward_scheme: 'http',
        block_exploits: false,
        waf_enabled: false,
        enabled: true,
      });

      // Until the new server block is live the catch-all answers instead and
      // nothing reaches this host's access log.
      const probePath = `/_npg_access_copy_off_${Date.now()}`;
      await triggerUntil(
        { host, path: probePath, xForwardedFor: '203.0.113.43' },
        r => [200, 404, 502, 504].includes(r.status),
        { describe: `${host} to be served by its own server block` },
      );

      const row = await pollForLog(api, {
        host,
        expectedLogType: 'access',
        uriContains: probePath,
        timeoutMs: 20000,
      });
      expect(row.request_uri).toContain(probePath);
    } finally {
      await api.updateGlobalSettings({ access_log_enabled: original });
    }
  });
});

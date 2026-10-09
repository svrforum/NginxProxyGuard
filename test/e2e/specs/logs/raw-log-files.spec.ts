// Raw log files (Logs -> Raw log files): rotation by size and age, the disk
// estimate measured from real files, and the archive directory.
//
// The archive half needs the e2e compose's api service settings: a tmpfs at
// /archive (empty, so uninitialised, on every start) and
// NPG_RAW_LOG_ARCHIVE_SETTLE=0s so a rotated file may move at once. The
// archive switch is global, so the file runs serially and restores it.

import { test, expect, type APIRequestContext } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { triggerRequest } from '../../utils/log-helper';
import { API_ENDPOINTS } from '../../fixtures/test-data';

test.describe.configure({ mode: 'serial' });

const LOG_FILES = `${API_ENDPOINTS.systemSettings}/log-files`;

async function authed(api: APIHelper) {
  return { Authorization: `Bearer ${await api.getToken()}` };
}

async function getLogFiles(request: APIRequestContext, api: APIHelper, query = '') {
  const res = await request.get(`${LOG_FILES}${query}`, { headers: await authed(api) });
  return { status: res.status(), body: await res.json() };
}

/** A canary request is logged to access_raw.log like any other. */
function writeAccessLines(tag: string, n = 5) {
  for (let i = 0; i < n; i++) {
    triggerRequest({ host: 'localhost', path: `/__npg_canary?n=${tag}-${i}` });
  }
}

test.describe('Raw log files', () => {
  let api: APIHelper;

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
  });

  test('the form has no rotated-file count and shows the measured estimate', async ({ page }) => {
    await page.goto('/logs/raw-files');
    await page.waitForLoadState('networkidle');
    await expect(page.getByTestId('raw-log-usage-estimate')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/보관할 로테이션 파일 수|Rotation Keep Count/)).toHaveCount(0);
    await expect(page.locator('#raw-log-raw_log_max_size_mb')).toHaveAttribute('min', '10');
    await expect(page.locator('#raw-log-raw_log_retention_days')).toHaveAttribute('max', '3650');
  });

  test('the list reports usage and pages', async ({ request }) => {
    const { status, body } = await getLogFiles(request, api, '?limit=1&offset=0');
    expect(status).toBe(200);
    expect(body.limit).toBe(1);
    expect(body.files.length).toBeLessThanOrEqual(1);
    expect(body.location).toBe('local');
    expect(typeof body.usage.avg_daily_bytes).toBe('number');
    expect(typeof body.usage.live_bytes).toBe('number');
    expect(['last_7_days', 'history', 'none']).toContain(body.usage.basis);
    const live = (await getLogFiles(request, api)).body.files.find((f: { name: string }) => f.name === 'access_raw.log');
    expect(live?.is_active).toBe(true);
  });

  test('out-of-range values are refused, echoed stored values are not', async ({ request }) => {
    const before = await api.getSystemSettings();
    const headers = { ...(await authed(api)), 'Content-Type': 'application/json' };
    const bad = await request.put(API_ENDPOINTS.systemSettings, { headers, data: { raw_log_retention_days: 0 } });
    expect(bad.status()).toBe(400);
    expect((await bad.json()).error).toContain('raw_log_retention_days must be between 1 and 3650');
    const echo = await request.put(API_ENDPOINTS.systemSettings, {
      headers,
      data: { raw_log_retention_days: before.raw_log_retention_days, raw_log_rotate_count: before.raw_log_rotate_count },
    });
    expect(echo.status()).toBe(200);
  });

  test('the live raw log cannot be deleted', async ({ request }) => {
    const res = await request.delete(`${LOG_FILES}/access_raw.log`, { headers: await authed(api) });
    expect(res.status()).toBe(400);
  });

  test('archive: check, initialise, rotate, move, list and download', async ({ request }) => {
    const headers = await authed(api);
    const before = await api.getSystemSettings();
    try {
      const listing = await getLogFiles(request, api);
      expect(listing.body.archive, 'the e2e api service needs the /archive tmpfs').toBeTruthy();
      expect(listing.body.archive.dir).toBe('/archive');

      const check = await request.post(`${LOG_FILES}/archive/check`, { headers });
      expect(check.status()).toBe(200);
      const probe = await check.json();
      expect(probe.writable).toBe(true);
      expect(['not_initialized', 'ready']).toContain(probe.status);

      const init = await request.post(`${LOG_FILES}/archive/init`, { headers });
      expect(init.status()).toBe(200);
      expect((await init.json()).status).toBe('ready');

      await api.updateSystemSettings({ raw_log_archive_enabled: true, raw_log_compress_rotated: true });

      // Two cuts with traffic in between: delaycompress compresses the first
      // rotated file at the second rotation.
      for (const round of ['a', 'b']) {
        writeAccessLines(`raw-archive-${round}-${Date.now()}`);
        await expect.poll(async () => {
          const r = await request.post(`${LOG_FILES}/rotate`, { headers });
          return r.status() === 200 ? (await r.json()).status : `HTTP ${r.status()}`;
        }, { timeout: 30000, intervals: [1500] }).toBe('completed');
      }

      const run = await request.post(`${LOG_FILES}/archive/run`, { headers });
      expect(run.status()).toBe(202);

      let archived = '';
      await expect.poll(async () => {
        const { status, body } = await getLogFiles(request, api, '?location=archive');
        if (status !== 200) return `HTTP ${status}`;
        archived = body.files.find((f: { name: string }) => f.name.endsWith('.gz'))?.name ?? '';
        return archived !== '';
      }, { timeout: 60000, intervals: [2000] }).toBe(true);

      const local = await getLogFiles(request, api);
      expect(local.body.files.map((f: { name: string }) => f.name)).not.toContain(archived);
      expect(local.body.archive.status).toBe('ready');

      const dl = await request.get(`${LOG_FILES}/${encodeURIComponent(archived)}/download?location=archive`, { headers });
      expect(dl.status()).toBe(200);
      const bytes = await dl.body();
      expect(bytes[0]).toBe(0x1f); // gzip magic
      expect(bytes[1]).toBe(0x8b);
    } finally {
      await api.updateSystemSettings({ raw_log_archive_enabled: before.raw_log_archive_enabled ?? false });
    }
  });
});

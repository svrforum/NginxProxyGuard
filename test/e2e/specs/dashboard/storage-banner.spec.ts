import { test, expect, type Page } from '@playwright/test';
import { DashboardPage } from '../../pages/dashboard.page';

// The disk warning (D4) without filling a disk: GET /dashboard is answered by
// the real API and `storage` (plus the matching system_health disk figures) is
// spliced into the response before the UI sees it.

const GB = 1024 ** 3;
type Level = 'ok' | 'low' | 'critical';

function storage(level: Level, pct: number, emergency?: Record<string, unknown>, measured = true) {
  const total = 188 * GB;
  return {
    level,
    thresholds: { warn_percent: 85, critical_percent: 90, recover_percent: 80 },
    filesystems: [{
      key: 'db',
      roles: ['db', 'nginx_logs', 'backups', 'docker'],
      path: 'npg-db:/var/lib/postgresql/data',
      source: 'docker_exec',
      total_bytes: total,
      used_bytes: (pct / 100) * total,
      avail_bytes: ((100 - pct) / 100) * total,
      used_percent: pct,
      level,
      growth_per_day_bytes: 2 * GB,
      days_to_full: (((100 - pct) / 100) * 188) / 2,
      measured_at: new Date().toISOString(),
    }],
    database: measured
      ? { measured: true, container: 'npg-db', data_dir: '/var/lib/postgresql/data' }
      : { measured: false, reason: 'db_container_not_found' },
    ...(emergency ? { emergency } : {}),
    measured_at: new Date().toISOString(),
  };
}

async function mockStorage(page: Page, s: ReturnType<typeof storage>) {
  await page.route('**/api/v1/dashboard', async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    const fs = s.filesystems[0];
    await route.fulfill({
      response: res,
      json: {
        ...body,
        storage: s,
        // The server reports the same disk in both places.
        system_health: {
          ...body.system_health,
          disk_usage: fs.used_percent, disk_used: fs.used_bytes, disk_total: fs.total_bytes, disk_path: fs.path,
        },
      },
    });
  });
}

test.describe('Dashboard storage warning', () => {
  test('critical shows a red alert with the emergency compression progress', async ({ page }) => {
    await mockStorage(page, storage('critical', 91.4, {
      mode: 'on', state: 'running', chunks_done: 1, chunks_total: 2, freed_bytes: 7 * GB,
    }));
    await new DashboardPage(page).goto();

    const banner = page.getByTestId('storage-alert');
    await expect(banner).toBeVisible();
    await expect(banner).toHaveAttribute('data-level', 'critical');
    await expect(banner).toContainText('npg-db:/var/lib/postgresql/data');
    await expect(page.getByTestId('storage-emergency')).toContainText('1/2');
    await expect(banner).not.toContainText('storage.'); // no raw i18n keys
    await expect(page.getByTestId('disk-usage-bar')).toHaveClass(/bg-red-500/);
  });

  test('low shows an amber alert and the unmeasured-database note; ok shows none', async ({ page }) => {
    await mockStorage(page, storage('low', 86.2, undefined, false));
    await new DashboardPage(page).goto();

    await expect(page.getByTestId('storage-alert')).toHaveAttribute('data-level', 'low');
    await expect(page.getByTestId('storage-emergency')).toHaveCount(0);
    await expect(page.getByTestId('disk-usage-bar')).toHaveClass(/bg-amber-500/);
    await expect(page.getByTestId('disk-db-not-measured')).toContainText('NPG_DB_CONTAINER');

    await page.unroute('**/api/v1/dashboard');
    await mockStorage(page, storage('ok', 52));
    await page.reload();
    // Wait for the mocked dashboard to render before asserting an absence.
    await expect(page.getByTestId('disk-usage-bar')).toHaveClass(/bg-green-500/);
    await expect(page.getByTestId('storage-alert')).toHaveCount(0);
  });
});

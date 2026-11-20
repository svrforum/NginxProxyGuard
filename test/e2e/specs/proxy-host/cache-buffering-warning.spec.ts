import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { GlobalSettingsPage } from '../../pages/global-settings.page';
import type { Page } from '@playwright/test';

/**
 * nginx stores nothing in the proxy cache while proxy_buffering is off, so a
 * host with both set answers MISS forever. The form says so, whether the off
 * comes from the host or from the global setting it falls back to.
 */
// The global value is shared with the other specs; answer for it here instead
// of changing it.
async function pretendGlobalBuffering(page: Page, value: string): Promise<void> {
  await page.route('**/api/v1/settings', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...(await response.json()), proxy_buffering: value } });
  });
}

test.describe('Cache with proxy buffering off', () => {
  test('warns in the host form until buffering is on', async ({ page }) => {
    await pretendGlobalBuffering(page, 'off');

    const listPage = new ProxyHostListPage(page);
    const formPage = new ProxyHostFormPage(page);
    await listPage.goto();
    await listPage.clickAddHost();
    await formPage.switchTab('performance');

    const warning = page.getByTestId('cache-buffering-warning');
    const buffering = page.locator('select').filter({
      has: page.locator('option', { hasText: 'Off (stream directly)' }),
    });

    // Cache off: nothing to warn about.
    await expect(buffering).toHaveValue('');
    await expect(warning).toHaveCount(0);

    await page.getByRole('checkbox').first().check();
    await expect(warning).toContainText('global settings');

    await buffering.selectOption('on');
    await expect(warning).toHaveCount(0);

    await buffering.selectOption('off');
    await expect(warning).toContainText('proxy settings below');
    await expect(warning).not.toContainText('global settings');
  });

  test('says nothing while the global setting buffers', async ({ page }) => {
    await pretendGlobalBuffering(page, '');

    const listPage = new ProxyHostListPage(page);
    const formPage = new ProxyHostFormPage(page);
    await listPage.goto();
    await listPage.clickAddHost();
    await formPage.switchTab('performance');

    const settings = page.waitForResponse((r) => r.url().endsWith('/api/v1/settings'));
    await page.getByRole('checkbox').first().check();
    await settings;
    await expect(page.getByText('Cache behavior:')).toBeVisible();
    await expect(page.getByTestId('cache-buffering-warning')).toHaveCount(0);
  });

  test('the global setting says what turning it off costs', async ({ page }) => {
    await pretendGlobalBuffering(page, 'off');

    const settingsPage = new GlobalSettingsPage(page);
    await settingsPage.goto();
    await settingsPage.gotoPerformanceTab();
    await expect(page.getByText('hosts that have caching enabled store nothing')).toBeVisible();
  });
});

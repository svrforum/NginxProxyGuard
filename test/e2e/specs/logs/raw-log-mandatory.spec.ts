import { test, expect } from '@playwright/test';

test.describe('v2.17.1 raw log mandatory enforcement', () => {
  test('UI: /logs/raw-files shows always-on emerald notice', async ({ page }) => {
    await page.goto('/logs/raw-files');
    await page.waitForLoadState('networkidle');

    const notice = page.getByText(/Raw 로그 저장 항상 활성화|Raw Log Storage Always Enabled/);
    await expect(notice).toBeVisible({ timeout: 10000 });

    const desc = page.getByText(/raw 로그 저장은 항상 활성화됩니다|raw log storage is always enabled/);
    await expect(desc).toBeVisible();
  });

  test('UI: no edit-able raw_log_enabled toggle remains on the page', async ({ page }) => {
    await page.goto('/logs/raw-files');
    await page.waitForLoadState('networkidle');
    await page.getByText(/Raw 로그 저장 항상 활성화|Raw Log Storage Always Enabled/).waitFor({ state: 'visible' });

    const toggles = page.locator('label.cursor-pointer:has(input[type="checkbox"])');
    const count = await toggles.count();
    for (let i = 0; i < count; i++) {
      const labelText = (await toggles.nth(i).textContent()) || '';
      const looksLikeMasterRawToggle = /raw[^a-z]/i.test(labelText) && /활성|enable/i.test(labelText) && !/회전|압축|compress|rotate/i.test(labelText);
      expect(looksLikeMasterRawToggle, `Master raw_log_enabled toggle should be gone — found label: ${labelText.trim()}`).toBeFalsy();
    }
  });

  test('API: PUT system-settings with raw_log_enabled=false is silently coerced to true', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const result = await page.evaluate(async () => {
      const token = localStorage.getItem('npg_token');
      const resp = await fetch('/api/v1/system-settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ raw_log_enabled: false }),
      });
      const body = await resp.json();
      return { status: resp.status, body };
    });

    expect(result.status).toBe(200);
    expect(result.body.raw_log_enabled).toBe(true);
  });

  test('API: GET system-settings reflects raw_log_enabled=true after override', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const result = await page.evaluate(async () => {
      const token = localStorage.getItem('npg_token');
      const resp = await fetch('/api/v1/system-settings', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return resp.json();
    });

    expect(result.raw_log_enabled).toBe(true);
  });
});

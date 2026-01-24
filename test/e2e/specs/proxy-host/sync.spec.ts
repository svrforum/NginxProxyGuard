import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { DashboardPage } from '../../pages/dashboard.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Proxy Host Sync', () => {
  let listPage: ProxyHostListPage;
  let dashboardPage: DashboardPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    listPage = new ProxyHostListPage(page);
    dashboardPage = new DashboardPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestHosts();
  });

  test('should show sync all button in header', async ({ page }) => {
    await dashboardPage.goto();
    await expect(dashboardPage.syncAllButton).toBeVisible();
  });

  test('should trigger sync all from header', async ({ page }) => {
    await dashboardPage.goto();

    // Click sync button
    await dashboardPage.syncAllButton.click();

    // Should show sync progress modal
    const syncModal = page.locator('[class*="modal"], [role="dialog"]');
    await expect(syncModal).toBeVisible({ timeout: TIMEOUTS.medium });

    // Wait for sync to complete
    await page.waitForFunction(
      () => {
        const spinner = document.querySelector('[class*="animate-spin"]');
        const modal = document.querySelector('[class*="modal"], [role="dialog"]');
        return !spinner || !modal || modal.textContent?.includes('success') || modal.textContent?.includes('complete');
      },
      { timeout: TIMEOUTS.veryLong }
    );
  });

  test('should show sync result with success status', async ({ page }) => {
    // Create a test host first
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);

    await dashboardPage.goto();
    await dashboardPage.syncAllButton.click();

    // Wait for sync to complete
    const syncModal = page.locator('[class*="modal"], [role="dialog"]');
    await expect(syncModal).toBeVisible();

    // Wait for success indicator
    await page.waitForSelector('text=/success|complete|synced/i', { timeout: TIMEOUTS.veryLong });
  });

  test('should handle sync with no hosts', async ({ page }) => {
    // Cleanup all test hosts first
    await apiHelper.cleanupTestHosts(/.*/);

    await dashboardPage.goto();
    await dashboardPage.syncAllButton.click();

    // Sync should complete (even if no hosts)
    const syncModal = page.locator('[class*="modal"], [role="dialog"]');
    await expect(syncModal).toBeVisible();

    // Wait for completion
    await page.waitForTimeout(TIMEOUTS.medium);
  });

  test('should sync after creating new host', async ({ page }) => {
    // Create a new host via UI
    await listPage.goto();
    await listPage.clickAddHost();

    const formPage = await import('../../pages/proxy-host-form.page').then(m => new m.ProxyHostFormPage(page));
    const testDomain = TestDataFactory.generateDomain('sync-after-create');

    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');
    await formPage.fillForwardPort(8080);
    await formPage.save();

    // Wait for form to close
    await formPage.expectClosed();

    // Now sync
    await listPage.syncAllButton.click();

    // Wait for sync to complete
    await page.waitForSelector('[class*="modal"], [role="dialog"]', { state: 'visible' });
    await page.waitForFunction(
      () => !document.querySelector('[class*="animate-spin"]'),
      { timeout: TIMEOUTS.veryLong }
    );
  });

  test('should show sync status per host in result', async ({ page }) => {
    // Create multiple hosts
    const host1 = TestDataFactory.createProxyHost();
    const host2 = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(host1);
    await apiHelper.createProxyHost(host2);

    await dashboardPage.goto();
    await dashboardPage.syncAllButton.click();

    const syncModal = page.locator('[class*="modal"], [role="dialog"]');
    await expect(syncModal).toBeVisible();

    // Wait for sync to complete
    await page.waitForFunction(
      () => !document.querySelector('[class*="animate-spin"]'),
      { timeout: TIMEOUTS.veryLong }
    );

    // Modal should show result for multiple hosts
    const modalContent = await syncModal.textContent();
    expect(modalContent).toBeTruthy();
  });

  test('should close sync modal', async ({ page }) => {
    await dashboardPage.goto();
    await dashboardPage.syncAllButton.click();

    const syncModal = page.locator('[class*="modal"], [role="dialog"]');
    await expect(syncModal).toBeVisible();

    // Wait for sync to complete
    await page.waitForFunction(
      () => !document.querySelector('[class*="animate-spin"]'),
      { timeout: TIMEOUTS.veryLong }
    );

    // Close the modal
    const closeButton = syncModal.locator('button').filter({ hasText: /close|done|ok/i }).first();
    if (await closeButton.isVisible()) {
      await closeButton.click();
      await expect(syncModal).not.toBeVisible({ timeout: TIMEOUTS.short });
    }
  });

  test('should sync via API helper', async () => {
    // Create a test host
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);

    // Sync via API
    const result = await apiHelper.syncAllProxyHosts();

    expect(result).toHaveProperty('total_hosts');
    expect(result).toHaveProperty('success_count');
    expect(result.total_hosts).toBeGreaterThanOrEqual(1);
  });
});

test.describe('Sync Error Handling', () => {
  test.skip('should show error when sync fails', async ({ page, request }) => {
    // This test would require creating an invalid configuration
    // that causes nginx test/reload to fail
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    // Create a host with potentially invalid config
    // (This is hard to test without actually breaking nginx)

    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();
    await dashboardPage.syncAllButton.click();

    // Check if error is shown when sync fails
  });
});

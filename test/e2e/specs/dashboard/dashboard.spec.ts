import { test, expect } from '@playwright/test';
import { DashboardPage } from '../../pages/dashboard.page';
import { ROUTES, TIMEOUTS } from '../../fixtures/test-data';
import { APIHelper } from '../../utils/api-helper';
import { TestDataFactory } from '../../utils/test-data-factory';

test.describe('Dashboard', () => {
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    dashboardPage = new DashboardPage(page);
  });

  test('should navigate to dashboard', async () => {
    await dashboardPage.goto();
    await dashboardPage.expectDashboard();
  });

  test('should redirect root to dashboard', async ({ page }) => {
    await page.goto('/');
    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/(dashboard|proxy-hosts)/);
  });

  test('should display main navigation tabs', async ({ page }) => {
    await dashboardPage.goto();

    // Verify all main navigation tabs are visible
    await expect(dashboardPage.navDashboard).toBeVisible();
    await expect(dashboardPage.navProxyHosts).toBeVisible();
    await expect(dashboardPage.navWaf).toBeVisible();
    await expect(dashboardPage.navCertificates).toBeVisible();
    await expect(dashboardPage.navLogs).toBeVisible();
    await expect(dashboardPage.navSettings).toBeVisible();
  });

  test('should show app title in header', async ({ page }) => {
    await dashboardPage.goto();

    // Should have NPG title/logo
    await expect(page.locator('header')).toContainText(/nginx.*proxy.*guard/i);
  });

  test('should show version number', async ({ page }) => {
    await dashboardPage.goto();

    // Version should be displayed (e.g., v1.3.24)
    const versionText = page.locator('text=/v\\d+\\.\\d+\\.\\d+/');
    await expect(versionText.first()).toBeVisible({ timeout: TIMEOUTS.medium });
  });

  test('should show logged in user', async ({ page }) => {
    await dashboardPage.goto();

    const username = await dashboardPage.getLoggedInUser();
    expect(username).toBeTruthy();
  });

  test('should display statistics section', async ({ page }) => {
    await dashboardPage.goto();

    // Stats section should be visible
    await expect(dashboardPage.statsSection).toBeVisible({ timeout: TIMEOUTS.medium });
  });

  test('should navigate from dashboard to proxy hosts', async ({ page }) => {
    await dashboardPage.goto();
    await dashboardPage.gotoProxyHosts();

    await expect(page).toHaveURL(/\/proxy-hosts/);
  });

  test('should navigate from dashboard to certificates', async ({ page }) => {
    await dashboardPage.goto();
    await dashboardPage.gotoCertificates();

    await expect(page).toHaveURL(/\/certificates/);
  });

  test('should navigate from dashboard to logs', async ({ page }) => {
    await dashboardPage.goto();
    await dashboardPage.gotoLogs();

    await expect(page).toHaveURL(/\/logs/);
  });

  test('should navigate from dashboard to settings', async ({ page }) => {
    await dashboardPage.goto();
    await dashboardPage.gotoSettings();

    await expect(page).toHaveURL(/\/settings/);
  });

  test('should navigate from dashboard to WAF', async ({ page }) => {
    await dashboardPage.goto();
    await dashboardPage.gotoWaf();

    await expect(page).toHaveURL(/\/waf/);
  });
});

test.describe('Dashboard Statistics', () => {
  test('should show host count', async ({ page, request }) => {
    const dashboardPage = new DashboardPage(page);
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    // Create a test host
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);

    await dashboardPage.goto();

    // Should show at least 1 host
    const totalHosts = await dashboardPage.getTotalHostsCount();
    expect(totalHosts).toBeGreaterThanOrEqual(1);

    // Cleanup
    await apiHelper.cleanupTestHosts();
  });

  test('should update stats after creating host', async ({ page, request }) => {
    const dashboardPage = new DashboardPage(page);
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    // Clean up first
    await apiHelper.cleanupTestHosts();

    await dashboardPage.goto();
    const initialCount = await dashboardPage.getTotalHostsCount();

    // Create a new host
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);

    // Refresh dashboard
    await dashboardPage.refresh();

    const newCount = await dashboardPage.getTotalHostsCount();
    expect(newCount).toBeGreaterThan(initialCount);

    // Cleanup
    await apiHelper.cleanupTestHosts();
  });
});

test.describe('Dashboard Dark Mode', () => {
  test('should toggle dark mode', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();

    // Get initial state
    const initialIsDark = await page.evaluate(() =>
      document.documentElement.classList.contains('dark')
    );

    // Toggle dark mode
    await dashboardPage.toggleDarkMode();

    // Verify mode changed
    const afterToggleIsDark = await page.evaluate(() =>
      document.documentElement.classList.contains('dark')
    );

    expect(afterToggleIsDark).not.toBe(initialIsDark);
  });

  test('should persist dark mode preference', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();

    // Enable dark mode
    const initialIsDark = await page.evaluate(() =>
      document.documentElement.classList.contains('dark')
    );

    if (!initialIsDark) {
      await dashboardPage.toggleDarkMode();
    }

    // Refresh page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Dark mode should be preserved
    const afterReloadIsDark = await page.evaluate(() =>
      document.documentElement.classList.contains('dark')
    );

    expect(afterReloadIsDark).toBe(true);
  });
});

test.describe('Dashboard Footer', () => {
  test('should show footer with copyright', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();

    // Footer should have copyright
    const footer = page.locator('footer');
    await expect(footer).toContainText(/nginx.*proxy.*guard/i);
  });

  test('should have GitHub link', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();

    const githubLink = page.locator('a[href*="github"]');
    await expect(githubLink.first()).toBeVisible();
  });

  test('should have documentation link', async ({ page }) => {
    const dashboardPage = new DashboardPage(page);
    await dashboardPage.goto();

    const docsLink = page.locator('a').filter({ hasText: /doc/i });
    await expect(docsLink.first()).toBeVisible();
  });
});

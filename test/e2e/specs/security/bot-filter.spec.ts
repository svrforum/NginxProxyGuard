import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES, TIMEOUTS } from '../../fixtures/test-data';

test.describe('Bot Filter on Proxy Host', () => {
  let listPage: ProxyHostListPage;
  let formPage: ProxyHostFormPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    listPage = new ProxyHostListPage(page);
    formPage = new ProxyHostFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestHosts();
  });

  test('should enable Bot Filter on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Enable Bot Filter
    await formPage.toggleBotFilter(true);

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.bot_filter_enabled).toBe(true);
  });

  test('should disable Bot Filter on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost({
      bot_filter_enabled: true,
    });
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Disable Bot Filter
    await formPage.toggleBotFilter(false);

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.bot_filter_enabled).toBe(false);
  });

  test('should create proxy host with Bot Filter from scratch', async ({ page }) => {
    const testDomain = TestDataFactory.generateDomain('botfilter-new');

    await listPage.goto();
    await listPage.clickAddHost();

    // Fill basic info
    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');
    await formPage.fillForwardPort(8080);

    // Enable Bot Filter
    await formPage.toggleBotFilter(true);

    await formPage.save();

    // Verify
    const hosts = await apiHelper.getProxyHosts();
    const createdHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(createdHost?.bot_filter_enabled).toBe(true);
  });
});

test.describe('Bot Filter Global Settings', () => {
  test('should navigate to Bot Filter settings page', async ({ page }) => {
    await page.goto(ROUTES.settingsBotfilter);
    await expect(page).toHaveURL(/\/settings\/botfilter/);
  });

  test('should display Bot Filter settings interface', async ({ page }) => {
    await page.goto(ROUTES.settingsBotfilter);

    // Page should have settings content
    await expect(page.locator('main')).toContainText(/bot/i);
  });
});

test.describe('Bot Filter Logs', () => {
  test('should navigate to Bot Filter logs', async ({ page }) => {
    await page.goto(ROUTES.logsBotFilter);
    await expect(page).toHaveURL(/\/logs\/bot-filter/);
  });

  test('should display Bot Filter logs interface', async ({ page }) => {
    await page.goto(ROUTES.logsBotFilter);

    // Page should load without errors
    await page.waitForLoadState('networkidle');

    // Should have some content (empty state or logs)
    await expect(page.locator('main')).toBeVisible();
  });
});

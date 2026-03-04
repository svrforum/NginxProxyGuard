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
  let createdHostId: number | null;

  test.beforeEach(async ({ page, request }) => {
    listPage = new ProxyHostListPage(page);
    formPage = new ProxyHostFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
    createdHostId = null;
  });

  test.afterEach(async () => {
    // Only delete the host created by this specific test
    if (createdHostId) {
      await apiHelper.deleteProxyHost(createdHostId).catch(() => {});
    }
  });

  test('should enable Bot Filter on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost(testData);
    createdHostId = created.id;
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Enable Bot Filter
    await formPage.toggleBotFilter(true);

    await formPage.save();

    // Verify via bot filter API
    const botFilter = await apiHelper.getBotFilter(created.id.toString());
    expect(botFilter?.enabled).toBe(true);
  });

  test('should disable Bot Filter on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost(testData);
    createdHostId = created.id;
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Enable Bot Filter first, then disable
    await formPage.toggleBotFilter(true);
    await formPage.save();

    await listPage.goto();
    await listPage.clickHost(testDomain);
    await formPage.toggleBotFilter(false);
    await formPage.save();

    // Verify via bot filter API
    const botFilter = await apiHelper.getBotFilter(created.id.toString());
    expect(botFilter?.enabled).toBe(false);
  });

  test('should create proxy host with Bot Filter from scratch', async ({ page }) => {
    const testDomain = TestDataFactory.generateDomain('bf');

    await listPage.goto();
    await listPage.clickAddHost();

    // Fill basic info
    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');
    await formPage.fillForwardPort(8080);

    // Enable Bot Filter
    await formPage.toggleBotFilter(true);

    // In create mode, save button is only visible on the last tab
    await formPage.switchTab('advanced');
    await formPage.save();

    // Verify via bot filter API
    const hosts = await apiHelper.getProxyHosts();
    const createdHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(createdHost).toBeTruthy();
    createdHostId = createdHost!.id;
    const botFilter = await apiHelper.getBotFilter(createdHost!.id.toString());
    expect(botFilter?.enabled).toBe(true);
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
    await page.waitForLoadState('domcontentloaded');

    // Should have some content (empty state or logs)
    await expect(page.locator('main')).toBeVisible();
  });
});

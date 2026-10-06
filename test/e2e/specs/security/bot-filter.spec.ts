import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { triggerUntil } from '../../utils/log-helper';
import { ROUTES, TIMEOUTS } from '../../fixtures/test-data';

test.describe('Bot Filter on Proxy Host', () => {
  let listPage: ProxyHostListPage;
  let formPage: ProxyHostFormPage;
  let apiHelper: APIHelper;
  let createdHostId: string | null;

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

test.describe('Bot Filter path-limited allowed agent (#313)', () => {
  let apiHelper: APIHelper;
  let createdHostId: string | null;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
    createdHostId = null;
  });

  test.afterEach(async () => {
    if (createdHostId) {
      await apiHelper.deleteProxyHost(createdHostId).catch(() => {});
    }
  });

  test('should exempt an allowed agent only under its paths', async () => {
    // Unreachable upstream: a request the bot filter lets through answers 502
    // (which also proves the exemption holds through the error_page redirect
    // to /error_502.html), one it blocks answers 403.
    const host = await apiHelper.createProxyHost({
      domain_names: [TestDataFactory.generateDomain('bf-scope')],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 1,
      enabled: true,
    });
    createdHostId = host.id;
    const domain = host.domain_names[0];
    const okhttp = 'okhttp/4.12.0';

    // A path without "/" is refused instead of being saved as a dead user agent.
    await expect(
      apiHelper.setBotFilter(host.id, { blockSuspiciousClients: true, customAllowedAgents: 'okhttp @ api' }),
    ).rejects.toThrow(/400.*must start with/);

    await apiHelper.setBotFilter(host.id, {
      blockSuspiciousClients: true,
      customAllowedAgents: 'okhttp @ /api\nGoodBot',
    });

    // Without the bot filter every request is a 502, so wait for the block
    // first: once okhttp gets 403 outside /api, the new config is live.
    await triggerUntil({ host: domain, path: '/admin', userAgent: okhttp }, r => r.status === 403, {
      describe: 'okhttp to be blocked outside /api',
    });
    for (const path of ['/api', '/api/v1/items', '/api?x=1']) {
      const res = await triggerUntil({ host: domain, path, userAgent: okhttp }, r => r.status === 502, {
        describe: `okhttp to be exempt on ${path}`,
      });
      expect(res.status).toBe(502);
    }
    // A sibling path and a path a backend may resolve above /api stay blocked.
    for (const path of ['/api-admin', '/', '/api/..;/admin']) {
      const res = await triggerUntil({ host: domain, path, userAgent: okhttp }, r => r.status === 403, {
        describe: `okhttp to stay blocked on ${path}`,
      });
      expect(res.status).toBe(403);
    }
    // Another client library is not exempted on /api; the whole-host line is.
    const curl = await triggerUntil({ host: domain, path: '/api', userAgent: 'curl/8.5.0' }, r => r.status === 403);
    expect(curl.status).toBe(403);
    const goodBot = await triggerUntil({ host: domain, path: '/admin', userAgent: 'GoodBot curl/8.5.0' }, r => r.status === 502);
    expect(goodBot.status).toBe(502);
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

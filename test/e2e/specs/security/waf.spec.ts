import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES, TIMEOUTS, WAF_MODES, PARANOIA_LEVELS } from '../../fixtures/test-data';

test.describe('WAF Settings on Proxy Host', () => {
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

  test('should display Security tab in form', async () => {
    await listPage.goto();
    await listPage.clickAddHost();

    await expect(formPage.securityTab).toBeVisible();
  });

  test('should enable WAF on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Enable WAF
    await formPage.toggleWAF(true);

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.waf_enabled).toBe(true);
  });

  test('should disable WAF on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createWAFProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Disable WAF
    await formPage.toggleWAF(false);

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.waf_enabled).toBe(false);
  });

  test('should set WAF mode to Detection Only', async ({ page }) => {
    const testData = TestDataFactory.createWAFProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.setWAFMode('DetectionOnly');

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.waf_mode).toBe('DetectionOnly');
  });

  test('should set WAF mode to Blocking', async ({ page }) => {
    const testData = TestDataFactory.createWAFProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.setWAFMode('On');

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.waf_mode).toBe('On');
  });

  test('should create proxy host with WAF enabled from scratch', async ({ page }) => {
    const testDomain = TestDataFactory.generateDomain('waf-new');

    await listPage.goto();
    await listPage.clickAddHost();

    // Fill basic info
    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');
    await formPage.fillForwardPort(8080);

    // Enable WAF
    await formPage.toggleWAF(true);

    await formPage.save();

    // Verify
    const hosts = await apiHelper.getProxyHosts();
    const createdHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(createdHost?.waf_enabled).toBe(true);
  });
});

test.describe('WAF Global Settings Page', () => {
  test('should navigate to WAF settings page', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);
    await expect(page).toHaveURL(/\/waf\/settings/);
  });

  test('should display WAF settings interface', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);

    // Should have sub-navigation for WAF sections
    await expect(page.locator('button, [role="tab"]').filter({ hasText: /settings/i }).first()).toBeVisible();
  });

  test('should navigate to banned IPs section', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);

    const bannedIpsTab = page.locator('button, [role="tab"]').filter({ hasText: /banned.*ip/i }).first();
    if (await bannedIpsTab.isVisible()) {
      await bannedIpsTab.click();
      await expect(page).toHaveURL(/\/waf\/banned-ips/);
    }
  });

  test('should navigate to URI blocks section', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);

    const uriBlocksTab = page.locator('button, [role="tab"]').filter({ hasText: /uri.*block/i }).first();
    if (await uriBlocksTab.isVisible()) {
      await uriBlocksTab.click();
      await expect(page).toHaveURL(/\/waf\/uri-blocks/);
    }
  });

  test('should navigate to exploit rules section', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);

    const exploitRulesTab = page.locator('button, [role="tab"]').filter({ hasText: /exploit.*rule/i }).first();
    if (await exploitRulesTab.isVisible()) {
      await exploitRulesTab.click();
      await expect(page).toHaveURL(/\/waf\/exploit-rules/);
    }
  });

  test('should navigate to fail2ban section', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);

    const fail2banTab = page.locator('button, [role="tab"]').filter({ hasText: /fail2ban/i }).first();
    if (await fail2banTab.isVisible()) {
      await fail2banTab.click();
      await expect(page).toHaveURL(/\/waf\/fail2ban/);
    }
  });

  test('should navigate to WAF tester section', async ({ page }) => {
    await page.goto(ROUTES.wafSettings);

    const testerTab = page.locator('button, [role="tab"]').filter({ hasText: /test/i }).first();
    if (await testerTab.isVisible()) {
      await testerTab.click();
      await expect(page).toHaveURL(/\/waf\/tester/);
    }
  });
});

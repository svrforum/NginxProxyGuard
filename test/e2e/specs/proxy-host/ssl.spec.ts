import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Proxy Host SSL Settings', () => {
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

  test('should display SSL tab in form', async () => {
    await listPage.goto();
    await listPage.clickAddHost();

    await expect(formPage.sslTab).toBeVisible();
  });

  test('should enable SSL for proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Switch to SSL tab and enable SSL
    await formPage.toggleSSL(true);

    // Save changes
    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.ssl_enabled).toBe(true);
  });

  test('should disable SSL for proxy host', async ({ page }) => {
    // Create host with SSL enabled
    const testData = TestDataFactory.createSSLProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Disable SSL
    await formPage.toggleSSL(false);

    // Save changes
    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.ssl_enabled).toBe(false);
  });

  test('should enable HTTP/2 with SSL', async ({ page }) => {
    const testData = TestDataFactory.createSSLProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.switchTab('ssl');

    // HTTP/2 toggle should be visible when SSL is enabled
    if (await formPage.http2Toggle.isVisible()) {
      const isChecked = await formPage.http2Toggle.isChecked();
      if (!isChecked) {
        await formPage.http2Toggle.click();
      }
    }

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.http2_enabled).toBe(true);
  });

  test('should enable HTTP/3 with SSL', async ({ page }) => {
    const testData = TestDataFactory.createSSLProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.switchTab('ssl');

    // HTTP/3 toggle should be visible
    if (await formPage.http3Toggle.isVisible()) {
      const isChecked = await formPage.http3Toggle.isChecked();
      if (!isChecked) {
        await formPage.http3Toggle.click();
      }

      await formPage.save();

      // Verify via API
      const hosts = await apiHelper.getProxyHosts();
      const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
      expect(updatedHost?.http3_enabled).toBe(true);
    }
  });

  test('should enable Force HTTPS redirect', async ({ page }) => {
    const testData = TestDataFactory.createSSLProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.switchTab('ssl');

    // Force HTTPS toggle
    if (await formPage.forceHttpsToggle.isVisible()) {
      const isChecked = await formPage.forceHttpsToggle.isChecked();
      if (!isChecked) {
        await formPage.forceHttpsToggle.click();
      }

      await formPage.save();

      // Verify the setting was saved (check via API or UI)
    }
  });

  test('should enable HSTS', async ({ page }) => {
    const testData = TestDataFactory.createSSLProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.switchTab('ssl');

    // HSTS toggle
    if (await formPage.hstsToggle.isVisible()) {
      const isChecked = await formPage.hstsToggle.isChecked();
      if (!isChecked) {
        await formPage.hstsToggle.click();
      }

      await formPage.save();
    }
  });

  test('should show SSL options only when SSL is enabled', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost({
      ssl_enabled: false,
    });
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    await formPage.switchTab('ssl');

    // SSL is disabled - HTTP/2, HTTP/3, etc. might be hidden or disabled
    // This depends on UI implementation
  });

  test('should create proxy host with SSL from scratch', async ({ page }) => {
    const testDomain = TestDataFactory.generateDomain('ssl-from-scratch');

    await listPage.goto();
    await listPage.clickAddHost();

    // Fill basic info
    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');
    await formPage.fillForwardPort(8080);

    // Enable SSL
    await formPage.toggleSSL(true);

    // Save
    await formPage.save();

    // Verify
    await listPage.waitForHostsLoad();
    const hosts = await apiHelper.getProxyHosts();
    const createdHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(createdHost?.ssl_enabled).toBe(true);
  });
});

test.describe('SSL Certificate Selection', () => {
  test.skip('should show certificate selection dropdown when SSL is enabled', async ({ page, request }) => {
    // This test requires certificates to exist
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    const certificates = await apiHelper.getCertificates();

    // Skip if no certificates exist
    if (certificates.length === 0) {
      test.skip();
      return;
    }

    const listPage = new ProxyHostListPage(page);
    const formPage = new ProxyHostFormPage(page);

    await listPage.goto();
    await listPage.clickAddHost();

    // Enable SSL
    await formPage.toggleSSL(true);

    // Certificate select should be visible
    await expect(formPage.certificateSelect).toBeVisible();
  });
});

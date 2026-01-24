import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES, TIMEOUTS } from '../../fixtures/test-data';

test.describe('GeoIP on Proxy Host', () => {
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

  test('should enable GeoIP on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Enable GeoIP (note: may need license key configured)
    await formPage.toggleGeoIP(true);

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.geoip_enabled).toBe(true);
  });

  test('should disable GeoIP on proxy host', async ({ page }) => {
    const testData = TestDataFactory.createProxyHost({
      geoip_enabled: true,
    });
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Disable GeoIP
    await formPage.toggleGeoIP(false);

    await formPage.save();

    // Verify via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.domain_names.includes(testDomain));
    expect(updatedHost?.geoip_enabled).toBe(false);
  });
});

test.describe('GeoIP Global Settings', () => {
  test('should navigate to GeoIP settings page', async ({ page }) => {
    await page.goto(ROUTES.settingsGeoip);
    await expect(page).toHaveURL(/\/settings\/geoip/);
  });

  test('should display GeoIP settings interface', async ({ page }) => {
    await page.goto(ROUTES.settingsGeoip);

    // Page should have GeoIP content
    await page.waitForLoadState('networkidle');
    await expect(page.locator('main')).toContainText(/geo/i);
  });

  test('should show license key configuration section', async ({ page }) => {
    await page.goto(ROUTES.settingsGeoip);

    // GeoIP requires MaxMind license key
    // Should have input or configuration for license key
    const licenseKeySection = page.locator('input[type="text"], input[type="password"]').filter({
      has: page.locator('[placeholder*="key"], [placeholder*="license"]'),
    });

    // Either license key input exists or status indicator
    const hasLicenseSection = await licenseKeySection.count() > 0 ||
      await page.locator('text=/license|maxmind/i').count() > 0;

    expect(hasLicenseSection).toBeTruthy();
  });
});

test.describe('GeoIP Country Selection', () => {
  test.skip('should show country selection when GeoIP is enabled', async ({ page, request }) => {
    // This test requires GeoIP to be properly configured with license key
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    const listPage = new ProxyHostListPage(page);
    const formPage = new ProxyHostFormPage(page);

    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickHost(testDomain);

    // Enable GeoIP
    await formPage.toggleGeoIP(true);

    // Should show country selection interface
    const countrySelector = page.locator('[class*="country"], select, [role="listbox"]').filter({
      has: page.locator('text=/country|region|geo/i'),
    });

    await expect(countrySelector).toBeVisible();
  });
});

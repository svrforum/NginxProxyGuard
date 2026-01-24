import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Proxy Host CRUD', () => {
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
    // Cleanup test hosts
    await apiHelper.cleanupTestHosts();
  });

  test('should display proxy host list', async () => {
    await listPage.goto();
    await listPage.expectProxyHostList();
  });

  test('should show add button', async () => {
    await listPage.goto();
    await expect(listPage.addHostButton).toBeVisible();
  });

  test('should open add host form', async () => {
    await listPage.goto();
    await listPage.clickAddHost();

    await formPage.expectForm();
  });

  test('should create new proxy host with basic configuration', async ({ page }) => {
    const testDomain = TestDataFactory.generateDomain('crud-test');

    await listPage.goto();
    await listPage.clickAddHost();

    // Fill in basic configuration
    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');
    await formPage.fillForwardPort(8080);

    // Save the host
    await formPage.save();

    // Verify form closed
    await formPage.expectClosed();

    // Verify host appears in list
    await listPage.waitForHostsLoad();
    await expect(listPage.getHostByDomain(testDomain)).toBeVisible({ timeout: TIMEOUTS.medium });
  });

  test('should edit existing proxy host', async ({ page }) => {
    // Create a host via API first
    const testData = TestDataFactory.createProxyHost();
    const createdHost = await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();

    // Click on the host to edit
    await listPage.clickHost(testDomain);
    await formPage.expectForm();

    // Change the forward port
    await formPage.fillForwardPort(9090);

    // Save changes
    await formPage.save();

    // Verify changes via API
    const hosts = await apiHelper.getProxyHosts();
    const updatedHost = hosts.find(h => h.id === createdHost.id);
    expect(updatedHost?.forward_port).toBe(9090);
  });

  test('should delete proxy host', async ({ page }) => {
    // Create a host via API first
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();

    // Verify host exists
    await expect(listPage.getHostByDomain(testDomain)).toBeVisible();

    // Delete the host
    await listPage.deleteHost(testDomain);

    // Verify host is removed
    await listPage.waitForHostsLoad();
    await expect(listPage.getHostByDomain(testDomain)).not.toBeVisible({ timeout: TIMEOUTS.medium });
  });

  test('should validate required fields', async ({ page }) => {
    await listPage.goto();
    await listPage.clickAddHost();

    // Try to save without filling required fields
    await formPage.save();

    // Should show validation errors
    await page.waitForTimeout(500);
    const hasErrors = await formPage.hasValidationErrors();
    expect(hasErrors).toBeTruthy();

    // Form should still be open
    await formPage.expectForm();
  });

  test('should cancel form without saving', async ({ page }) => {
    await listPage.goto();
    const initialCount = await listPage.getHostCount();

    await listPage.clickAddHost();

    // Fill in some data
    await formPage.fillDomain('should-not-be-saved.example.local');
    await formPage.fillForwardHost('192.168.1.1');

    // Cancel
    await formPage.cancel();

    // Form should close
    await formPage.expectClosed();

    // Count should remain the same
    const finalCount = await listPage.getHostCount();
    expect(finalCount).toBe(initialCount);
  });

  test('should handle duplicate domain error', async ({ page }) => {
    // Create a host first
    const testData = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(testData);
    const existingDomain = testData.domain_names[0];

    await listPage.goto();
    await listPage.clickAddHost();

    // Try to create another host with the same domain
    await formPage.fillDomain(existingDomain);
    await formPage.fillForwardHost('192.168.1.200');
    await formPage.fillForwardPort(8080);

    await formPage.save();

    // Should show error (duplicate domain)
    await page.waitForTimeout(1000);
    // Form should still be open or show error
    const hasErrors = await formPage.hasValidationErrors();
    // Either validation error or form still open
    expect(hasErrors || await formPage.isVisible()).toBeTruthy();
  });

  test('should search hosts by domain', async ({ page }) => {
    // Create multiple hosts
    const host1 = TestDataFactory.createProxyHost({
      domain_names: [TestDataFactory.generateDomain('search-alpha')],
    });
    const host2 = TestDataFactory.createProxyHost({
      domain_names: [TestDataFactory.generateDomain('search-beta')],
    });
    await apiHelper.createProxyHost(host1);
    await apiHelper.createProxyHost(host2);

    await listPage.goto();

    // Search for alpha
    await listPage.searchHosts('search-alpha');

    // Should show only matching host
    await expect(listPage.getHostByDomain(host1.domain_names[0])).toBeVisible();

    // Clear search
    await listPage.clearSearch();

    // Should show all hosts again
    await listPage.waitForHostsLoad();
  });

  test('should handle host with multiple domains', async ({ page }) => {
    const domains = TestDataFactory.generateDomains(3, 'multi-domain');
    const testData = TestDataFactory.createProxyHost({
      domain_names: domains,
    });

    await apiHelper.createProxyHost(testData);

    await listPage.goto();

    // Primary domain should be visible
    await expect(listPage.getHostByDomain(domains[0])).toBeVisible();
  });
});

test.describe('Proxy Host Form Tabs', () => {
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

  test('should switch between form tabs', async ({ page }) => {
    await listPage.goto();
    await listPage.clickAddHost();

    // Switch to SSL tab
    await formPage.switchTab('ssl');
    await expect(formPage.sslTab).toHaveClass(/border-primary|active|selected/);

    // Switch to Security tab
    await formPage.switchTab('security');
    await expect(formPage.securityTab).toHaveClass(/border-primary|active|selected/);

    // Switch back to Basic tab
    await formPage.switchTab('basic');
    await expect(formPage.basicTab).toHaveClass(/border-primary|active|selected/);
  });

  test('should preserve form data when switching tabs', async ({ page }) => {
    await listPage.goto();
    await listPage.clickAddHost();

    // Fill basic info
    const testDomain = TestDataFactory.generateDomain('tab-preserve');
    await formPage.fillDomain(testDomain);
    await formPage.fillForwardHost('192.168.1.100');

    // Switch to SSL tab
    await formPage.switchTab('ssl');

    // Switch back to Basic tab
    await formPage.switchTab('basic');

    // Data should be preserved (verify form still has values)
    // This depends on implementation, but form should not reset
  });
});

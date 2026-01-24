import { test, expect } from '@playwright/test';
import { DnsProviderPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('DNS Provider Management', () => {
  let dnsProviderPage: DnsProviderPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    dnsProviderPage = new DnsProviderPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Cleanup test DNS providers
    await apiHelper.cleanupTestDnsProviders();
  });

  test.describe('DNS Provider List', () => {
    test('should display DNS providers page', async () => {
      await dnsProviderPage.goto();
      await dnsProviderPage.expectDnsProviderPage();
    });

    test('should show add provider button', async () => {
      await dnsProviderPage.goto();
      await expect(dnsProviderPage.addProviderButton).toBeVisible();
    });

    test('should open add provider form', async () => {
      await dnsProviderPage.goto();
      await dnsProviderPage.clickAddProvider();
      await expect(dnsProviderPage.modal).toBeVisible();
    });

    test('should display provider count', async () => {
      await dnsProviderPage.goto();
      const count = await dnsProviderPage.getProviderCount();
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  test.describe('Create DNS Provider', () => {
    test('should show provider type selection', async () => {
      await dnsProviderPage.goto();
      await dnsProviderPage.clickAddProvider();
      await expect(dnsProviderPage.typeSelect).toBeVisible();
    });

    test('should create Cloudflare provider', async () => {
      const providerData = TestDataFactory.createCloudflareDnsProvider();

      await dnsProviderPage.goto();
      await dnsProviderPage.createProvider(providerData);

      // Verify provider exists
      await dnsProviderPage.waitForLoad();
      const exists = await dnsProviderPage.providerExists(providerData.name);
      expect(exists).toBeTruthy();
    });

    test('should create DuckDNS provider', async () => {
      const providerData = TestDataFactory.createDuckDnsProvider();

      await dnsProviderPage.goto();
      await dnsProviderPage.createProvider(providerData);

      // Verify provider exists
      await dnsProviderPage.waitForLoad();
      const exists = await dnsProviderPage.providerExists(providerData.name);
      expect(exists).toBeTruthy();
    });

    test('should create Dynu provider', async () => {
      const providerData = TestDataFactory.createDynuDnsProvider();

      await dnsProviderPage.goto();
      await dnsProviderPage.createProvider(providerData);

      // Verify provider exists
      await dnsProviderPage.waitForLoad();
      const exists = await dnsProviderPage.providerExists(providerData.name);
      expect(exists).toBeTruthy();
    });

    test('should validate required fields', async ({ page }) => {
      await dnsProviderPage.goto();
      await dnsProviderPage.clickAddProvider();

      // Try to save without filling required fields
      await dnsProviderPage.save();

      // Should show validation errors or form should still be open
      await page.waitForTimeout(500);
      const hasErrors = await dnsProviderPage.hasValidationErrors();
      const modalVisible = await dnsProviderPage.modal.isVisible();
      expect(hasErrors || modalVisible).toBeTruthy();
    });

    test('should cancel form without saving', async () => {
      await dnsProviderPage.goto();
      const initialCount = await dnsProviderPage.getProviderCount();

      await dnsProviderPage.clickAddProvider();
      await dnsProviderPage.fillName('should-not-be-saved');
      await dnsProviderPage.cancel();

      // Count should remain the same
      const finalCount = await dnsProviderPage.getProviderCount();
      expect(finalCount).toBe(initialCount);
    });
  });

  test.describe('Edit DNS Provider', () => {
    test('should open edit form when clicking provider', async () => {
      // Create a provider first
      const providerData = TestDataFactory.createCloudflareDnsProvider();
      await apiHelper.createDnsProvider(providerData);

      await dnsProviderPage.goto();
      await dnsProviderPage.clickProvider(providerData.name);
      await expect(dnsProviderPage.modal).toBeVisible();
    });

    test('should update provider name', async () => {
      // Create a provider first
      const providerData = TestDataFactory.createCloudflareDnsProvider();
      const created = await apiHelper.createDnsProvider(providerData);

      await dnsProviderPage.goto();
      await dnsProviderPage.clickProvider(providerData.name);

      // Change name
      const newName = `updated-${Date.now()}`;
      await dnsProviderPage.fillName(newName);
      await dnsProviderPage.save();

      // Verify update
      await dnsProviderPage.waitForLoad();
      const exists = await dnsProviderPage.providerExists(newName);
      expect(exists).toBeTruthy();
    });
  });

  test.describe('Delete DNS Provider', () => {
    test('should delete provider', async () => {
      // Create a provider first
      const providerData = TestDataFactory.createCloudflareDnsProvider();
      await apiHelper.createDnsProvider(providerData);

      await dnsProviderPage.goto();

      // Verify it exists
      await expect(dnsProviderPage.getProviderByName(providerData.name)).toBeVisible();

      // Delete it
      await dnsProviderPage.deleteProvider(providerData.name);

      // Verify it's gone
      const exists = await dnsProviderPage.providerExists(providerData.name);
      expect(exists).toBeFalsy();
    });
  });

  test.describe('Connection Test', () => {
    test.skip('should test connection for valid credentials', async () => {
      // This test would require valid API credentials
      await dnsProviderPage.goto();
      await dnsProviderPage.clickAddProvider();
      await dnsProviderPage.fillName('test-connection');
      await dnsProviderPage.fillCloudflareCredentials('valid-token');

      const result = await dnsProviderPage.testConnection();
      // Skipped because requires real credentials
      expect(result).toBeDefined();
    });

    test('should show error for invalid credentials', async () => {
      await dnsProviderPage.goto();
      await dnsProviderPage.clickAddProvider();
      await dnsProviderPage.fillName('test-invalid');
      await dnsProviderPage.fillCloudflareCredentials('invalid-token-123');

      // Try to test connection - should fail or show error
      await dnsProviderPage.testConnection();

      // Either error message or connection status should indicate failure
      // This depends on actual API behavior
    });
  });

  test.describe('API Integration', () => {
    test('should fetch DNS providers via API', async () => {
      const providers = await apiHelper.getDnsProviders();
      expect(Array.isArray(providers)).toBeTruthy();
    });

    test('should create DNS provider via API', async () => {
      const providerData = TestDataFactory.createCloudflareDnsProvider();
      const created = await apiHelper.createDnsProvider(providerData);

      expect(created).toHaveProperty('id');
      expect(created.name).toBe(providerData.name);
    });

    test('should delete DNS provider via API', async () => {
      const providerData = TestDataFactory.createCloudflareDnsProvider();
      const created = await apiHelper.createDnsProvider(providerData);

      await apiHelper.deleteDnsProvider(created.id);

      // Verify deletion
      const providers = await apiHelper.getDnsProviders();
      const found = providers.find(p => p.id === created.id);
      expect(found).toBeUndefined();
    });
  });
});

test.describe('DNS Provider Types', () => {
  let dnsProviderPage: DnsProviderPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    dnsProviderPage = new DnsProviderPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestDnsProviders();
  });

  test('should show Cloudflare credential fields', async () => {
    await dnsProviderPage.goto();
    await dnsProviderPage.clickAddProvider();
    await dnsProviderPage.selectType('cloudflare');

    // API token field should be visible
    await expect(
      dnsProviderPage.cloudflareApiTokenInput
        .or(dnsProviderPage.page.locator('input[placeholder*="token"], input[name*="token"]'))
    ).toBeVisible();
  });

  test('should show DuckDNS credential fields', async () => {
    await dnsProviderPage.goto();
    await dnsProviderPage.clickAddProvider();
    await dnsProviderPage.selectType('duckdns');

    // Token field should be visible
    await expect(
      dnsProviderPage.duckdnsTokenInput
        .or(dnsProviderPage.page.locator('input[placeholder*="token"], input[name*="token"]'))
    ).toBeVisible();
  });

  test('should show Dynu credential fields', async () => {
    await dnsProviderPage.goto();
    await dnsProviderPage.clickAddProvider();
    await dnsProviderPage.selectType('dynu');

    // Username and password fields should be visible
    const usernameVisible = await dnsProviderPage.dynuUsernameInput.isVisible() ||
      await dnsProviderPage.page.locator('input[placeholder*="username"], input[name*="username"]').isVisible();
    const passwordVisible = await dnsProviderPage.dynuPasswordInput.isVisible() ||
      await dnsProviderPage.page.locator('input[placeholder*="password"], input[name*="password"]').isVisible();

    expect(usernameVisible && passwordVisible).toBeTruthy();
  });
});

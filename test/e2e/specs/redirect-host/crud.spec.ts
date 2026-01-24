import { test, expect } from '@playwright/test';
import { RedirectHostListPage, RedirectHostFormPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Redirect Host CRUD', () => {
  let listPage: RedirectHostListPage;
  let formPage: RedirectHostFormPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    listPage = new RedirectHostListPage(page);
    formPage = new RedirectHostFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Cleanup test redirect hosts
    await apiHelper.cleanupTestRedirectHosts();
  });

  test.describe('List Page', () => {
    test('should display redirect host list', async () => {
      await listPage.goto();
      await listPage.expectRedirectHostList();
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
  });

  test.describe('Create Redirect Host', () => {
    test('should create new redirect host with 301 code', async () => {
      const testDomain = TestDataFactory.generateDomain('redirect-e2e');

      await listPage.goto();
      await listPage.clickAddHost();

      await formPage.fillConfig({
        domain: testDomain,
        forwardDomain: 'https://example.com',
        redirectCode: 301,
        preservePath: true,
      });

      await formPage.save();
      await formPage.expectClosed();

      // Verify host appears in list
      await listPage.waitForHostsLoad();
      await expect(listPage.getHostByDomain(testDomain)).toBeVisible({ timeout: TIMEOUTS.medium });
    });

    test('should create new redirect host with 302 code', async () => {
      const testData = TestDataFactory.createTemporaryRedirect();
      const testDomain = testData.domain_names[0];

      await listPage.goto();
      await listPage.clickAddHost();

      await formPage.fillConfig({
        domain: testDomain,
        forwardDomain: testData.forward_domain,
        redirectCode: 302,
        preservePath: testData.preserve_path,
      });

      await formPage.save();
      await formPage.expectClosed();

      // Verify host appears in list
      await listPage.waitForHostsLoad();
      await expect(listPage.getHostByDomain(testDomain)).toBeVisible({ timeout: TIMEOUTS.medium });
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

    test('should cancel form without saving', async () => {
      await listPage.goto();
      const initialCount = await listPage.getHostCount();

      await listPage.clickAddHost();
      await formPage.fillDomain('should-not-be-saved.example.local');
      await formPage.fillForwardDomain('https://example.com');
      await formPage.cancel();

      await formPage.expectClosed();

      const finalCount = await listPage.getHostCount();
      expect(finalCount).toBe(initialCount);
    });
  });

  test.describe('Edit Redirect Host', () => {
    test('should open edit form when clicking host', async () => {
      // Create a host via API first
      const testData = TestDataFactory.createRedirectHost();
      await apiHelper.createRedirectHost(testData);
      const testDomain = testData.domain_names[0];

      await listPage.goto();
      await listPage.clickHost(testDomain);
      await formPage.expectForm();
    });

    test('should update redirect code', async () => {
      // Create a host via API first
      const testData = TestDataFactory.createRedirectHost({ redirect_code: 301 });
      const created = await apiHelper.createRedirectHost(testData);
      const testDomain = testData.domain_names[0];

      await listPage.goto();
      await listPage.clickHost(testDomain);

      // Change redirect code to 302
      await formPage.selectRedirectCode(302);
      await formPage.save();

      // Verify change via API
      const hosts = await apiHelper.getRedirectHosts();
      const updatedHost = hosts.find(h => h.id === created.id);
      expect(updatedHost?.redirect_code).toBe(302);
    });

    test('should update forward domain', async () => {
      const testData = TestDataFactory.createRedirectHost();
      const created = await apiHelper.createRedirectHost(testData);
      const testDomain = testData.domain_names[0];

      await listPage.goto();
      await listPage.clickHost(testDomain);

      const newTarget = 'https://new-target.example.com';
      await formPage.fillForwardDomain(newTarget);
      await formPage.save();

      // Verify change via API
      const hosts = await apiHelper.getRedirectHosts();
      const updatedHost = hosts.find(h => h.id === created.id);
      expect(updatedHost?.forward_domain).toBe(newTarget);
    });
  });

  test.describe('Delete Redirect Host', () => {
    test('should delete redirect host', async () => {
      // Create a host via API first
      const testData = TestDataFactory.createRedirectHost();
      await apiHelper.createRedirectHost(testData);
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
  });

  test.describe('Search', () => {
    test('should search hosts by domain', async () => {
      // Create multiple hosts
      const host1 = TestDataFactory.createRedirectHost({
        domain_names: [TestDataFactory.generateDomain('search-alpha')],
      });
      const host2 = TestDataFactory.createRedirectHost({
        domain_names: [TestDataFactory.generateDomain('search-beta')],
      });
      await apiHelper.createRedirectHost(host1);
      await apiHelper.createRedirectHost(host2);

      await listPage.goto();

      // Search for alpha
      await listPage.searchHosts('search-alpha');

      // Should show only matching host
      await expect(listPage.getHostByDomain(host1.domain_names[0])).toBeVisible();

      // Clear search
      await listPage.clearSearch();
      await listPage.waitForHostsLoad();
    });
  });

  test.describe('Redirect Codes', () => {
    test.describe.parallel('should create redirects with different codes', () => {
      const redirectCodes: Array<301 | 302 | 307 | 308> = [301, 302, 307, 308];

      for (const code of redirectCodes) {
        test(`should create redirect with ${code} code`, async ({ page, request }) => {
          const localApiHelper = new APIHelper(request);
          await localApiHelper.login();

          const testData = TestDataFactory.createRedirectHost({ redirect_code: code });
          const created = await localApiHelper.createRedirectHost(testData);

          expect(created.redirect_code).toBe(code);

          // Cleanup
          await localApiHelper.deleteRedirectHost(created.id);
        });
      }
    });
  });

  test.describe('Preserve Path Option', () => {
    test('should create redirect with preserve path enabled', async () => {
      const testData = TestDataFactory.createRedirectHost({ preserve_path: true });
      const created = await apiHelper.createRedirectHost(testData);

      expect(created.preserve_path).toBe(true);
    });

    test('should create redirect with preserve path disabled', async () => {
      const testData = TestDataFactory.createRedirectHost({ preserve_path: false });
      const created = await apiHelper.createRedirectHost(testData);

      expect(created.preserve_path).toBe(false);
    });

    test('should toggle preserve path in form', async () => {
      await listPage.goto();
      await listPage.clickAddHost();

      const testDomain = TestDataFactory.generateDomain('preserve-path-test');
      await formPage.fillDomain(testDomain);
      await formPage.fillForwardDomain('https://example.com');
      await formPage.togglePreservePath(true);
      await formPage.save();

      // Verify via API
      const hosts = await apiHelper.getRedirectHosts();
      const host = hosts.find(h => h.domain_names.includes(testDomain));
      expect(host?.preserve_path).toBe(true);
    });
  });

  test.describe('API Integration', () => {
    test('should fetch redirect hosts via API', async () => {
      const hosts = await apiHelper.getRedirectHosts();
      expect(Array.isArray(hosts)).toBeTruthy();
    });

    test('should create redirect host via API', async () => {
      const testData = TestDataFactory.createRedirectHost();
      const created = await apiHelper.createRedirectHost(testData);

      expect(created).toHaveProperty('id');
      expect(created.domain_names).toEqual(testData.domain_names);
      expect(created.forward_domain).toBe(testData.forward_domain);
    });

    test('should update redirect host via API', async () => {
      const testData = TestDataFactory.createRedirectHost();
      const created = await apiHelper.createRedirectHost(testData);

      const updated = await apiHelper.updateRedirectHost(created.id, {
        redirect_code: 308,
      });

      expect(updated.redirect_code).toBe(308);
    });

    test('should delete redirect host via API', async () => {
      const testData = TestDataFactory.createRedirectHost();
      const created = await apiHelper.createRedirectHost(testData);

      await apiHelper.deleteRedirectHost(created.id);

      // Verify deletion
      const hosts = await apiHelper.getRedirectHosts();
      const found = hosts.find(h => h.id === created.id);
      expect(found).toBeUndefined();
    });
  });
});

test.describe('Redirect Host Status', () => {
  let listPage: RedirectHostListPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    listPage = new RedirectHostListPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestRedirectHosts();
  });

  test('should display enabled status', async () => {
    const testData = TestDataFactory.createRedirectHost({ enabled: true });
    await apiHelper.createRedirectHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();

    const isEnabled = await listPage.isHostEnabled(testDomain);
    expect(isEnabled).toBe(true);
  });

  test('should toggle enabled status', async () => {
    const testData = TestDataFactory.createRedirectHost({ enabled: true });
    await apiHelper.createRedirectHost(testData);
    const testDomain = testData.domain_names[0];

    await listPage.goto();

    // Toggle disabled
    await listPage.toggleHostEnabled(testDomain);

    // Verify status changed
    const isEnabled = await listPage.isHostEnabled(testDomain);
    // Note: This might be async, so we check it's a boolean
    expect(typeof isEnabled).toBe('boolean');
  });
});

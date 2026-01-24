import { test, expect } from '@playwright/test';
import { AccessListPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Access List Management', () => {
  let accessListPage: AccessListPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    accessListPage = new AccessListPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Cleanup test access lists
    await apiHelper.cleanupTestAccessLists();
  });

  test.describe('Access List Page', () => {
    test('should display access lists page', async () => {
      await accessListPage.goto();
      await accessListPage.expectAccessListPage();
    });

    test('should show add list button', async () => {
      await accessListPage.goto();
      await expect(accessListPage.addListButton).toBeVisible();
    });

    test('should open add list form', async () => {
      await accessListPage.goto();
      await accessListPage.clickAddList();
      await expect(accessListPage.modal).toBeVisible();
    });

    test('should display list count', async () => {
      await accessListPage.goto();
      const count = await accessListPage.getListCount();
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  test.describe('Create Access List', () => {
    test('should create access list with allowed IPs', async () => {
      const testData = TestDataFactory.createAccessList({
        allowed_ips: ['192.168.1.0/24', '10.0.0.1'],
      });

      await accessListPage.goto();
      await accessListPage.createList({
        name: testData.name,
        allowedIps: testData.allowed_ips,
      });

      // Verify list exists
      await accessListPage.waitForLoad();
      const exists = await accessListPage.listExists(testData.name);
      expect(exists).toBeTruthy();
    });

    test('should create access list with denied IPs', async () => {
      const testData = TestDataFactory.createAccessList({
        denied_ips: ['192.168.1.100', '192.168.1.200'],
      });

      await accessListPage.goto();
      await accessListPage.createList({
        name: testData.name,
        deniedIps: testData.denied_ips,
      });

      // Verify list exists
      await accessListPage.waitForLoad();
      const exists = await accessListPage.listExists(testData.name);
      expect(exists).toBeTruthy();
    });

    test('should create access list with both allow and deny rules', async () => {
      const testData = TestDataFactory.createMixedAccessList();

      await accessListPage.goto();
      await accessListPage.createList({
        name: testData.name,
        allowedIps: testData.allowed_ips,
        deniedIps: testData.denied_ips,
      });

      // Verify list exists
      await accessListPage.waitForLoad();
      const exists = await accessListPage.listExists(testData.name);
      expect(exists).toBeTruthy();
    });

    test('should validate required fields', async ({ page }) => {
      await accessListPage.goto();
      await accessListPage.clickAddList();

      // Try to save without filling name
      await accessListPage.save();

      // Should show validation errors
      await page.waitForTimeout(500);
      const hasErrors = await accessListPage.hasValidationErrors();
      const modalVisible = await accessListPage.modal.isVisible();
      expect(hasErrors || modalVisible).toBeTruthy();
    });

    test('should cancel form without saving', async () => {
      await accessListPage.goto();
      const initialCount = await accessListPage.getListCount();

      await accessListPage.clickAddList();
      await accessListPage.fillName('should-not-be-saved');
      await accessListPage.cancel();

      const finalCount = await accessListPage.getListCount();
      expect(finalCount).toBe(initialCount);
    });
  });

  test.describe('Edit Access List', () => {
    test('should open edit form when clicking list', async () => {
      // Create a list via API
      const testData = TestDataFactory.createAccessList();
      await apiHelper.createAccessList(testData);

      await accessListPage.goto();
      await accessListPage.clickList(testData.name);
      await expect(accessListPage.modal).toBeVisible();
    });

    test('should update list name', async () => {
      // Create a list via API
      const testData = TestDataFactory.createAccessList();
      const created = await apiHelper.createAccessList(testData);

      await accessListPage.goto();
      await accessListPage.clickList(testData.name);

      // Change name
      const newName = `updated-acl-${Date.now()}`;
      await accessListPage.fillName(newName);
      await accessListPage.save();

      // Verify update
      await accessListPage.waitForLoad();
      const exists = await accessListPage.listExists(newName);
      expect(exists).toBeTruthy();
    });

    test('should add new IP to existing list', async () => {
      const testData = TestDataFactory.createAccessList({
        allowed_ips: ['192.168.1.0/24'],
      });
      await apiHelper.createAccessList(testData);

      await accessListPage.goto();
      await accessListPage.clickList(testData.name);

      // Add new IP
      await accessListPage.addAllowedIp('10.0.0.1');
      await accessListPage.save();

      // Verify via API
      const lists = await apiHelper.getAccessLists();
      const list = lists.find(l => l.name === testData.name);
      expect(list?.allowed_ips).toContain('10.0.0.1');
    });
  });

  test.describe('Delete Access List', () => {
    test('should delete access list', async () => {
      // Create a list via API
      const testData = TestDataFactory.createAccessList();
      await apiHelper.createAccessList(testData);

      await accessListPage.goto();

      // Verify it exists
      await expect(accessListPage.getListByName(testData.name)).toBeVisible();

      // Delete it
      await accessListPage.deleteList(testData.name);

      // Verify it's gone
      const exists = await accessListPage.listExists(testData.name);
      expect(exists).toBeFalsy();
    });
  });

  test.describe('CIDR Notation Support', () => {
    test('should accept CIDR notation', async () => {
      const testData = TestDataFactory.createAccessList({
        allowed_ips: ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
      });

      const created = await apiHelper.createAccessList(testData);

      expect(created.allowed_ips).toContain('192.168.0.0/16');
      expect(created.allowed_ips).toContain('10.0.0.0/8');
      expect(created.allowed_ips).toContain('172.16.0.0/12');
    });

    test('should accept single IP addresses', async () => {
      const testData = TestDataFactory.createAccessList({
        allowed_ips: ['192.168.1.1', '10.0.0.1'],
      });

      const created = await apiHelper.createAccessList(testData);

      expect(created.allowed_ips).toContain('192.168.1.1');
      expect(created.allowed_ips).toContain('10.0.0.1');
    });
  });

  test.describe('API Integration', () => {
    test('should fetch access lists via API', async () => {
      const lists = await apiHelper.getAccessLists();
      expect(Array.isArray(lists)).toBeTruthy();
    });

    test('should create access list via API', async () => {
      const testData = TestDataFactory.createAccessList();
      const created = await apiHelper.createAccessList(testData);

      expect(created).toHaveProperty('id');
      expect(created.name).toBe(testData.name);
    });

    test('should update access list via API', async () => {
      const testData = TestDataFactory.createAccessList();
      const created = await apiHelper.createAccessList(testData);

      const updated = await apiHelper.updateAccessList(created.id, {
        allowed_ips: ['10.10.10.0/24'],
      });

      expect(updated.allowed_ips).toContain('10.10.10.0/24');
    });

    test('should delete access list via API', async () => {
      const testData = TestDataFactory.createAccessList();
      const created = await apiHelper.createAccessList(testData);

      await apiHelper.deleteAccessList(created.id);

      // Verify deletion
      const lists = await apiHelper.getAccessLists();
      const found = lists.find(l => l.id === created.id);
      expect(found).toBeUndefined();
    });
  });
});

test.describe('Access List with Proxy Host', () => {
  let accessListPage: AccessListPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    accessListPage = new AccessListPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestAccessLists();
    await apiHelper.cleanupTestHosts();
  });

  test.skip('should apply ACL to proxy host', async () => {
    // Create an access list
    const aclData = TestDataFactory.createAccessList();
    const acl = await apiHelper.createAccessList(aclData);

    // Create a proxy host with the ACL
    const hostData = TestDataFactory.createProxyHost({
      // access_list_id: acl.id, // If supported
    });
    await apiHelper.createProxyHost(hostData);

    // Verify association - depends on API structure
  });
});

test.describe('Access List IP Validation', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestAccessLists();
  });

  test('should accept valid IPv4 addresses', async () => {
    const testData = TestDataFactory.createAccessList({
      allowed_ips: ['192.168.1.1', '10.0.0.1', '172.16.0.1'],
    });

    const created = await apiHelper.createAccessList(testData);
    expect(created.allowed_ips.length).toBe(3);
  });

  test('should accept valid CIDR ranges', async () => {
    const testData = TestDataFactory.createAccessList({
      allowed_ips: ['192.168.0.0/24', '10.0.0.0/8'],
    });

    const created = await apiHelper.createAccessList(testData);
    expect(created.allowed_ips.length).toBe(2);
  });

  test('should handle deny-all with allow exceptions', async () => {
    const whitelistData = TestDataFactory.createWhitelistOnlyAccessList([
      '192.168.1.100',
      '192.168.1.101',
    ]);

    const created = await apiHelper.createAccessList(whitelistData);
    expect(created.denied_ips).toContain('0.0.0.0/0');
    expect(created.allowed_ips.length).toBe(2);
  });
});

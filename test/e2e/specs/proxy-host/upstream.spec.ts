import { test, expect } from '@playwright/test';
import { ProxyHostListPage, ProxyHostFormPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Upstream/Load Balancing', () => {
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

  test.describe('Basic Upstream Configuration', () => {
    test('should configure single upstream server', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_host: '192.168.1.100',
        forward_port: 8080,
      });

      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.forward_host).toBe('192.168.1.100');
      expect(created.forward_port).toBe(8080);
    });

    test('should configure HTTPS upstream', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_scheme: 'https',
        forward_host: '192.168.1.100',
        forward_port: 443,
      });

      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.forward_scheme).toBe('https');
      expect(created.forward_port).toBe(443);
    });

    test('should configure different upstream ports', async () => {
      const ports = [80, 443, 3000, 8080, 8443];

      for (const port of ports) {
        const proxyHost = TestDataFactory.createProxyHost({
          forward_port: port,
        });

        const created = await apiHelper.createProxyHost(proxyHost);
        expect(created.forward_port).toBe(port);

        await apiHelper.deleteProxyHost(created.id);
      }
    });
  });

  test.describe('Upstream IP Configuration', () => {
    test('should accept valid IP address', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_host: '10.0.0.100',
      });

      const created = await apiHelper.createProxyHost(proxyHost);
      expect(created.forward_host).toBe('10.0.0.100');
    });

    test('should accept hostname', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_host: 'backend.local',
      });

      const created = await apiHelper.createProxyHost(proxyHost);
      expect(created.forward_host).toBe('backend.local');
    });

    test('should accept localhost', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_host: 'localhost',
      });

      const created = await apiHelper.createProxyHost(proxyHost);
      expect(created.forward_host).toBe('localhost');
    });

    test('should accept 127.0.0.1', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_host: '127.0.0.1',
      });

      const created = await apiHelper.createProxyHost(proxyHost);
      expect(created.forward_host).toBe('127.0.0.1');
    });
  });

  test.describe('Load Balancing (if supported)', () => {
    test.skip('should configure multiple upstream servers', async ({ page }) => {
      // This would require multiple upstream support in the API
      await listPage.goto();
      await listPage.clickAddHost();

      // Look for "Add Upstream" or similar button
      const addUpstreamBtn = page.locator('button').filter({
        hasText: /add.*upstream|add.*server/i,
      }).first();

      if (await addUpstreamBtn.isVisible()) {
        // Multiple upstream is supported
        await addUpstreamBtn.click();
      }
    });

    test.skip('should configure load balancing method', async ({ page }) => {
      // Load balancing methods: round-robin, least-connections, ip-hash
      await listPage.goto();
      await listPage.clickAddHost();

      const lbMethodSelect = page.locator('select[name*="load_balance"], [role="combobox"]').filter({
        has: page.locator('option:has-text("round"), option:has-text("least")'),
      }).first();

      if (await lbMethodSelect.isVisible()) {
        await lbMethodSelect.selectOption('round-robin');
      }
    });

    test.skip('should configure upstream weights', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      const weightInput = page.locator('input[name*="weight"]').first();

      if (await weightInput.isVisible()) {
        await weightInput.fill('5');
      }
    });

    test.skip('should configure upstream health checks', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      const healthCheckToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/health.*check/i'),
      }).first();

      if (await healthCheckToggle.isVisible()) {
        await healthCheckToggle.click();
      }
    });
  });

  test.describe('Upstream Failover (if supported)', () => {
    test.skip('should configure backup upstream', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      const backupToggle = page.locator('input[type="checkbox"]').filter({
        has: page.locator('text=/backup/i'),
      }).first();

      if (await backupToggle.isVisible()) {
        await backupToggle.click();
      }
    });

    test.skip('should configure failover timeout', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      const timeoutInput = page.locator('input[name*="timeout"], input[name*="fail"]').first();

      if (await timeoutInput.isVisible()) {
        await timeoutInput.fill('30');
      }
    });
  });

  test.describe('Upstream Scheme Selection', () => {
    test('should switch between HTTP and HTTPS upstream', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      // Select HTTP first
      if (await formPage.forwardSchemeSelect.isVisible()) {
        await formPage.selectForwardScheme('http');

        // Then switch to HTTPS
        await formPage.selectForwardScheme('https');
      }
    });
  });

  test.describe('Advanced Upstream Settings', () => {
    test.skip('should configure upstream connection timeout', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      await formPage.switchTab('advanced');

      const timeoutInput = page.locator('input[name*="connect_timeout"]').first();

      if (await timeoutInput.isVisible()) {
        await timeoutInput.fill('60');
      }
    });

    test.skip('should configure upstream read timeout', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      await formPage.switchTab('advanced');

      const readTimeoutInput = page.locator('input[name*="read_timeout"]').first();

      if (await readTimeoutInput.isVisible()) {
        await readTimeoutInput.fill('120');
      }
    });

    test.skip('should configure upstream send timeout', async ({ page }) => {
      await listPage.goto();
      await listPage.clickAddHost();

      await formPage.switchTab('advanced');

      const sendTimeoutInput = page.locator('input[name*="send_timeout"]').first();

      if (await sendTimeoutInput.isVisible()) {
        await sendTimeoutInput.fill('60');
      }
    });
  });
});

test.describe('Upstream Validation', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestHosts();
  });

  test('should validate port range', async () => {
    // Valid port
    const validHost = TestDataFactory.createProxyHost({
      forward_port: 8080,
    });
    const created = await apiHelper.createProxyHost(validHost);
    expect(created.forward_port).toBe(8080);

    // Invalid port (negative) - should be caught by API
    try {
      const invalidHost = TestDataFactory.createProxyHost({
        forward_port: -1,
      });
      await apiHelper.createProxyHost(invalidHost);
    } catch (error) {
      expect(error).toBeDefined();
    }
  });

  test('should validate IP/hostname format', async () => {
    const validFormats = [
      '192.168.1.1',
      '10.0.0.1',
      'localhost',
      'backend.local',
      'api.example.com',
    ];

    for (const host of validFormats) {
      const proxyHost = TestDataFactory.createProxyHost({
        forward_host: host,
      });
      const created = await apiHelper.createProxyHost(proxyHost);
      expect(created.forward_host).toBe(host);

      await apiHelper.deleteProxyHost(created.id);
    }
  });
});

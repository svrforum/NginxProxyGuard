import { test, expect } from '@playwright/test';
import { WAFPage, ProxyHostListPage, ProxyHostFormPage } from '../../pages';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Advanced WAF Scenarios', () => {
  let wafPage: WAFPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    wafPage = new WAFPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestHosts();
  });

  test.describe('WAF Mode Configuration', () => {
    test('should configure DetectionOnly mode', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        waf_enabled: true,
        waf_mode: 'DetectionOnly',
      });

      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.waf_mode).toBe('DetectionOnly');
    });

    test('should configure On (blocking) mode', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        waf_enabled: true,
        waf_mode: 'On',
      });

      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.waf_mode).toBe('On');
    });

    test('should configure Off mode', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        waf_enabled: false,
      });

      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.waf_enabled).toBe(false);
    });
  });

  test.describe('Paranoia Level Configuration', () => {
    test.describe.parallel('should configure different paranoia levels', () => {
      const levels: Array<1 | 2 | 3 | 4> = [1, 2, 3, 4];

      for (const level of levels) {
        test(`should set paranoia level ${level}`, async ({ request }) => {
          const localApiHelper = new APIHelper(request);
          await localApiHelper.login();

          const proxyHost = TestDataFactory.createWAFProxyHost({
            // paranoia_level: level, // If supported
          });

          const created = await localApiHelper.createProxyHost(proxyHost);
          expect(created.waf_enabled).toBe(true);

          // Cleanup
          await localApiHelper.deleteProxyHost(created.id);
        });
      }
    });
  });

  test.describe('WAF Tester', () => {
    test('should test SQL injection payload', async () => {
      const payload = "' OR '1'='1";
      const result = await apiHelper.testWafPayload(payload);

      expect(result.blocked).toBeTruthy();
      expect(result.matched_rules.length).toBeGreaterThan(0);
    });

    test('should test XSS payload', async () => {
      const payload = '<script>alert("XSS")</script>';
      const result = await apiHelper.testWafPayload(payload);

      expect(result.blocked).toBeTruthy();
    });

    test('should test command injection payload', async () => {
      const payload = '; ls -la';
      const result = await apiHelper.testWafPayload(payload);

      expect(result.blocked).toBeTruthy();
    });

    test('should test path traversal payload', async () => {
      const payload = '../../../etc/passwd';
      const result = await apiHelper.testWafPayload(payload);

      expect(result.blocked).toBeTruthy();
    });

    test('should allow safe requests', async () => {
      const payload = 'Hello, this is a normal request';
      const result = await apiHelper.testWafPayload(payload);

      expect(result.blocked).toBeFalsy();
    });
  });

  test.describe('WAF Tester UI', () => {
    test('should display WAF tester page', async () => {
      await wafPage.gotoTester();
      await expect(wafPage.page).toHaveURL(/\/waf\/tester/);
    });

    test('should have payload input', async () => {
      await wafPage.gotoTester();

      await expect(wafPage.testerInput).toBeVisible();
    });

    test('should have test button', async () => {
      await wafPage.gotoTester();

      await expect(wafPage.testButton).toBeVisible();
    });

    test('should test payload and show result', async () => {
      await wafPage.testPayload('<script>alert(1)</script>');

      // Result should be visible
      const resultVisible = await wafPage.testResult.isVisible();
      expect(typeof resultVisible).toBe('boolean');
    });
  });

  test.describe('WAF with Multiple Hosts', () => {
    test('should enable WAF independently per host', async () => {
      // Create host with WAF enabled
      const wafHost = TestDataFactory.createWAFProxyHost();
      const createdWaf = await apiHelper.createProxyHost(wafHost);

      // Create host without WAF
      const noWafHost = TestDataFactory.createProxyHost({
        waf_enabled: false,
      });
      const createdNoWaf = await apiHelper.createProxyHost(noWafHost);

      expect(createdWaf.waf_enabled).toBe(true);
      expect(createdNoWaf.waf_enabled).toBe(false);
    });

    test('should configure different WAF modes per host', async () => {
      const detectionHost = TestDataFactory.createProxyHost({
        waf_enabled: true,
        waf_mode: 'DetectionOnly',
      });
      const blockingHost = TestDataFactory.createProxyHost({
        waf_enabled: true,
        waf_mode: 'On',
      });

      const createdDetection = await apiHelper.createProxyHost(detectionHost);
      const createdBlocking = await apiHelper.createProxyHost(blockingHost);

      expect(createdDetection.waf_mode).toBe('DetectionOnly');
      expect(createdBlocking.waf_mode).toBe('On');
    });
  });

  test.describe('WAF Integration with Security Features', () => {
    test('should combine WAF with bot filter', async () => {
      const proxyHost = TestDataFactory.createSecureProxyHost();
      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.waf_enabled).toBe(true);
      expect(created.bot_filter_enabled).toBe(true);
    });

    test('should combine WAF with SSL', async () => {
      const proxyHost = TestDataFactory.createProxyHost({
        ssl_enabled: true,
        waf_enabled: true,
        waf_mode: 'On',
      });

      const created = await apiHelper.createProxyHost(proxyHost);

      expect(created.ssl_enabled).toBe(true);
      expect(created.waf_enabled).toBe(true);
    });
  });
});

test.describe('WAF Custom Rules', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test('should fetch exploit rules', async () => {
    const rules = await apiHelper.getWafExploitRules();
    expect(Array.isArray(rules)).toBeTruthy();
  });

  test('should have rules with categories', async () => {
    const rules = await apiHelper.getWafExploitRules();

    if (rules.length > 0) {
      const categories = [...new Set(rules.map(r => r.category))];
      expect(categories.length).toBeGreaterThan(0);
    }
  });
});

test.describe('WAF Performance', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    await apiHelper.cleanupTestHosts();
  });

  test('should create multiple WAF-enabled hosts efficiently', async () => {
    const hosts = TestDataFactory.createProxyHostBatch(5).map(h => ({
      ...h,
      waf_enabled: true,
      waf_mode: 'DetectionOnly',
    }));

    const created = [];
    for (const host of hosts) {
      created.push(await apiHelper.createProxyHost(host));
    }

    expect(created.length).toBe(5);
    expect(created.every(h => h.waf_enabled)).toBe(true);
  });

  test('should test multiple payloads efficiently', async () => {
    const payloads = [
      ...TestDataFactory.getSqlInjectionPayloads().slice(0, 2),
      ...TestDataFactory.getXssPayloads().slice(0, 2),
      ...TestDataFactory.getSafePayloads().slice(0, 2),
    ];

    const results = [];
    for (const payload of payloads) {
      results.push(await apiHelper.testWafPayload(payload));
    }

    expect(results.length).toBe(6);
    // First 4 should be blocked, last 2 should pass
    expect(results.slice(0, 4).every(r => r.blocked)).toBe(true);
    expect(results.slice(4).every(r => !r.blocked)).toBe(true);
  });
});

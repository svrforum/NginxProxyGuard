import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { TestDataFactory } from '../../utils/test-data-factory';

test.describe('Global Trusted IPs', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Clear trusted IPs after each test
    try {
      await apiHelper.updateGlobalSettings({ global_trusted_ips: '' });
    } catch {
      // Ignore cleanup errors
    }
  });

  test.describe('Set Trusted IPs via API', () => {
    test('should set a single trusted IP', async () => {
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: '192.168.1.100',
      });

      const settings = await apiHelper.getGlobalSettings();
      expect(settings.global_trusted_ips).toBe('192.168.1.100');
    });

    test('should set trusted IP with CIDR notation', async () => {
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: '10.0.0.0/24',
      });

      const settings = await apiHelper.getGlobalSettings();
      expect(settings.global_trusted_ips).toBe('10.0.0.0/24');
    });

    test('should set multiple trusted IPs (newline-separated)', async () => {
      const trustedIps = '192.168.1.100\n10.0.0.0/24\n172.16.0.1';
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: trustedIps,
      });

      const settings = await apiHelper.getGlobalSettings();
      expect(settings.global_trusted_ips).toBe(trustedIps);
    });

    test('should clear trusted IPs', async () => {
      // Set first
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: '192.168.1.100',
      });

      // Clear
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: '',
      });

      const settings = await apiHelper.getGlobalSettings();
      expect(settings.global_trusted_ips || '').toBe('');
    });
  });

  test.describe('Comment Lines and Invalid IPs', () => {
    test('should accept comment lines starting with #', async () => {
      const trustedIps = '# Office network\n192.168.1.0/24\n# VPN\n10.0.0.1';
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: trustedIps,
      });

      const settings = await apiHelper.getGlobalSettings();
      expect(settings.global_trusted_ips).toBe(trustedIps);

      // Config generation should succeed (comments are ignored)
      const syncResult = await apiHelper.syncAllConfigs();
      expect(syncResult.test_success).toBe(true);
      expect(syncResult.reload_success).toBe(true);
    });

    test('should handle invalid IP formats gracefully', async () => {
      const trustedIps = 'not-an-ip\n192.168.1.100\nabc.def.ghi.jkl';
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: trustedIps,
      });

      // Config generation should still succeed (invalid entries filtered out)
      const syncResult = await apiHelper.syncAllConfigs();
      expect(syncResult.test_success).toBe(true);
      expect(syncResult.reload_success).toBe(true);
    });
  });

  test.describe('Trusted IPs with Banned IPs', () => {
    const testIp = '192.168.50.50';

    test.afterEach(async () => {
      try {
        const bannedIps = await apiHelper.getWafBannedIps();
        const entry = bannedIps.find(b => b.ip_address === testIp);
        if (entry) {
          await apiHelper.unbanIp(entry.id);
        }
      } catch {
        // Ignore cleanup errors
      }
      await apiHelper.cleanupTestHosts();
    });

    test('should coexist with banned IPs without breaking nginx config', async () => {
      // Set the IP as both trusted and banned
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: testIp,
      });
      await apiHelper.banIp(testIp, 'Test ban for trusted IP');

      // Verify both exist
      const settings = await apiHelper.getGlobalSettings();
      expect(settings.global_trusted_ips).toContain(testIp);

      const bannedIps = await apiHelper.getWafBannedIps();
      const found = bannedIps.find(b => b.ip_address === testIp);
      expect(found).toBeDefined();

      // Sync should succeed - trusted IP bypasses security
      const syncResult = await apiHelper.syncAllConfigs();
      expect(syncResult.test_success).toBe(true);
      expect(syncResult.reload_success).toBe(true);
    });
  });

  test.describe('Config Generation with Trusted IPs', () => {
    test.afterEach(async () => {
      await apiHelper.cleanupTestHosts();
    });

    test('should generate valid nginx config with trusted IPs and proxy host', async () => {
      // Set trusted IPs
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: '192.168.1.0/24\n10.0.0.0/8',
      });

      // Create a proxy host with WAF enabled
      const testData = TestDataFactory.createProxyHost({
        waf_enabled: true,
      });
      await apiHelper.createProxyHost(testData);

      // Sync should succeed
      const syncResult = await apiHelper.syncAllConfigs();
      expect(syncResult.test_success).toBe(true);
      expect(syncResult.reload_success).toBe(true);
    });

    test('should handle empty trusted IPs with active proxy hosts', async () => {
      await apiHelper.updateGlobalSettings({
        global_trusted_ips: '',
      });

      const testData = TestDataFactory.createProxyHost();
      await apiHelper.createProxyHost(testData);

      const syncResult = await apiHelper.syncAllConfigs();
      expect(syncResult.test_success).toBe(true);
      expect(syncResult.reload_success).toBe(true);
    });
  });
});

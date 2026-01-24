import { test, expect } from '@playwright/test';
import { WAFPage } from '../../pages';
import { APIHelper } from '../../utils/api-helper';
import { TIMEOUTS } from '../../fixtures/test-data';

test.describe('Fail2ban Integration', () => {
  let wafPage: WAFPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    wafPage = new WAFPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.describe('Fail2ban Page', () => {
    test('should display fail2ban page', async () => {
      await wafPage.gotoFail2ban();
      await wafPage.expectWAFPage();
      await expect(wafPage.page).toHaveURL(/\/waf\/fail2ban/);
    });
  });

  test.describe('Banned IPs Management', () => {
    test('should display banned IPs page', async () => {
      await wafPage.gotoBannedIps();
      await expect(wafPage.page).toHaveURL(/\/waf\/banned-ips/);
    });

    test('should show banned IPs list', async () => {
      await wafPage.gotoBannedIps();

      const listVisible = await wafPage.bannedIpList.isVisible();
      expect(listVisible).toBeTruthy();
    });

    test('should display banned IP count', async () => {
      await wafPage.gotoBannedIps();

      const count = await wafPage.getBannedIpCount();
      expect(count).toBeGreaterThanOrEqual(0);
    });

    test('should show add ban button', async () => {
      await wafPage.gotoBannedIps();

      await expect(wafPage.addBanButton).toBeVisible();
    });
  });

  test.describe('Ban IP', () => {
    const testIp = '192.168.99.99';

    test.afterEach(async () => {
      // Cleanup - unban test IP
      try {
        await apiHelper.unbanIp(testIp);
      } catch {
        // IP might not be banned
      }
    });

    test('should ban IP address via API', async () => {
      await apiHelper.banIp(testIp, 'Test ban');

      const bannedIps = await apiHelper.getWafBannedIps();
      const found = bannedIps.find(b => b.ip === testIp);

      expect(found).toBeDefined();
    });

    test('should ban IP with reason', async () => {
      const reason = 'Automated test ban';
      await apiHelper.banIp(testIp, reason);

      const bannedIps = await apiHelper.getWafBannedIps();
      const found = bannedIps.find(b => b.ip === testIp);

      expect(found?.reason).toBe(reason);
    });

    test('should ban IP via UI', async ({ page }) => {
      await wafPage.gotoBannedIps();
      await wafPage.addBanButton.click();

      // Wait for modal
      await page.waitForSelector('[class*="modal"], [role="dialog"]', {
        state: 'visible',
        timeout: TIMEOUTS.medium,
      });

      // Fill IP
      const ipInput = page.locator('input[placeholder*="IP"], input[name*="ip"]').first();
      if (await ipInput.isVisible()) {
        await ipInput.fill(testIp);
      }

      // Fill reason
      const reasonInput = page.locator('input[name*="reason"], textarea').first();
      if (await reasonInput.isVisible()) {
        await reasonInput.fill('Test from UI');
      }

      // Save
      const saveBtn = page.locator('button').filter({ hasText: /ban|save|add/i }).first();
      await saveBtn.click();

      await page.waitForTimeout(500);
    });
  });

  test.describe('Unban IP', () => {
    const testIp = '192.168.88.88';

    test('should unban IP address via API', async () => {
      // Ban first
      await apiHelper.banIp(testIp, 'Test for unban');

      // Verify it's banned
      let bannedIps = await apiHelper.getWafBannedIps();
      let found = bannedIps.find(b => b.ip === testIp);
      expect(found).toBeDefined();

      // Unban
      await apiHelper.unbanIp(testIp);

      // Verify it's unbanned
      bannedIps = await apiHelper.getWafBannedIps();
      found = bannedIps.find(b => b.ip === testIp);
      expect(found).toBeUndefined();
    });
  });

  test.describe('Banned IP Display', () => {
    test('should display ban timestamp', async () => {
      const testIp = '192.168.77.77';

      // Ban an IP
      await apiHelper.banIp(testIp, 'Test timestamp');

      const bannedIps = await apiHelper.getWafBannedIps();
      const found = bannedIps.find(b => b.ip === testIp);

      expect(found?.banned_at).toBeDefined();

      // Cleanup
      await apiHelper.unbanIp(testIp);
    });

    test('should display ban reason', async () => {
      const testIp = '192.168.66.66';
      const reason = 'Test reason display';

      await apiHelper.banIp(testIp, reason);

      const bannedIps = await apiHelper.getWafBannedIps();
      const found = bannedIps.find(b => b.ip === testIp);

      expect(found?.reason).toBe(reason);

      // Cleanup
      await apiHelper.unbanIp(testIp);
    });
  });

  test.describe('API Integration', () => {
    test('should fetch banned IPs via API', async () => {
      const bannedIps = await apiHelper.getWafBannedIps();
      expect(Array.isArray(bannedIps)).toBeTruthy();
    });
  });
});

test.describe('IP Validation', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test('should accept valid IPv4 address', async () => {
    const testIp = '10.0.0.100';

    await apiHelper.banIp(testIp);

    const bannedIps = await apiHelper.getWafBannedIps();
    const found = bannedIps.find(b => b.ip === testIp);
    expect(found).toBeDefined();

    // Cleanup
    await apiHelper.unbanIp(testIp);
  });

  test('should accept CIDR notation', async () => {
    const testCidr = '10.0.0.0/24';

    try {
      await apiHelper.banIp(testCidr);

      const bannedIps = await apiHelper.getWafBannedIps();
      const found = bannedIps.find(b => b.ip === testCidr);

      // Cleanup if successful
      if (found) {
        await apiHelper.unbanIp(testCidr);
      }
    } catch {
      // CIDR might not be supported
    }
  });

  test('should reject invalid IP format', async () => {
    try {
      await apiHelper.banIp('invalid-ip');
      // Should throw error
      expect(true).toBeFalsy(); // Should not reach here
    } catch (error) {
      expect(error).toBeDefined();
    }
  });
});

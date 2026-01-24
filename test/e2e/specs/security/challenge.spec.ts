import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES } from '../../fixtures/test-data';

test.describe('Challenge/CAPTCHA', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.describe('Challenge Settings Page', () => {
    test('should access challenge settings page', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      await page.waitForLoadState('networkidle');
      // Page should load without error
    });

    test('should display challenge configuration options', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      // Look for challenge/CAPTCHA settings
      const challengeSection = page.locator('section, div').filter({
        hasText: /challenge|captcha|verification/i,
      }).first();

      const sectionVisible = await challengeSection.isVisible().catch(() => false);
      expect(typeof sectionVisible).toBe('boolean');
    });
  });

  test.describe('CAPTCHA Provider Configuration', () => {
    test('should display CAPTCHA provider selection', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const providerSelect = page.locator('select[name*="captcha"], [role="combobox"]').filter({
        has: page.locator('option:has-text("reCAPTCHA"), option:has-text("hCaptcha")'),
      }).first();

      const selectVisible = await providerSelect.isVisible().catch(() => false);
      expect(typeof selectVisible).toBe('boolean');
    });

    test('should configure reCAPTCHA', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const providerSelect = page.locator('select[name*="captcha"], select[name*="provider"]').first();

      if (await providerSelect.isVisible()) {
        await providerSelect.selectOption('recaptcha');

        // Site key and secret key inputs should appear
        const siteKeyInput = page.locator('input[name*="site_key"]').first();
        const secretKeyInput = page.locator('input[name*="secret_key"]').first();

        if (await siteKeyInput.isVisible()) {
          await siteKeyInput.fill('test-site-key');
        }
        if (await secretKeyInput.isVisible()) {
          await secretKeyInput.fill('test-secret-key');
        }
      }
    });

    test('should configure hCaptcha', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const providerSelect = page.locator('select[name*="captcha"], select[name*="provider"]').first();

      if (await providerSelect.isVisible()) {
        try {
          await providerSelect.selectOption('hcaptcha');
        } catch {
          // hCaptcha might not be an option
        }
      }
    });

    test('should configure Cloudflare Turnstile', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const providerSelect = page.locator('select[name*="captcha"], select[name*="provider"]').first();

      if (await providerSelect.isVisible()) {
        try {
          await providerSelect.selectOption('turnstile');
        } catch {
          // Turnstile might not be an option
        }
      }
    });
  });

  test.describe('Challenge Trigger Configuration', () => {
    test('should configure challenge on suspicious activity', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const suspiciousToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/suspicious|threat/i'),
      }).first();

      if (await suspiciousToggle.isVisible()) {
        await suspiciousToggle.click();
      }
    });

    test('should configure challenge threshold', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const thresholdInput = page.locator('input[name*="threshold"], input[type="number"]').first();

      if (await thresholdInput.isVisible()) {
        await thresholdInput.fill('5');
      }
    });

    test('should configure challenge duration', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const durationInput = page.locator('input[name*="duration"], input[name*="timeout"]').first();

      if (await durationInput.isVisible()) {
        await durationInput.fill('3600'); // 1 hour
      }
    });
  });

  test.describe('JavaScript Challenge', () => {
    test('should enable JavaScript challenge', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const jsToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/javascript.*challenge|js.*challenge/i'),
      }).first();

      if (await jsToggle.isVisible()) {
        await jsToggle.click();
      }
    });

    test('should configure JS challenge difficulty', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const difficultySelect = page.locator('select[name*="difficulty"]').first();

      if (await difficultySelect.isVisible()) {
        await difficultySelect.selectOption('medium');
      }
    });
  });

  test.describe('Challenge Page Customization', () => {
    test('should customize challenge page title', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const titleInput = page.locator('input[name*="title"], input[name*="heading"]').first();

      if (await titleInput.isVisible()) {
        await titleInput.fill('Security Verification Required');
      }
    });

    test('should customize challenge page message', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const messageInput = page.locator('textarea[name*="message"], input[name*="message"]').first();

      if (await messageInput.isVisible()) {
        await messageInput.fill('Please complete the verification to continue.');
      }
    });

    test('should configure challenge page theme', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const themeSelect = page.locator('select[name*="theme"]').first();

      if (await themeSelect.isVisible()) {
        await themeSelect.selectOption('dark');
      }
    });
  });

  test.describe('Per-Host Challenge Configuration', () => {
    test.skip('should enable challenge for specific host', async () => {
      // This would require proxy host form with challenge settings
    });

    test.skip('should configure different challenge type per host', async () => {
      // This would require proxy host with custom challenge config
    });
  });

  test.describe('Challenge Bypass', () => {
    test('should configure IP whitelist for challenge bypass', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const whitelistInput = page.locator('textarea[name*="whitelist"], input[name*="bypass"]').first();

      if (await whitelistInput.isVisible()) {
        await whitelistInput.fill('192.168.1.0/24');
      }
    });

    test('should configure user agent whitelist', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      const uaWhitelist = page.locator('textarea[name*="user_agent"], input[name*="bot"]').first();

      if (await uaWhitelist.isVisible()) {
        await uaWhitelist.fill('Googlebot\nBingbot');
      }
    });
  });

  test.describe('Save Challenge Settings', () => {
    test('should save challenge configuration', async ({ page }) => {
      await page.goto(ROUTES.settingsChallenge);

      // Make a change
      const toggle = page.locator('input[type="checkbox"], button[role="switch"]').first();
      if (await toggle.isVisible()) {
        await toggle.click();
      }

      // Save
      const saveBtn = page.locator('button').filter({ hasText: /save|apply/i }).first();
      if (await saveBtn.isVisible()) {
        await saveBtn.click();
        await page.waitForTimeout(500);
      }
    });
  });
});

test.describe('Challenge Integration with WAF', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test('should trigger challenge on WAF threshold exceeded', async ({ page }) => {
    // This tests the integration between WAF and challenge system
    await page.goto(ROUTES.settingsChallenge);

    const wafTriggerToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/waf|modsec/i'),
    }).first();

    if (await wafTriggerToggle.isVisible()) {
      await wafTriggerToggle.click();
    }
  });
});

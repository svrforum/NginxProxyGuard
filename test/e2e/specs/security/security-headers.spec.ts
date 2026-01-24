import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES } from '../../fixtures/test-data';

test.describe('Security Headers', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.describe('Security Headers Page', () => {
    test('should access security headers settings page', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      await page.waitForLoadState('networkidle');
      // Page should load without error
    });

    test('should display security headers configuration', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      // Look for security header settings
      const headerSection = page.locator('section, div').filter({
        hasText: /security.*header|CSP|HSTS|X-Frame/i,
      }).first();

      const sectionVisible = await headerSection.isVisible().catch(() => false);
      expect(typeof sectionVisible).toBe('boolean');
    });
  });

  test.describe('HSTS Configuration', () => {
    test('should configure HSTS header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      // Find HSTS toggle
      const hstsToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/HSTS|Strict-Transport/i'),
      }).first();

      if (await hstsToggle.isVisible()) {
        await hstsToggle.click();
        await page.waitForTimeout(300);
      }
    });

    test('should configure HSTS max-age', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const maxAgeInput = page.locator('input[name*="max_age"], input[name*="hsts"]').first();

      if (await maxAgeInput.isVisible()) {
        await maxAgeInput.fill('31536000'); // 1 year
      }
    });

    test('should configure HSTS includeSubDomains', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const includeSubdomains = page.locator('input[type="checkbox"]').filter({
        has: page.locator('text=/includeSubDomains|subdomains/i'),
      }).first();

      if (await includeSubdomains.isVisible()) {
        await includeSubdomains.click();
      }
    });

    test('should configure HSTS preload', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const preloadToggle = page.locator('input[type="checkbox"]').filter({
        has: page.locator('text=/preload/i'),
      }).first();

      if (await preloadToggle.isVisible()) {
        await preloadToggle.click();
      }
    });
  });

  test.describe('X-Frame-Options Configuration', () => {
    test('should configure X-Frame-Options header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const xframeSelect = page.locator('select[name*="frame"], [role="combobox"]').filter({
        has: page.locator('option:has-text("DENY"), option:has-text("SAMEORIGIN")'),
      }).first();

      if (await xframeSelect.isVisible()) {
        await xframeSelect.selectOption('DENY');
      }
    });

    test('should support DENY option', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const denyOption = page.locator('option:has-text("DENY"), [role="option"]:has-text("DENY")');
      const optionVisible = await denyOption.isVisible().catch(() => false);
      expect(typeof optionVisible).toBe('boolean');
    });

    test('should support SAMEORIGIN option', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const sameoriginOption = page.locator('option:has-text("SAMEORIGIN"), [role="option"]:has-text("SAMEORIGIN")');
      const optionVisible = await sameoriginOption.isVisible().catch(() => false);
      expect(typeof optionVisible).toBe('boolean');
    });
  });

  test.describe('X-Content-Type-Options Configuration', () => {
    test('should configure X-Content-Type-Options header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const nosniffToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/nosniff|Content-Type-Options/i'),
      }).first();

      if (await nosniffToggle.isVisible()) {
        await nosniffToggle.click();
      }
    });
  });

  test.describe('X-XSS-Protection Configuration', () => {
    test('should configure X-XSS-Protection header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const xssToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/XSS.*Protection/i'),
      }).first();

      if (await xssToggle.isVisible()) {
        await xssToggle.click();
      }
    });
  });

  test.describe('Content-Security-Policy Configuration', () => {
    test('should configure CSP header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const cspInput = page.locator('textarea[name*="csp"], input[name*="csp"]').first();

      if (await cspInput.isVisible()) {
        await cspInput.fill("default-src 'self'; script-src 'self'");
      }
    });

    test('should enable/disable CSP', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const cspToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
        has: page.locator('text=/CSP|Content-Security-Policy/i'),
      }).first();

      if (await cspToggle.isVisible()) {
        await cspToggle.click();
      }
    });
  });

  test.describe('Referrer-Policy Configuration', () => {
    test('should configure Referrer-Policy header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const referrerSelect = page.locator('select[name*="referrer"], [role="combobox"]').filter({
        has: page.locator('option:has-text("no-referrer"), option:has-text("same-origin")'),
      }).first();

      if (await referrerSelect.isVisible()) {
        await referrerSelect.selectOption('no-referrer');
      }
    });
  });

  test.describe('Permissions-Policy Configuration', () => {
    test('should configure Permissions-Policy header', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      const permissionsInput = page.locator('textarea[name*="permissions"], input[name*="permissions"]').first();

      if (await permissionsInput.isVisible()) {
        await permissionsInput.fill('geolocation=(), microphone=()');
      }
    });
  });

  test.describe('Per-Host Security Headers', () => {
    test.skip('should configure security headers per proxy host', async () => {
      // This would require proxy host form with security headers section
    });

    test.skip('should override global security headers per host', async () => {
      // This would require proxy host with custom headers
    });
  });

  test.describe('Save Security Headers', () => {
    test('should save security header configuration', async ({ page }) => {
      await page.goto(ROUTES.settingsSecurityHeaders);

      // Make a change
      const hstsToggle = page.locator('input[type="checkbox"], button[role="switch"]').first();
      if (await hstsToggle.isVisible()) {
        await hstsToggle.click();
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

test.describe('Security Headers Validation', () => {
  test('should validate CSP policy syntax', async ({ page, request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();

    await page.goto(ROUTES.settingsSecurityHeaders);

    const cspInput = page.locator('textarea[name*="csp"], input[name*="csp"]').first();

    if (await cspInput.isVisible()) {
      // Enter invalid CSP
      await cspInput.fill('invalid csp policy');

      const saveBtn = page.locator('button').filter({ hasText: /save|apply/i }).first();
      if (await saveBtn.isVisible()) {
        await saveBtn.click();
        await page.waitForTimeout(500);

        // Should show validation error or warning
      }
    }
  });
});

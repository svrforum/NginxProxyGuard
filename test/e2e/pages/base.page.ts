import { Page, Locator, expect } from '@playwright/test';
import { TIMEOUTS } from '../fixtures/test-data';

/**
 * Base page class with common functionality for all pages.
 */
export abstract class BasePage {
  readonly page: Page;

  // Common navigation elements
  readonly header: Locator;
  readonly navDashboard: Locator;
  readonly navProxyHosts: Locator;
  readonly navRedirects: Locator;
  readonly navWaf: Locator;
  readonly navAccess: Locator;
  readonly navCertificates: Locator;
  readonly navLogs: Locator;
  readonly navSettings: Locator;

  // Header actions
  readonly syncAllButton: Locator;
  readonly darkModeToggle: Locator;
  readonly userMenuButton: Locator;
  readonly logoutButton: Locator;
  readonly versionText: Locator;

  constructor(page: Page) {
    this.page = page;

    // Header
    this.header = page.locator('header');

    // Navigation tabs (based on translation keys or button text patterns)
    this.navDashboard = page.locator('nav button').filter({ hasText: /dashboard/i }).first();
    this.navProxyHosts = page.locator('nav button').filter({ hasText: /proxy.*host|hosts/i }).first();
    this.navRedirects = page.locator('nav button').filter({ hasText: /redirect/i }).first();
    this.navWaf = page.locator('nav button').filter({ hasText: /waf/i }).first();
    this.navAccess = page.locator('nav button').filter({ hasText: /access/i }).first();
    this.navCertificates = page.locator('nav button').filter({ hasText: /certificate|ssl/i }).first();
    this.navLogs = page.locator('nav button').filter({ hasText: /log/i }).first();
    this.navSettings = page.locator('nav button').filter({ hasText: /setting/i }).first();

    // Header actions
    this.syncAllButton = page.locator('header button[title*="Sync"]').first();
    this.darkModeToggle = page.locator('header button[title*="Mode"]').first();
    this.userMenuButton = page.locator('header button').filter({ hasText: TEST_CREDENTIALS_PATTERN });
    this.logoutButton = page.locator('header button').filter({ hasText: /logout|sign.*out/i });
    this.versionText = page.locator('header').locator('text=/v\\d+\\.\\d+\\.\\d+/');
  }

  /**
   * Navigate to a specific route.
   */
  async goto(path: string = '/'): Promise<void> {
    await this.page.goto(path);
    await this.waitForPageLoad();
  }

  /**
   * Wait for the page to fully load.
   */
  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle', { timeout: TIMEOUTS.long });
  }

  /**
   * Click Sync All button and wait for completion.
   */
  async clickSyncAll(): Promise<void> {
    await this.syncAllButton.click();
    // Wait for sync modal to appear and complete
    await this.page.waitForSelector('[class*="modal"], [role="dialog"]', {
      state: 'visible',
      timeout: TIMEOUTS.medium,
    });
    // Wait for sync to complete (spinner to stop or success message)
    await this.page.waitForFunction(
      () => {
        const spinner = document.querySelector('[class*="animate-spin"]');
        return !spinner || !spinner.closest('[class*="modal"], [role="dialog"]');
      },
      { timeout: TIMEOUTS.veryLong }
    );
  }

  /**
   * Navigate to Dashboard.
   */
  async gotoDashboard(): Promise<void> {
    await this.navDashboard.click();
    await this.page.waitForURL(/\/dashboard/);
  }

  /**
   * Navigate to Proxy Hosts.
   */
  async gotoProxyHosts(): Promise<void> {
    await this.navProxyHosts.click();
    await this.page.waitForURL(/\/proxy-hosts/);
  }

  /**
   * Navigate to WAF settings.
   */
  async gotoWaf(): Promise<void> {
    await this.navWaf.click();
    await this.page.waitForURL(/\/waf/);
  }

  /**
   * Navigate to Certificates.
   */
  async gotoCertificates(): Promise<void> {
    await this.navCertificates.click();
    await this.page.waitForURL(/\/certificates/);
  }

  /**
   * Navigate to Logs.
   */
  async gotoLogs(): Promise<void> {
    await this.navLogs.click();
    await this.page.waitForURL(/\/logs/);
  }

  /**
   * Navigate to Settings.
   */
  async gotoSettings(): Promise<void> {
    await this.navSettings.click();
    await this.page.waitForURL(/\/settings/);
  }

  /**
   * Logout from the application.
   */
  async logout(): Promise<void> {
    await this.logoutButton.click();
    // Wait for redirect to login page
    await this.page.waitForURL(/^(\/)?$/);
  }

  /**
   * Toggle dark mode.
   */
  async toggleDarkMode(): Promise<void> {
    await this.darkModeToggle.click();
  }

  /**
   * Check if a toast notification is visible with specific text.
   */
  async expectToast(text: string | RegExp): Promise<void> {
    const toast = this.page.locator('[class*="toast"], [role="alert"], [class*="notification"]');
    await expect(toast.filter({ hasText: text })).toBeVisible({ timeout: TIMEOUTS.medium });
  }

  /**
   * Wait for and close any modal dialogs.
   */
  async closeModal(): Promise<void> {
    const closeButton = this.page.locator('[class*="modal"] button[aria-label*="close"], [role="dialog"] button:has(svg)').first();
    if (await closeButton.isVisible()) {
      await closeButton.click();
      await this.page.waitForSelector('[class*="modal"], [role="dialog"]', { state: 'hidden' });
    }
  }

  /**
   * Get current logged in username from header.
   */
  async getLoggedInUser(): Promise<string> {
    const userButton = this.page.locator('header button').filter({ has: this.page.locator('.text-sm.font-medium') });
    return await userButton.locator('.text-sm.font-medium').textContent() || '';
  }
}

// Pattern to match username in header (used for locating user menu)
const TEST_CREDENTIALS_PATTERN = /admin|user/i;

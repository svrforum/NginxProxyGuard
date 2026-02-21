import { Page, Locator, expect } from '@playwright/test';
import { TIMEOUTS } from '../fixtures/test-data';

/**
 * Login page object model.
 */
export class LoginPage {
  readonly page: Page;

  // Login form elements
  readonly usernameInput: Locator;
  readonly passwordInput: Locator;
  readonly submitButton: Locator;
  readonly errorMessage: Locator;
  readonly loadingSpinner: Locator;

  // 2FA elements
  readonly totpInput: Locator;
  readonly totpSubmitButton: Locator;
  readonly backToLoginButton: Locator;

  // Page elements
  readonly logo: Locator;
  readonly title: Locator;
  readonly subtitle: Locator;
  readonly languageSwitcher: Locator;

  constructor(page: Page) {
    this.page = page;

    // Login form
    this.usernameInput = page.locator('input#username, input[name="username"], input[type="text"]').first();
    this.passwordInput = page.locator('input#password, input[name="password"], input[type="password"]').first();
    this.submitButton = page.locator('button[type="submit"]').first();
    this.errorMessage = page.locator('.bg-red-50, [class*="error"], [role="alert"]').first();
    this.loadingSpinner = page.locator('.animate-spin');

    // 2FA elements (shown after initial login if 2FA enabled)
    this.totpInput = page.locator('input[maxlength="6"]');
    this.totpSubmitButton = page.locator('form:has(input[maxlength="6"]) button[type="submit"]');
    this.backToLoginButton = page.locator('button').filter({ hasText: /back/i });

    // Page elements
    this.logo = page.locator('header img, .logo, svg').first();
    this.title = page.locator('h1').filter({ hasText: /nginx.*proxy.*guard/i });
    this.subtitle = page.locator('text=Secure Reverse Proxy Manager');
    this.languageSwitcher = page.locator('[class*="language"], button:has-text("English"), button:has-text("한국어")');
  }

  /**
   * Navigate to the login page.
   */
  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Fill in username field.
   */
  async fillUsername(username: string): Promise<void> {
    await this.usernameInput.fill(username);
  }

  /**
   * Fill in password field.
   */
  async fillPassword(password: string): Promise<void> {
    await this.passwordInput.fill(password);
  }

  /**
   * Click the login button.
   */
  async clickLogin(): Promise<void> {
    await this.submitButton.click();
  }

  /**
   * Perform complete login flow.
   */
  async login(username: string, password: string): Promise<void> {
    await this.fillUsername(username);
    await this.fillPassword(password);
    await this.clickLogin();

    // Wait for either navigation or error
    // Use a longer timeout to accommodate React auth state machine processing
    await Promise.race([
      this.page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.long }),
      this.errorMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.long }).catch(() => null),
    ]);

    // If still on login page without error, wait a bit more for React navigation
    const url = this.page.url();
    if (!url.includes('/dashboard') && !url.includes('/proxy-hosts')) {
      const hasError = await this.errorMessage.isVisible().catch(() => false);
      if (!hasError) {
        await this.page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.medium });
      }
    }
  }

  /**
   * Fill in TOTP code for 2FA.
   */
  async fillTotpCode(code: string): Promise<void> {
    await this.totpInput.fill(code);
  }

  /**
   * Submit TOTP code for 2FA.
   */
  async submitTotpCode(): Promise<void> {
    await this.totpSubmitButton.click();
  }

  /**
   * Complete 2FA verification.
   */
  async verify2FA(code: string): Promise<void> {
    await this.fillTotpCode(code);
    await this.submitTotpCode();
    await this.page.waitForURL(/\/(dashboard|proxy-hosts)/, { timeout: TIMEOUTS.long });
  }

  /**
   * Check if we're on the 2FA verification step.
   */
  async is2FARequired(): Promise<boolean> {
    return await this.totpInput.isVisible();
  }

  /**
   * Get the error message text.
   */
  async getErrorMessage(): Promise<string> {
    if (await this.errorMessage.isVisible()) {
      return await this.errorMessage.textContent() || '';
    }
    return '';
  }

  /**
   * Check if loading spinner is visible.
   */
  async isLoading(): Promise<boolean> {
    return await this.loadingSpinner.isVisible();
  }

  /**
   * Verify that the login page is displayed correctly.
   */
  async expectLoginPage(options?: { timeout?: number }): Promise<void> {
    const timeout = options?.timeout || TIMEOUTS.medium;
    await expect(this.title).toBeVisible({ timeout });
    await expect(this.usernameInput).toBeVisible({ timeout });
    await expect(this.passwordInput).toBeVisible({ timeout });
    await expect(this.submitButton).toBeVisible({ timeout });
  }

  /**
   * Verify that an error message is displayed.
   */
  async expectError(message?: string | RegExp): Promise<void> {
    await expect(this.errorMessage).toBeVisible();
    if (message) {
      await expect(this.errorMessage).toContainText(message);
    }
  }

  /**
   * Switch language on login page.
   */
  async switchLanguage(): Promise<void> {
    if (await this.languageSwitcher.isVisible()) {
      await this.languageSwitcher.click();
    }
  }
}

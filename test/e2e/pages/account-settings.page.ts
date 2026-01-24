import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Account Settings page object model.
 */
export class AccountSettingsPage extends BasePage {
  // Page elements
  readonly pageTitle: Locator;

  // Profile section
  readonly usernameDisplay: Locator;
  readonly emailInput: Locator;
  readonly changeUsernameButton: Locator;

  // Password section
  readonly currentPasswordInput: Locator;
  readonly newPasswordInput: Locator;
  readonly confirmPasswordInput: Locator;
  readonly changePasswordButton: Locator;

  // 2FA section
  readonly twoFactorSection: Locator;
  readonly twoFactorToggle: Locator;
  readonly setupTwoFactorButton: Locator;
  readonly disableTwoFactorButton: Locator;
  readonly qrCodeImage: Locator;
  readonly verificationCodeInput: Locator;
  readonly verifyCodeButton: Locator;
  readonly backupCodesDisplay: Locator;

  // Preferences section
  readonly languageSelect: Locator;
  readonly fontSelect: Locator;
  readonly themeSelect: Locator;
  readonly timezoneSelect: Locator;

  // Actions
  readonly saveButton: Locator;
  readonly cancelButton: Locator;

  // Status messages
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /account|profile/i }).first();

    // Profile section
    this.usernameDisplay = page.locator('text=/username|user/i').locator('..').locator('.font-medium, span').first();
    this.emailInput = page.locator('input[type="email"], input[name*="email"]').first();
    this.changeUsernameButton = page.locator('button').filter({ hasText: /change.*username|edit.*username/i }).first();

    // Password section
    this.currentPasswordInput = page.locator('input[type="password"]').filter({
      has: page.locator('[placeholder*="current"], [name*="current"]'),
    }).first().or(
      page.locator('input[name*="current_password"], input[placeholder*="current"]').first()
    );
    this.newPasswordInput = page.locator('input[type="password"]').filter({
      has: page.locator('[placeholder*="new"], [name*="new"]'),
    }).first().or(
      page.locator('input[name*="new_password"], input[placeholder*="new"]').first()
    );
    this.confirmPasswordInput = page.locator('input[type="password"]').filter({
      has: page.locator('[placeholder*="confirm"], [name*="confirm"]'),
    }).first().or(
      page.locator('input[name*="confirm_password"], input[placeholder*="confirm"]').first()
    );
    this.changePasswordButton = page.locator('button').filter({ hasText: /change.*password|update.*password/i }).first();

    // 2FA section
    this.twoFactorSection = page.locator('section, div').filter({ hasText: /two.*factor|2fa|authenticator/i }).first();
    this.twoFactorToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/two.*factor|2fa/i'),
    }).first();
    this.setupTwoFactorButton = page.locator('button').filter({ hasText: /setup|enable.*2fa|enable.*two/i }).first();
    this.disableTwoFactorButton = page.locator('button').filter({ hasText: /disable.*2fa|disable.*two/i }).first();
    this.qrCodeImage = page.locator('img[alt*="QR"], svg[class*="qr"], canvas').first();
    this.verificationCodeInput = page.locator('input[placeholder*="code"], input[name*="verification"], input[maxlength="6"]').first();
    this.verifyCodeButton = page.locator('button').filter({ hasText: /verify|confirm/i }).first();
    this.backupCodesDisplay = page.locator('[class*="backup"], [class*="recovery"]').first();

    // Preferences section
    this.languageSelect = page.locator('select[name*="language"], [role="combobox"]').filter({
      has: page.locator('option:has-text("English"), [role="option"]'),
    }).first();
    this.fontSelect = page.locator('select[name*="font"], [role="combobox"]').filter({
      has: page.locator('option:has-text("Pretendard"), [role="option"]'),
    }).first();
    this.themeSelect = page.locator('select[name*="theme"], [role="combobox"]').filter({
      has: page.locator('option:has-text("dark"), option:has-text("light")'),
    }).first();
    this.timezoneSelect = page.locator('select[name*="timezone"], [role="combobox"]').first();

    // Actions
    this.saveButton = page.locator('button').filter({ hasText: /save|update/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel/i }).first();

    // Status messages
    this.successMessage = page.locator('text=/success|saved|updated/i, [class*="toast"]');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
  }

  /**
   * Navigate to account settings page.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.settingsAccount);
    await this.waitForLoad();
  }

  /**
   * Wait for page to load.
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await this.page.waitForTimeout(500);
  }

  /**
   * Get current username.
   */
  async getUsername(): Promise<string> {
    return await this.usernameDisplay.textContent() || '';
  }

  /**
   * Change password.
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    // Find password inputs more robustly
    const passwordInputs = await this.page.locator('input[type="password"]').all();

    if (passwordInputs.length >= 3) {
      await passwordInputs[0].fill(currentPassword);
      await passwordInputs[1].fill(newPassword);
      await passwordInputs[2].fill(newPassword);
    } else {
      // Fallback to named locators
      if (await this.currentPasswordInput.isVisible()) {
        await this.currentPasswordInput.fill(currentPassword);
      }
      if (await this.newPasswordInput.isVisible()) {
        await this.newPasswordInput.fill(newPassword);
      }
      if (await this.confirmPasswordInput.isVisible()) {
        await this.confirmPasswordInput.fill(newPassword);
      }
    }

    await this.changePasswordButton.click();
    await this.page.waitForTimeout(500);
  }

  /**
   * Check if 2FA is enabled.
   */
  async isTwoFactorEnabled(): Promise<boolean> {
    if (await this.disableTwoFactorButton.isVisible()) {
      return true;
    }
    if (await this.twoFactorToggle.isVisible()) {
      return await this.twoFactorToggle.isChecked();
    }
    return false;
  }

  /**
   * Setup 2FA - initiates the setup process.
   */
  async setupTwoFactor(): Promise<void> {
    await this.setupTwoFactorButton.click();
    // Wait for QR code to appear
    await this.qrCodeImage.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Verify 2FA code during setup.
   */
  async verifyTwoFactorCode(code: string): Promise<void> {
    await this.verificationCodeInput.fill(code);
    await this.verifyCodeButton.click();
    await this.page.waitForTimeout(1000);
  }

  /**
   * Disable 2FA.
   */
  async disableTwoFactor(): Promise<void> {
    if (await this.disableTwoFactorButton.isVisible()) {
      await this.disableTwoFactorButton.click();
      // May need to confirm
      const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|disable/i }).last();
      if (await confirmBtn.isVisible()) {
        await confirmBtn.click();
      }
      await this.page.waitForTimeout(500);
    }
  }

  /**
   * Select language.
   */
  async selectLanguage(language: string): Promise<void> {
    if (await this.languageSelect.isVisible()) {
      await this.languageSelect.selectOption({ label: language });
    }
  }

  /**
   * Select font.
   */
  async selectFont(font: string): Promise<void> {
    if (await this.fontSelect.isVisible()) {
      await this.fontSelect.selectOption({ label: font });
    }
  }

  /**
   * Select theme.
   */
  async selectTheme(theme: 'light' | 'dark' | 'system'): Promise<void> {
    if (await this.themeSelect.isVisible()) {
      await this.themeSelect.selectOption(theme);
    }
  }

  /**
   * Save settings.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
    await this.page.waitForTimeout(500);
  }

  /**
   * Check for success message.
   */
  async hasSuccessMessage(): Promise<boolean> {
    return await this.successMessage.isVisible();
  }

  /**
   * Check for error message.
   */
  async hasErrorMessage(): Promise<boolean> {
    return await this.errorMessage.count() > 0;
  }

  /**
   * Get error messages.
   */
  async getErrorMessages(): Promise<string[]> {
    return await this.errorMessage.allTextContents();
  }

  /**
   * Verify page is loaded correctly.
   */
  async expectAccountSettingsPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/settings\/account/);
  }
}

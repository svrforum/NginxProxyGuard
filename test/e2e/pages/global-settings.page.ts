import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Global Settings page object model.
 */
export class GlobalSettingsPage extends BasePage {
  // Page elements
  readonly pageTitle: Locator;
  readonly saveButton: Locator;
  readonly resetButton: Locator;

  // Nginx Settings section
  readonly nginxSection: Locator;
  readonly workerProcessesInput: Locator;
  readonly workerConnectionsInput: Locator;
  readonly clientMaxBodySizeInput: Locator;

  // WAF Settings section
  readonly wafSection: Locator;
  readonly defaultWafModeSelect: Locator;
  readonly defaultParanoiaLevelSelect: Locator;
  readonly wafAutoBanToggle: Locator;
  readonly wafAutoBanThresholdInput: Locator;
  readonly wafAutoBanDurationInput: Locator;

  // GeoIP Settings section
  readonly geoipSection: Locator;
  readonly geoipEnabledToggle: Locator;
  readonly geoipLicenseKeyInput: Locator;
  readonly geoipUpdateButton: Locator;

  // Bot Filter Settings section
  readonly botFilterSection: Locator;
  readonly botFilterDefaultToggle: Locator;
  readonly botFilterStrictnessSelect: Locator;

  // SSL/ACME Settings section
  readonly sslSection: Locator;
  readonly dhparamBitsSelect: Locator;
  readonly acmeEmailInput: Locator;
  readonly sslProtocolsCheckboxes: Locator;

  // CAPTCHA Settings section
  readonly captchaSection: Locator;
  readonly captchaProviderSelect: Locator;
  readonly captchaSiteKeyInput: Locator;
  readonly captchaSecretKeyInput: Locator;

  // Status messages
  readonly successMessage: Locator;
  readonly errorMessage: Locator;
  readonly warningMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /global.*setting|general.*setting/i }).first();
    this.saveButton = page.locator('button').filter({ hasText: /save|apply/i }).first();
    this.resetButton = page.locator('button').filter({ hasText: /reset|default/i }).first();

    // Nginx Settings
    this.nginxSection = page.locator('section, div').filter({ hasText: /nginx.*setting/i }).first();
    this.workerProcessesInput = page.locator('input[name*="worker_processes"], input[id*="worker_processes"]').first();
    this.workerConnectionsInput = page.locator('input[name*="worker_connections"], input[id*="worker_connections"]').first();
    this.clientMaxBodySizeInput = page.locator('input[name*="client_max_body"], input[id*="client_max_body"]').first();

    // WAF Settings
    this.wafSection = page.locator('section, div').filter({ hasText: /waf.*setting|modsec/i }).first();
    this.defaultWafModeSelect = page.locator('select[name*="waf_mode"], [role="combobox"]').filter({
      has: page.locator('option:has-text("Detection"), option:has-text("On")'),
    }).first();
    this.defaultParanoiaLevelSelect = page.locator('select[name*="paranoia"], [role="combobox"]').filter({
      has: page.locator('option:has-text("1"), option:has-text("2")'),
    }).first();
    this.wafAutoBanToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/auto.*ban/i'),
    }).first();
    this.wafAutoBanThresholdInput = page.locator('input[name*="threshold"], input[id*="threshold"]').first();
    this.wafAutoBanDurationInput = page.locator('input[name*="duration"], input[id*="duration"]').first();

    // GeoIP Settings
    this.geoipSection = page.locator('section, div').filter({ hasText: /geoip.*setting/i }).first();
    this.geoipEnabledToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/geoip|geo.*ip/i'),
    }).first();
    this.geoipLicenseKeyInput = page.locator('input[name*="geoip_license"], input[placeholder*="license"]').first();
    this.geoipUpdateButton = page.locator('button').filter({ hasText: /update.*database|download/i }).first();

    // Bot Filter Settings
    this.botFilterSection = page.locator('section, div').filter({ hasText: /bot.*filter.*setting/i }).first();
    this.botFilterDefaultToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/bot.*filter.*default|default.*bot/i'),
    }).first();
    this.botFilterStrictnessSelect = page.locator('select[name*="strictness"], [role="combobox"]').first();

    // SSL/ACME Settings
    this.sslSection = page.locator('section, div').filter({ hasText: /ssl.*setting|acme/i }).first();
    this.dhparamBitsSelect = page.locator('select[name*="dhparam"], [role="combobox"]').filter({
      has: page.locator('option:has-text("2048"), option:has-text("4096")'),
    }).first();
    this.acmeEmailInput = page.locator('input[name*="acme_email"], input[type="email"]').first();
    this.sslProtocolsCheckboxes = page.locator('input[type="checkbox"][name*="protocol"]');

    // CAPTCHA Settings
    this.captchaSection = page.locator('section, div').filter({ hasText: /captcha.*setting/i }).first();
    this.captchaProviderSelect = page.locator('select[name*="captcha_provider"], [role="combobox"]').first();
    this.captchaSiteKeyInput = page.locator('input[name*="site_key"], input[placeholder*="site.*key"]').first();
    this.captchaSecretKeyInput = page.locator('input[name*="secret_key"], input[placeholder*="secret"]').first();

    // Status messages
    this.successMessage = page.locator('text=/success|saved|applied/i, [class*="toast"]');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
    this.warningMessage = page.locator('.text-yellow-500, .text-amber-500, [class*="warning"]');
  }

  /**
   * Navigate to global settings page.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.settingsGlobal);
    await this.waitForLoad();
  }

  /**
   * Wait for page to load.
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await this.saveButton.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  // ==================== Nginx Settings ====================

  /**
   * Set worker processes.
   */
  async setWorkerProcesses(value: number | 'auto'): Promise<void> {
    if (await this.workerProcessesInput.isVisible()) {
      await this.workerProcessesInput.fill(value.toString());
    }
  }

  /**
   * Set worker connections.
   */
  async setWorkerConnections(value: number): Promise<void> {
    if (await this.workerConnectionsInput.isVisible()) {
      await this.workerConnectionsInput.fill(value.toString());
    }
  }

  /**
   * Set client max body size.
   */
  async setClientMaxBodySize(value: string): Promise<void> {
    if (await this.clientMaxBodySizeInput.isVisible()) {
      await this.clientMaxBodySizeInput.fill(value);
    }
  }

  // ==================== WAF Settings ====================

  /**
   * Set default WAF mode.
   */
  async setDefaultWafMode(mode: 'DetectionOnly' | 'On' | 'Off'): Promise<void> {
    if (await this.defaultWafModeSelect.isVisible()) {
      await this.defaultWafModeSelect.selectOption(mode);
    }
  }

  /**
   * Set default paranoia level.
   */
  async setDefaultParanoiaLevel(level: 1 | 2 | 3 | 4): Promise<void> {
    if (await this.defaultParanoiaLevelSelect.isVisible()) {
      await this.defaultParanoiaLevelSelect.selectOption(level.toString());
    }
  }

  /**
   * Toggle WAF auto ban.
   */
  async toggleWafAutoBan(enable: boolean): Promise<void> {
    if (await this.wafAutoBanToggle.isVisible()) {
      const isChecked = await this.wafAutoBanToggle.isChecked().catch(() => false);
      if (isChecked !== enable) {
        await this.wafAutoBanToggle.click();
      }
    }
  }

  /**
   * Set WAF auto ban threshold.
   */
  async setWafAutoBanThreshold(threshold: number): Promise<void> {
    if (await this.wafAutoBanThresholdInput.isVisible()) {
      await this.wafAutoBanThresholdInput.fill(threshold.toString());
    }
  }

  // ==================== GeoIP Settings ====================

  /**
   * Toggle GeoIP.
   */
  async toggleGeoip(enable: boolean): Promise<void> {
    if (await this.geoipEnabledToggle.isVisible()) {
      const isChecked = await this.geoipEnabledToggle.isChecked().catch(() => false);
      if (isChecked !== enable) {
        await this.geoipEnabledToggle.click();
      }
    }
  }

  /**
   * Set GeoIP license key.
   */
  async setGeoipLicenseKey(key: string): Promise<void> {
    if (await this.geoipLicenseKeyInput.isVisible()) {
      await this.geoipLicenseKeyInput.fill(key);
    }
  }

  /**
   * Update GeoIP database.
   */
  async updateGeoipDatabase(): Promise<void> {
    if (await this.geoipUpdateButton.isVisible()) {
      await this.geoipUpdateButton.click();
      await this.page.waitForTimeout(2000);
    }
  }

  // ==================== Bot Filter Settings ====================

  /**
   * Toggle bot filter default.
   */
  async toggleBotFilterDefault(enable: boolean): Promise<void> {
    if (await this.botFilterDefaultToggle.isVisible()) {
      const isChecked = await this.botFilterDefaultToggle.isChecked().catch(() => false);
      if (isChecked !== enable) {
        await this.botFilterDefaultToggle.click();
      }
    }
  }

  // ==================== SSL Settings ====================

  /**
   * Set DH param bits.
   */
  async setDhparamBits(bits: 2048 | 4096): Promise<void> {
    if (await this.dhparamBitsSelect.isVisible()) {
      await this.dhparamBitsSelect.selectOption(bits.toString());
    }
  }

  /**
   * Set ACME email.
   */
  async setAcmeEmail(email: string): Promise<void> {
    if (await this.acmeEmailInput.isVisible()) {
      await this.acmeEmailInput.fill(email);
    }
  }

  // ==================== CAPTCHA Settings ====================

  /**
   * Set CAPTCHA provider.
   */
  async setCaptchaProvider(provider: string): Promise<void> {
    if (await this.captchaProviderSelect.isVisible()) {
      await this.captchaProviderSelect.selectOption(provider);
    }
  }

  /**
   * Set CAPTCHA keys.
   */
  async setCaptchaKeys(siteKey: string, secretKey: string): Promise<void> {
    if (await this.captchaSiteKeyInput.isVisible()) {
      await this.captchaSiteKeyInput.fill(siteKey);
    }
    if (await this.captchaSecretKeyInput.isVisible()) {
      await this.captchaSecretKeyInput.fill(secretKey);
    }
  }

  // ==================== Actions ====================

  /**
   * Save settings.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
    await this.page.waitForTimeout(500);
  }

  /**
   * Reset to defaults.
   */
  async resetToDefaults(): Promise<void> {
    if (await this.resetButton.isVisible()) {
      await this.resetButton.click();
      // Confirm if needed
      const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|reset/i }).last();
      if (await confirmBtn.isVisible()) {
        await confirmBtn.click();
      }
      await this.page.waitForTimeout(500);
    }
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
  async expectGlobalSettingsPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/settings\/global/);
    await expect(this.saveButton).toBeVisible({ timeout: TIMEOUTS.medium });
  }
}

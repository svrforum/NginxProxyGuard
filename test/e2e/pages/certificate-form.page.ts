import { Page, Locator, expect } from '@playwright/test';
import { TIMEOUTS } from '../fixtures/test-data';

/**
 * Certificate Form (modal) page object model.
 */
export class CertificateFormPage {
  readonly page: Page;

  // Modal container
  readonly modal: Locator;
  readonly closeButton: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;

  // Certificate type selection
  readonly letsEncryptOption: Locator;
  readonly customOption: Locator;

  // Let's Encrypt fields
  readonly domainInput: Locator;
  readonly addDomainButton: Locator;
  readonly domainChips: Locator;
  readonly emailInput: Locator;
  readonly dnsProviderSelect: Locator;
  readonly wildcardToggle: Locator;

  // Custom certificate fields
  readonly certificateInput: Locator;
  readonly privateKeyInput: Locator;
  readonly certificateChainInput: Locator;
  readonly uploadCertButton: Locator;
  readonly uploadKeyButton: Locator;

  // Status/progress
  readonly progressIndicator: Locator;
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    this.page = page;

    // Modal container
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.closeButton = page.locator('button[aria-label*="close"], button:has(svg path[d*="M6 18L18 6"])').first();
    this.saveButton = page.locator('button').filter({ hasText: /save|request|submit|create/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel|close/i }).first();

    // Certificate type selection
    this.letsEncryptOption = page.locator('button, [role="radio"], input[type="radio"]').filter({
      hasText: /let.*encrypt|acme/i,
    }).first();
    this.customOption = page.locator('button, [role="radio"], input[type="radio"]').filter({
      hasText: /custom|upload/i,
    }).first();

    // Let's Encrypt fields
    this.domainInput = page.locator('input[placeholder*="domain"], input[name*="domain"]').first();
    this.addDomainButton = page.locator('button').filter({ hasText: /add|\+/ }).first();
    this.domainChips = page.locator('[class*="chip"], [class*="tag"], .bg-slate-100');
    this.emailInput = page.locator('input[type="email"], input[placeholder*="email"], input[name*="email"]').first();
    this.dnsProviderSelect = page.locator('select[name*="dns_provider"], [role="combobox"]').filter({
      has: page.locator('option:has-text("provider"), [role="option"]'),
    }).first();
    this.wildcardToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/wildcard|\\*/i'),
    }).first();

    // Custom certificate fields
    this.certificateInput = page.locator('textarea[name*="certificate"], textarea[placeholder*="certificate"]').first();
    this.privateKeyInput = page.locator('textarea[name*="private_key"], textarea[placeholder*="key"]').first();
    this.certificateChainInput = page.locator('textarea[name*="chain"], textarea[placeholder*="chain"]').first();
    this.uploadCertButton = page.locator('button, input[type="file"]').filter({ hasText: /upload.*cert/i }).first();
    this.uploadKeyButton = page.locator('button, input[type="file"]').filter({ hasText: /upload.*key/i }).first();

    // Status/progress
    this.progressIndicator = page.locator('.animate-spin, [class*="progress"]').first();
    this.successMessage = page.locator('text=/success|complete|issued/i');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
  }

  /**
   * Check if form modal is visible.
   */
  async isVisible(): Promise<boolean> {
    return await this.modal.isVisible();
  }

  /**
   * Wait for form to be visible.
   */
  async waitForForm(): Promise<void> {
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Select Let's Encrypt certificate type.
   */
  async selectLetsEncrypt(): Promise<void> {
    if (await this.letsEncryptOption.isVisible()) {
      await this.letsEncryptOption.click();
      await this.page.waitForTimeout(300);
    }
  }

  /**
   * Select custom certificate type.
   */
  async selectCustomCertificate(): Promise<void> {
    if (await this.customOption.isVisible()) {
      await this.customOption.click();
      await this.page.waitForTimeout(300);
    }
  }

  /**
   * Fill domain for Let's Encrypt certificate.
   */
  async fillDomain(domain: string): Promise<void> {
    await this.domainInput.fill(domain);
    if (await this.addDomainButton.isVisible()) {
      await this.addDomainButton.click();
    } else {
      await this.domainInput.press('Enter');
    }
  }

  /**
   * Fill multiple domains.
   */
  async fillDomains(domains: string[]): Promise<void> {
    for (const domain of domains) {
      await this.fillDomain(domain);
      await this.page.waitForTimeout(200);
    }
  }

  /**
   * Fill email address.
   */
  async fillEmail(email: string): Promise<void> {
    if (await this.emailInput.isVisible()) {
      await this.emailInput.fill(email);
    }
  }

  /**
   * Select DNS provider.
   */
  async selectDnsProvider(providerName: string): Promise<void> {
    if (await this.dnsProviderSelect.isVisible()) {
      await this.dnsProviderSelect.selectOption({ label: providerName });
    }
  }

  /**
   * Toggle wildcard certificate option.
   */
  async toggleWildcard(enable: boolean): Promise<void> {
    if (await this.wildcardToggle.isVisible()) {
      const isChecked = await this.wildcardToggle.isChecked();
      if (isChecked !== enable) {
        await this.wildcardToggle.click();
      }
    }
  }

  /**
   * Fill custom certificate content.
   */
  async fillCustomCertificate(cert: string, key: string, chain?: string): Promise<void> {
    await this.selectCustomCertificate();

    if (await this.certificateInput.isVisible()) {
      await this.certificateInput.fill(cert);
    }

    if (await this.privateKeyInput.isVisible()) {
      await this.privateKeyInput.fill(key);
    }

    if (chain && await this.certificateChainInput.isVisible()) {
      await this.certificateChainInput.fill(chain);
    }
  }

  /**
   * Request Let's Encrypt certificate.
   */
  async requestLetsEncryptCertificate(config: {
    domains: string[];
    email?: string;
    dnsProvider?: string;
    wildcard?: boolean;
  }): Promise<void> {
    await this.selectLetsEncrypt();
    await this.fillDomains(config.domains);

    if (config.email) {
      await this.fillEmail(config.email);
    }

    if (config.dnsProvider) {
      await this.selectDnsProvider(config.dnsProvider);
    }

    if (config.wildcard !== undefined) {
      await this.toggleWildcard(config.wildcard);
    }

    await this.save();
  }

  /**
   * Save/submit the form.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
    // Wait for operation to complete
    await this.page.waitForTimeout(500);
    await Promise.race([
      this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.veryLong }),
      this.successMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.veryLong }),
      this.errorMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.veryLong }),
    ]).catch(() => null);
  }

  /**
   * Cancel and close the form.
   */
  async cancel(): Promise<void> {
    if (await this.cancelButton.isVisible()) {
      await this.cancelButton.click();
    } else {
      await this.closeButton.click();
    }
    await this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.short });
  }

  /**
   * Check for validation errors.
   */
  async hasValidationErrors(): Promise<boolean> {
    return await this.errorMessage.count() > 0;
  }

  /**
   * Get validation error messages.
   */
  async getValidationErrors(): Promise<string[]> {
    return await this.errorMessage.allTextContents();
  }

  /**
   * Wait for certificate issuance to complete.
   */
  async waitForIssuance(): Promise<void> {
    // Certificate issuance can take time
    await this.page.waitForSelector('text=/success|complete|issued/i', {
      timeout: TIMEOUTS.veryLong,
    });
  }

  /**
   * Verify form is displayed correctly.
   */
  async expectForm(): Promise<void> {
    await expect(this.modal).toBeVisible();
    await expect(this.saveButton).toBeVisible();
  }

  /**
   * Verify form is closed.
   */
  async expectClosed(): Promise<void> {
    await expect(this.modal).not.toBeVisible();
  }
}

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

  // Domain field (textarea in the actual form)
  readonly domainInput: Locator;
  readonly domainChips: Locator;
  readonly emailInput: Locator;
  readonly dnsProviderSelect: Locator;
  readonly wildcardToggle: Locator;

  // Custom certificate fields
  readonly certificateInput: Locator;
  readonly privateKeyInput: Locator;
  readonly certificateChainInput: Locator;

  // Status/progress
  readonly progressIndicator: Locator;
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    this.page = page;

    // Modal container - the fixed overlay
    this.modal = page.locator('.fixed.inset-0').first();

    // Scope all locators inside the modal to avoid matching background elements
    const modal = this.modal;

    this.closeButton = modal.locator('button:has(svg path[d*="M6 18L18 6"])').first();
    this.saveButton = modal.locator('button[type="submit"]').first();
    this.cancelButton = modal.locator('button').filter({ hasText: /cancel/i }).first();

    // Certificate type selection - provider buttons in the grid
    this.letsEncryptOption = modal.locator('.grid-cols-3 button').filter({
      hasText: /let.*encrypt/i,
    }).first();
    this.customOption = modal.locator('.grid-cols-3 button').filter({
      hasText: /custom|upload/i,
    }).first();

    // Domain field - the form uses a textarea for domain input
    this.domainInput = modal.locator('textarea').first();
    this.domainChips = modal.locator('[class*="chip"], [class*="tag"]');
    this.emailInput = modal.locator('input[type="email"]').first();
    this.dnsProviderSelect = modal.locator('select').first();
    this.wildcardToggle = modal.locator('input[type="checkbox"]').first();

    // Custom certificate fields - textareas with BEGIN CERTIFICATE / BEGIN PRIVATE KEY placeholders
    this.certificateInput = modal.locator('textarea[placeholder*="CERTIFICATE"]').first();
    this.privateKeyInput = modal.locator('textarea[placeholder*="PRIVATE KEY"]').first();
    this.certificateChainInput = modal.locator('textarea').nth(3);

    // Status/progress
    this.progressIndicator = modal.locator('.animate-spin').first();
    this.successMessage = modal.locator('text=/success|complete|issued/i');
    this.errorMessage = modal.locator('.text-red-500, .text-red-600, .text-red-700, .bg-red-50');
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
    await this.letsEncryptOption.click();
    await this.page.waitForTimeout(300);
  }

  /**
   * Select custom certificate type.
   */
  async selectCustomCertificate(): Promise<void> {
    await this.customOption.click();
    await this.page.waitForTimeout(300);
  }

  /**
   * Fill domain in the domain textarea.
   * The form uses a textarea (one domain per line), not input + add button.
   */
  async fillDomain(domain: string): Promise<void> {
    const current = await this.domainInput.inputValue();
    const newValue = current ? `${current}\n${domain}` : domain;
    await this.domainInput.fill(newValue);
  }

  /**
   * Fill multiple domains.
   */
  async fillDomains(domains: string[]): Promise<void> {
    await this.domainInput.fill(domains.join('\n'));
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
      this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.long }),
      this.successMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.long }),
      this.errorMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.long }),
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

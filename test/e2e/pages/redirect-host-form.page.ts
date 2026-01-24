import { Page, Locator, expect } from '@playwright/test';
import { TIMEOUTS } from '../fixtures/test-data';

/**
 * Redirect Host Form (modal) page object model.
 */
export class RedirectHostFormPage {
  readonly page: Page;

  // Modal container
  readonly modal: Locator;
  readonly closeButton: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;

  // Domain fields
  readonly domainInput: Locator;
  readonly addDomainButton: Locator;
  readonly domainChips: Locator;

  // Redirect configuration
  readonly forwardDomainInput: Locator;
  readonly redirectCodeSelect: Locator;
  readonly preservePathToggle: Locator;
  readonly enabledToggle: Locator;

  // SSL options
  readonly sslEnabledToggle: Locator;
  readonly forceHttpsToggle: Locator;

  // Status messages
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    this.page = page;

    // Modal container
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.closeButton = page.locator('button').filter({ has: page.locator('svg path[d*="M6 18L18 6"]') }).first();
    this.saveButton = page.locator('button').filter({ hasText: /save|submit|create|update/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel|close/i }).first();

    // Domain fields
    this.domainInput = page.locator('input[placeholder*="domain"], input[name*="domain"]').first();
    this.addDomainButton = page.locator('button').filter({ hasText: /add|\+/ }).first();
    this.domainChips = page.locator('[class*="chip"], [class*="tag"], .bg-slate-100');

    // Redirect configuration
    this.forwardDomainInput = page.locator('input[placeholder*="target"], input[placeholder*="redirect"], input[name*="forward"]').first();
    this.redirectCodeSelect = page.locator('select[name*="redirect_code"], select[name*="code"], [role="combobox"]').filter({
      has: page.locator('option:has-text("301"), option:has-text("302")'),
    }).first();
    this.preservePathToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/preserve.*path|keep.*path/i'),
    }).first().or(
      page.locator('label').filter({ hasText: /preserve.*path|keep.*path/i }).locator('input, button[role="switch"]')
    );
    this.enabledToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/enabled|active/i'),
    }).first();

    // SSL options
    this.sslEnabledToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/ssl|https/i'),
    }).first();
    this.forceHttpsToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({
      has: page.locator('text=/force.*https/i'),
    }).first();

    // Status messages
    this.successMessage = page.locator('text=/success|saved|created/i');
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
   * Fill domain name.
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
   * Fill multiple domain names.
   */
  async fillDomains(domains: string[]): Promise<void> {
    for (const domain of domains) {
      await this.fillDomain(domain);
      await this.page.waitForTimeout(200);
    }
  }

  /**
   * Fill forward/target domain.
   */
  async fillForwardDomain(url: string): Promise<void> {
    await this.forwardDomainInput.fill(url);
  }

  /**
   * Select redirect code.
   */
  async selectRedirectCode(code: 301 | 302 | 303 | 307 | 308): Promise<void> {
    if (await this.redirectCodeSelect.isVisible()) {
      await this.redirectCodeSelect.selectOption(code.toString());
    }
  }

  /**
   * Toggle preserve path option.
   */
  async togglePreservePath(enable: boolean): Promise<void> {
    const toggle = this.page.locator('label').filter({ hasText: /preserve.*path|keep.*path/i })
      .locator('input[type="checkbox"], button[role="switch"]').first();

    if (await toggle.isVisible()) {
      const isChecked = await toggle.isChecked().catch(() => {
        // For switch buttons, check aria-checked
        return toggle.getAttribute('aria-checked').then(v => v === 'true');
      });

      if (isChecked !== enable) {
        await toggle.click();
      }
    }
  }

  /**
   * Toggle enabled state.
   */
  async toggleEnabled(enable: boolean): Promise<void> {
    if (await this.enabledToggle.isVisible()) {
      const isChecked = await this.enabledToggle.isChecked().catch(() => false);
      if (isChecked !== enable) {
        await this.enabledToggle.click();
      }
    }
  }

  /**
   * Toggle SSL enabled.
   */
  async toggleSSL(enable: boolean): Promise<void> {
    if (await this.sslEnabledToggle.isVisible()) {
      const isChecked = await this.sslEnabledToggle.isChecked().catch(() => false);
      if (isChecked !== enable) {
        await this.sslEnabledToggle.click();
      }
    }
  }

  /**
   * Fill complete redirect host configuration.
   */
  async fillConfig(config: {
    domain: string;
    forwardDomain: string;
    redirectCode?: 301 | 302 | 303 | 307 | 308;
    preservePath?: boolean;
    sslEnabled?: boolean;
  }): Promise<void> {
    await this.fillDomain(config.domain);
    await this.fillForwardDomain(config.forwardDomain);

    if (config.redirectCode) {
      await this.selectRedirectCode(config.redirectCode);
    }

    if (config.preservePath !== undefined) {
      await this.togglePreservePath(config.preservePath);
    }

    if (config.sslEnabled !== undefined) {
      await this.toggleSSL(config.sslEnabled);
    }
  }

  /**
   * Save the redirect host configuration.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
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

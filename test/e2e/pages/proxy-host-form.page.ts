import { Page, Locator, expect } from '@playwright/test';
import { TIMEOUTS } from '../fixtures/test-data';

/**
 * Proxy Host Form (modal) page object model.
 */
export class ProxyHostFormPage {
  readonly page: Page;

  // Modal container
  readonly modal: Locator;
  readonly closeButton: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;

  // Tabs
  readonly basicTab: Locator;
  readonly sslTab: Locator;
  readonly securityTab: Locator;
  readonly performanceTab: Locator;
  readonly advancedTab: Locator;
  readonly protectionTab: Locator;

  // Basic tab fields
  readonly domainInput: Locator;
  readonly addDomainButton: Locator;
  readonly domainChips: Locator;
  readonly forwardSchemeSelect: Locator;
  readonly forwardHostInput: Locator;
  readonly forwardPortInput: Locator;
  readonly enabledToggle: Locator;

  // SSL tab fields
  readonly sslEnabledToggle: Locator;
  readonly http2Toggle: Locator;
  readonly http3Toggle: Locator;
  readonly forceHttpsToggle: Locator;
  readonly hstsToggle: Locator;
  readonly certificateSelect: Locator;

  // Security tab fields
  readonly wafEnabledToggle: Locator;
  readonly wafModeSelect: Locator;
  readonly paranoiaLevelSelect: Locator;
  readonly botFilterToggle: Locator;
  readonly geoipToggle: Locator;

  // Save progress modal
  readonly saveProgressModal: Locator;
  readonly saveProgressSpinner: Locator;
  readonly saveSuccessMessage: Locator;
  readonly saveErrorMessage: Locator;

  constructor(page: Page) {
    this.page = page;

    // Modal container - typically a fixed overlay
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.closeButton = this.modal.locator('button').filter({ has: page.locator('svg path[d*="M6 18L18 6"]') }).first();
    this.saveButton = page.locator('button').filter({ hasText: /save|submit|create|update/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel|close/i }).first();

    // Tabs - look for tab buttons
    this.basicTab = page.locator('button, [role="tab"]').filter({ hasText: /basic/i }).first();
    this.sslTab = page.locator('button, [role="tab"]').filter({ hasText: /ssl|https/i }).first();
    this.securityTab = page.locator('button, [role="tab"]').filter({ hasText: /security/i }).first();
    this.performanceTab = page.locator('button, [role="tab"]').filter({ hasText: /performance/i }).first();
    this.advancedTab = page.locator('button, [role="tab"]').filter({ hasText: /advanced/i }).first();
    this.protectionTab = page.locator('button, [role="tab"]').filter({ hasText: /protection/i }).first();

    // Basic tab fields
    this.domainInput = page.locator('input[placeholder*="domain"], input[name*="domain"], input').filter({
      has: page.locator('[placeholder*=".com"], [placeholder*="example"]'),
    }).first().or(page.locator('input').first());
    this.addDomainButton = page.locator('button').filter({ hasText: /add.*domain|\+/i }).first();
    this.domainChips = page.locator('[class*="chip"], [class*="tag"], .bg-slate-100');
    this.forwardSchemeSelect = page.locator('select, [role="combobox"]').filter({ has: page.locator('option:has-text("http"), [role="option"]:has-text("http")') }).first();
    this.forwardHostInput = page.locator('input[placeholder*="host"], input[placeholder*="IP"], input[name*="forward_host"]').first();
    this.forwardPortInput = page.locator('input[type="number"], input[placeholder*="port"], input[name*="forward_port"]').first();
    this.enabledToggle = page.locator('input[type="checkbox"], button[role="switch"]').first();

    // SSL tab fields
    this.sslEnabledToggle = page.locator('[class*="ssl"] input[type="checkbox"], [class*="ssl"] button[role="switch"]').first();
    this.http2Toggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/http.*2/i') }).first();
    this.http3Toggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/http.*3/i') }).first();
    this.forceHttpsToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/force.*https|redirect/i') }).first();
    this.hstsToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/hsts/i') }).first();
    this.certificateSelect = page.locator('select[name*="certificate"], [role="combobox"]').filter({ has: page.locator('option:has-text("certificate"), [role="option"]:has-text("certificate")') }).first();

    // Security tab fields
    this.wafEnabledToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/waf|modsec/i') }).first();
    this.wafModeSelect = page.locator('select[name*="waf_mode"], [role="combobox"]').filter({ has: page.locator('text=/detection|blocking/i') }).first();
    this.paranoiaLevelSelect = page.locator('select[name*="paranoia"], [role="combobox"]').filter({ has: page.locator('text=/paranoia|level/i') }).first();
    this.botFilterToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/bot.*filter/i') }).first();
    this.geoipToggle = page.locator('input[type="checkbox"], button[role="switch"]').filter({ has: page.locator('text=/geo.*ip|country/i') }).first();

    // Save progress modal
    this.saveProgressModal = page.locator('[class*="progress"], [class*="saving"]').first();
    this.saveProgressSpinner = page.locator('.animate-spin');
    this.saveSuccessMessage = page.locator('text=/success|saved|created/i');
    this.saveErrorMessage = page.locator('text=/error|failed/i, .text-red-500, .text-red-600');
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
   * Switch to a specific tab.
   */
  async switchTab(tab: 'basic' | 'ssl' | 'security' | 'performance' | 'advanced' | 'protection'): Promise<void> {
    const tabMap = {
      basic: this.basicTab,
      ssl: this.sslTab,
      security: this.securityTab,
      performance: this.performanceTab,
      advanced: this.advancedTab,
      protection: this.protectionTab,
    };

    const tabButton = tabMap[tab];
    if (await tabButton.isVisible()) {
      await tabButton.click();
      await this.page.waitForTimeout(300); // Tab transition
    }
  }

  /**
   * Fill domain name(s).
   */
  async fillDomain(domain: string): Promise<void> {
    // Find the domain input field more reliably
    const domainInputs = await this.page.locator('input').all();
    for (const input of domainInputs) {
      const placeholder = await input.getAttribute('placeholder');
      if (placeholder && (placeholder.toLowerCase().includes('domain') || placeholder.includes('.com'))) {
        await input.fill(domain);
        // Press Enter or click add button if available
        const addBtn = this.page.locator('button').filter({ hasText: /add|\+/ }).first();
        if (await addBtn.isVisible()) {
          await addBtn.click();
        } else {
          await input.press('Enter');
        }
        return;
      }
    }
    // Fallback: fill first input
    await this.domainInput.fill(domain);
  }

  /**
   * Fill forward host (upstream server).
   */
  async fillForwardHost(host: string): Promise<void> {
    // Find input by various patterns
    const hostInput = this.page.locator('input').filter({
      has: this.page.locator('[placeholder*="host"], [placeholder*="IP"], [placeholder*="server"]'),
    }).first().or(
      this.page.locator('input[name*="forward_host"], input[id*="forward_host"]').first()
    );

    if (await hostInput.isVisible()) {
      await hostInput.fill(host);
    } else {
      // Try to find by label
      const label = this.page.locator('label').filter({ hasText: /forward.*host|upstream/i }).first();
      if (await label.isVisible()) {
        const forAttr = await label.getAttribute('for');
        if (forAttr) {
          await this.page.locator(`#${forAttr}`).fill(host);
        }
      }
    }
  }

  /**
   * Fill forward port.
   */
  async fillForwardPort(port: number): Promise<void> {
    const portInput = this.page.locator('input[type="number"]').first().or(
      this.page.locator('input').filter({ has: this.page.locator('[placeholder*="port"]') }).first()
    );

    if (await portInput.isVisible()) {
      await portInput.fill(port.toString());
    }
  }

  /**
   * Select forward scheme (http/https).
   */
  async selectForwardScheme(scheme: 'http' | 'https'): Promise<void> {
    if (await this.forwardSchemeSelect.isVisible()) {
      await this.forwardSchemeSelect.selectOption(scheme);
    }
  }

  /**
   * Fill basic proxy host configuration.
   */
  async fillBasicConfig(config: {
    domain: string;
    forwardHost: string;
    forwardPort: number;
    forwardScheme?: 'http' | 'https';
  }): Promise<void> {
    await this.switchTab('basic');
    await this.fillDomain(config.domain);
    await this.fillForwardHost(config.forwardHost);
    await this.fillForwardPort(config.forwardPort);
    if (config.forwardScheme) {
      await this.selectForwardScheme(config.forwardScheme);
    }
  }

  /**
   * Enable/disable SSL.
   */
  async toggleSSL(enable: boolean): Promise<void> {
    await this.switchTab('ssl');
    const isEnabled = await this.isSSLEnabled();
    if (isEnabled !== enable) {
      await this.sslEnabledToggle.click();
    }
  }

  /**
   * Check if SSL is enabled.
   */
  async isSSLEnabled(): Promise<boolean> {
    const toggle = this.sslEnabledToggle;
    if (await toggle.isVisible()) {
      return await toggle.isChecked();
    }
    return false;
  }

  /**
   * Enable/disable WAF.
   */
  async toggleWAF(enable: boolean): Promise<void> {
    await this.switchTab('security');
    const isEnabled = await this.isWAFEnabled();
    if (isEnabled !== enable) {
      await this.wafEnabledToggle.click();
    }
  }

  /**
   * Check if WAF is enabled.
   */
  async isWAFEnabled(): Promise<boolean> {
    const toggle = this.wafEnabledToggle;
    if (await toggle.isVisible()) {
      return await toggle.isChecked();
    }
    return false;
  }

  /**
   * Set WAF mode.
   */
  async setWAFMode(mode: 'DetectionOnly' | 'On' | 'Off'): Promise<void> {
    await this.switchTab('security');
    if (await this.wafModeSelect.isVisible()) {
      await this.wafModeSelect.selectOption(mode);
    }
  }

  /**
   * Enable/disable bot filter.
   */
  async toggleBotFilter(enable: boolean): Promise<void> {
    await this.switchTab('security');
    const isEnabled = await this.botFilterToggle.isChecked().catch(() => false);
    if (isEnabled !== enable && await this.botFilterToggle.isVisible()) {
      await this.botFilterToggle.click();
    }
  }

  /**
   * Enable/disable GeoIP.
   */
  async toggleGeoIP(enable: boolean): Promise<void> {
    await this.switchTab('security');
    const isEnabled = await this.geoipToggle.isChecked().catch(() => false);
    if (isEnabled !== enable && await this.geoipToggle.isVisible()) {
      await this.geoipToggle.click();
    }
  }

  /**
   * Save the proxy host configuration.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
    // Wait for save operation to complete
    await this.page.waitForTimeout(500);
    // Wait for modal to close or success message
    await Promise.race([
      this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.long }),
      this.saveSuccessMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.long }),
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
    const errorMessages = this.page.locator('.text-red-500, .text-red-600, [class*="error"]');
    return await errorMessages.count() > 0;
  }

  /**
   * Get validation error messages.
   */
  async getValidationErrors(): Promise<string[]> {
    const errorMessages = this.page.locator('.text-red-500, .text-red-600, [class*="error"]');
    return await errorMessages.allTextContents();
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

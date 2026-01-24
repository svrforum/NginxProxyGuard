import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * DNS Provider management page object model.
 */
export class DnsProviderPage extends BasePage {
  // Page elements
  readonly pageTitle: Locator;
  readonly addProviderButton: Locator;
  readonly providerList: Locator;
  readonly providerItems: Locator;
  readonly emptyState: Locator;
  readonly loadingState: Locator;

  // Form modal elements
  readonly modal: Locator;
  readonly nameInput: Locator;
  readonly typeSelect: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;
  readonly testConnectionButton: Locator;

  // Provider-specific credential fields
  readonly cloudflareApiTokenInput: Locator;
  readonly cloudflareApiKeyInput: Locator;
  readonly cloudflareEmailInput: Locator;
  readonly duckdnsTokenInput: Locator;
  readonly dynuUsernameInput: Locator;
  readonly dynuPasswordInput: Locator;
  readonly genericCredentialInput: Locator;

  // Status indicators
  readonly connectionStatus: Locator;
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /dns.*provider/i }).first();
    this.addProviderButton = page.locator('button').filter({ hasText: /add|new|create/i }).first();
    this.providerList = page.locator('main .space-y-4, main .grid, main > div').first();
    this.providerItems = page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      has: page.locator('text=/cloudflare|duckdns|dynu|route53|godaddy/i'),
    });
    this.emptyState = page.locator('text=/no.*provider|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Form modal
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.nameInput = page.locator('input[name*="name"], input[placeholder*="name"]').first();
    this.typeSelect = page.locator('select[name*="type"], [role="combobox"]').first();
    this.saveButton = page.locator('button').filter({ hasText: /save|submit|create/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel|close/i }).first();
    this.testConnectionButton = page.locator('button').filter({ hasText: /test.*connect|verify/i }).first();

    // Provider-specific credentials
    this.cloudflareApiTokenInput = page.locator('input[name*="api_token"], input[placeholder*="API Token"]').first();
    this.cloudflareApiKeyInput = page.locator('input[name*="api_key"], input[placeholder*="API Key"]').first();
    this.cloudflareEmailInput = page.locator('input[name*="email"], input[placeholder*="email"]').first();
    this.duckdnsTokenInput = page.locator('input[name*="token"], input[placeholder*="Token"]').first();
    this.dynuUsernameInput = page.locator('input[name*="username"], input[placeholder*="Username"]').first();
    this.dynuPasswordInput = page.locator('input[name*="password"], input[placeholder*="Password"]').first();
    this.genericCredentialInput = page.locator('input[type="text"], input[type="password"]');

    // Status
    this.connectionStatus = page.locator('[class*="status"], .badge').first();
    this.successMessage = page.locator('text=/success|connected|valid/i');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
  }

  /**
   * Navigate to DNS providers page.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.certificatesDnsProviders);
    await this.waitForLoad();
  }

  /**
   * Wait for page to load.
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await Promise.race([
      this.providerItems.first().waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.emptyState.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.addProviderButton.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }),
    ]);
  }

  /**
   * Click add provider button.
   */
  async clickAddProvider(): Promise<void> {
    await this.addProviderButton.click();
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Get count of providers.
   */
  async getProviderCount(): Promise<number> {
    return await this.providerItems.count();
  }

  /**
   * Get provider by name.
   */
  getProviderByName(name: string): Locator {
    return this.page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      hasText: name,
    }).first();
  }

  /**
   * Fill provider name.
   */
  async fillName(name: string): Promise<void> {
    await this.nameInput.fill(name);
  }

  /**
   * Select provider type.
   */
  async selectType(type: string): Promise<void> {
    await this.typeSelect.selectOption(type);
    await this.page.waitForTimeout(300); // Wait for credential fields to appear
  }

  /**
   * Fill Cloudflare credentials.
   */
  async fillCloudflareCredentials(apiToken: string): Promise<void> {
    await this.selectType('cloudflare');
    if (await this.cloudflareApiTokenInput.isVisible()) {
      await this.cloudflareApiTokenInput.fill(apiToken);
    }
  }

  /**
   * Fill DuckDNS credentials.
   */
  async fillDuckdnsCredentials(token: string): Promise<void> {
    await this.selectType('duckdns');
    if (await this.duckdnsTokenInput.isVisible()) {
      await this.duckdnsTokenInput.fill(token);
    }
  }

  /**
   * Fill Dynu credentials.
   */
  async fillDynuCredentials(username: string, password: string): Promise<void> {
    await this.selectType('dynu');
    if (await this.dynuUsernameInput.isVisible()) {
      await this.dynuUsernameInput.fill(username);
    }
    if (await this.dynuPasswordInput.isVisible()) {
      await this.dynuPasswordInput.fill(password);
    }
  }

  /**
   * Create a new DNS provider.
   */
  async createProvider(config: {
    name: string;
    type: string;
    credentials: Record<string, string>;
  }): Promise<void> {
    await this.clickAddProvider();
    await this.fillName(config.name);
    await this.selectType(config.type);

    // Fill credentials based on type
    switch (config.type) {
      case 'cloudflare':
        if (config.credentials.api_token) {
          await this.cloudflareApiTokenInput.fill(config.credentials.api_token);
        }
        break;
      case 'duckdns':
        if (config.credentials.token) {
          await this.duckdnsTokenInput.fill(config.credentials.token);
        }
        break;
      case 'dynu':
        if (config.credentials.username) {
          await this.dynuUsernameInput.fill(config.credentials.username);
        }
        if (config.credentials.password) {
          await this.dynuPasswordInput.fill(config.credentials.password);
        }
        break;
      default:
        // Generic credential filling
        const inputs = await this.genericCredentialInput.all();
        const credValues = Object.values(config.credentials);
        for (let i = 0; i < Math.min(inputs.length, credValues.length); i++) {
          await inputs[i].fill(credValues[i]);
        }
    }

    await this.save();
  }

  /**
   * Test connection for a provider.
   */
  async testConnection(): Promise<boolean> {
    if (await this.testConnectionButton.isVisible()) {
      await this.testConnectionButton.click();
      await this.page.waitForTimeout(2000);
      return await this.successMessage.isVisible();
    }
    return false;
  }

  /**
   * Save the form.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
    await this.page.waitForTimeout(500);
    await Promise.race([
      this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.long }),
      this.errorMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.long }),
    ]).catch(() => null);
  }

  /**
   * Cancel and close the form.
   */
  async cancel(): Promise<void> {
    if (await this.cancelButton.isVisible()) {
      await this.cancelButton.click();
    }
    await this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.short });
  }

  /**
   * Click on provider to edit.
   */
  async clickProvider(name: string): Promise<void> {
    const provider = this.getProviderByName(name);
    await provider.click();
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Delete a provider.
   */
  async deleteProvider(name: string): Promise<void> {
    const provider = this.getProviderByName(name);
    const deleteBtn = provider.locator('button').filter({ hasText: /delete/i }).first();

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      // Try dropdown menu
      const menuBtn = provider.locator('button[title*="menu"], button:has(svg)').last();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /delete/i }).click();
      }
    }

    // Confirm deletion
    const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|delete/i }).last();
    await confirmBtn.click();
    await this.waitForLoad();
  }

  /**
   * Check if provider exists.
   */
  async providerExists(name: string): Promise<boolean> {
    return await this.getProviderByName(name).isVisible();
  }

  /**
   * Check for validation errors.
   */
  async hasValidationErrors(): Promise<boolean> {
    return await this.errorMessage.count() > 0;
  }

  /**
   * Verify page is loaded correctly.
   */
  async expectDnsProviderPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/certificates\/dns-providers/);
    await expect(this.addProviderButton).toBeVisible({ timeout: TIMEOUTS.medium });
  }
}

import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Access List management page object model.
 */
export class AccessListPage extends BasePage {
  // Page elements
  readonly pageTitle: Locator;
  readonly addListButton: Locator;
  readonly searchInput: Locator;

  // List display
  readonly accessLists: Locator;
  readonly accessListItems: Locator;
  readonly emptyState: Locator;
  readonly loadingState: Locator;

  // Form modal elements
  readonly modal: Locator;
  readonly nameInput: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;

  // IP management
  readonly allowedIpsSection: Locator;
  readonly deniedIpsSection: Locator;
  readonly addAllowedIpButton: Locator;
  readonly addDeniedIpButton: Locator;
  readonly ipInput: Locator;
  readonly ipChips: Locator;

  // Status messages
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /access.*list/i }).first();
    this.addListButton = page.locator('button').filter({ hasText: /add|new|create/i }).first();
    this.searchInput = page.locator('input[type="search"], input[placeholder*="search"]');

    // List display
    this.accessLists = page.locator('main .space-y-4, main .grid, main > div').first();
    this.accessListItems = page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      has: page.locator('text=/acl|access|allow|deny/i'),
    });
    this.emptyState = page.locator('text=/no.*list|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Form modal
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.nameInput = page.locator('input[name*="name"], input[placeholder*="name"]').first();
    this.saveButton = page.locator('button').filter({ hasText: /save|submit|create/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel|close/i }).first();

    // IP management
    this.allowedIpsSection = page.locator('section, div').filter({ hasText: /allowed|whitelist/i }).first();
    this.deniedIpsSection = page.locator('section, div').filter({ hasText: /denied|blacklist|blocked/i }).first();
    this.addAllowedIpButton = page.locator('button').filter({ hasText: /add.*allow|allow.*ip/i }).first();
    this.addDeniedIpButton = page.locator('button').filter({ hasText: /add.*deny|deny.*ip|block/i }).first();
    this.ipInput = page.locator('input[placeholder*="IP"], input[name*="ip"]').first();
    this.ipChips = page.locator('[class*="chip"], [class*="tag"], .bg-slate-100, .bg-green-100, .bg-red-100');

    // Status messages
    this.successMessage = page.locator('text=/success|saved|created/i');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
  }

  /**
   * Navigate to access lists page.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.accessLists);
    await this.waitForLoad();
  }

  /**
   * Wait for page to load.
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await Promise.race([
      this.accessListItems.first().waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.emptyState.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.addListButton.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }),
    ]);
  }

  /**
   * Click add list button.
   */
  async clickAddList(): Promise<void> {
    await this.addListButton.click();
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Get count of access lists.
   */
  async getListCount(): Promise<number> {
    return await this.accessListItems.count();
  }

  /**
   * Get list by name.
   */
  getListByName(name: string): Locator {
    return this.page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      hasText: name,
    }).first();
  }

  /**
   * Fill list name.
   */
  async fillName(name: string): Promise<void> {
    await this.nameInput.fill(name);
  }

  /**
   * Add an allowed IP address.
   */
  async addAllowedIp(ip: string): Promise<void> {
    // Find the allowed IPs section input
    const input = this.allowedIpsSection.locator('input[placeholder*="IP"], input').first().or(this.ipInput);
    await input.fill(ip);

    const addBtn = this.allowedIpsSection.locator('button').filter({ hasText: /add|\+/ }).first().or(this.addAllowedIpButton);
    if (await addBtn.isVisible()) {
      await addBtn.click();
    } else {
      await input.press('Enter');
    }
    await this.page.waitForTimeout(200);
  }

  /**
   * Add multiple allowed IP addresses.
   */
  async addAllowedIps(ips: string[]): Promise<void> {
    for (const ip of ips) {
      await this.addAllowedIp(ip);
    }
  }

  /**
   * Add a denied IP address.
   */
  async addDeniedIp(ip: string): Promise<void> {
    const input = this.deniedIpsSection.locator('input[placeholder*="IP"], input').first().or(this.ipInput);
    await input.fill(ip);

    const addBtn = this.deniedIpsSection.locator('button').filter({ hasText: /add|\+/ }).first().or(this.addDeniedIpButton);
    if (await addBtn.isVisible()) {
      await addBtn.click();
    } else {
      await input.press('Enter');
    }
    await this.page.waitForTimeout(200);
  }

  /**
   * Add multiple denied IP addresses.
   */
  async addDeniedIps(ips: string[]): Promise<void> {
    for (const ip of ips) {
      await this.addDeniedIp(ip);
    }
  }

  /**
   * Create a new access list.
   */
  async createList(config: {
    name: string;
    allowedIps?: string[];
    deniedIps?: string[];
  }): Promise<void> {
    await this.clickAddList();
    await this.fillName(config.name);

    if (config.allowedIps?.length) {
      await this.addAllowedIps(config.allowedIps);
    }

    if (config.deniedIps?.length) {
      await this.addDeniedIps(config.deniedIps);
    }

    await this.save();
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
   * Click on list to edit.
   */
  async clickList(name: string): Promise<void> {
    const list = this.getListByName(name);
    await list.click();
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Delete an access list.
   */
  async deleteList(name: string): Promise<void> {
    const list = this.getListByName(name);
    const deleteBtn = list.locator('button').filter({ hasText: /delete/i }).first();

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      const menuBtn = list.locator('button[title*="menu"], button:has(svg)').last();
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
   * Check if list exists.
   */
  async listExists(name: string): Promise<boolean> {
    return await this.getListByName(name).isVisible();
  }

  /**
   * Get IP count for a list.
   */
  async getListIpCount(name: string): Promise<{ allowed: number; denied: number }> {
    const list = this.getListByName(name);
    const allowedText = await list.locator('text=/\\d+.*allow/i').textContent().catch(() => '0');
    const deniedText = await list.locator('text=/\\d+.*deny|block/i').textContent().catch(() => '0');

    return {
      allowed: parseInt(allowedText?.match(/\d+/)?.[0] || '0', 10),
      denied: parseInt(deniedText?.match(/\d+/)?.[0] || '0', 10),
    };
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
  async expectAccessListPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/access\/lists/);
    await expect(this.addListButton).toBeVisible({ timeout: TIMEOUTS.medium });
  }

  /**
   * Verify empty state is shown.
   */
  async expectEmptyState(): Promise<void> {
    await expect(this.emptyState).toBeVisible();
  }
}

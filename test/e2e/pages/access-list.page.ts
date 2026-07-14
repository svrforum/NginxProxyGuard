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

    // List display — redesigned to EntityCard-based cards (div.group.rounded-xl.border),
    // no longer a table. The EmptyState box uses rounded-xl/border but lacks `group`.
    this.accessLists = page.locator('main .space-y-4, main .grid, main > div').first();
    this.accessListItems = page.locator('main div.group.rounded-xl.border');
    this.emptyState = page.locator('text=/no access lists configured|no.*access.*list/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Form modal
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    // The form's first text input is the name field (inside the modal)
    this.nameInput = page.locator('.fixed.inset-0 input[type="text"], [role="dialog"] input[type="text"], input[name*="name"], input[placeholder*="name"]').first();
    this.saveButton = page.locator('.fixed.inset-0 button[type="submit"], [role="dialog"] button[type="submit"]').first();
    this.cancelButton = page.locator('.fixed.inset-0 button, [role="dialog"] button').filter({ hasText: /cancel|close/i }).first();

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
    return this.page.locator('main div.group.rounded-xl.border').filter({
      hasText: name,
    }).first();
  }

  /**
   * Fill list name (clears existing value first).
   */
  async fillName(name: string): Promise<void> {
    // Use the name input inside the modal's form grid (first text input in the grid-cols-2 row)
    const nameField = this.page.locator('.fixed.inset-0 .grid.grid-cols-2 input[type="text"]').first();
    await nameField.clear();
    await nameField.fill(name);
  }

  /**
   * Add an access rule item (the form uses a list of directive+address items).
   * Each item has a select (allow/deny), an address input, and a description input.
   */
  private async addRuleItem(directive: 'allow' | 'deny', ip: string): Promise<void> {
    // The form uses a space-y-2 container with flex rows containing a select and inputs.
    // Each row: <div class="flex gap-2 items-start"><select>...<input address>...<input desc>...
    const ruleRowSelector = '.fixed.inset-0 .flex.gap-2, [role="dialog"] .flex.gap-2';
    const ruleRows = this.page.locator(ruleRowSelector).filter({
      has: this.page.locator('select'),
    });

    // Find the last empty row or add a new one
    let targetRow = ruleRows.last();
    const lastAddress = await targetRow.locator('input[type="text"]').first().inputValue().catch(() => '');

    if (lastAddress.trim() !== '') {
      // All rows are filled, click "add rule" button (text: "+ Add Rule" or "+ 규칙 추가")
      const addRuleBtn = this.page.locator('.fixed.inset-0 button[type="button"], [role="dialog"] button[type="button"]')
        .filter({ hasText: /add.*rule|\+|규칙/i }).first();
      if (await addRuleBtn.isVisible()) {
        await addRuleBtn.click();
        await this.page.waitForTimeout(300);
      }
      // Re-query after adding
      targetRow = this.page.locator(ruleRowSelector).filter({
        has: this.page.locator('select'),
      }).last();
    }

    // Set directive
    const select = targetRow.locator('select').first();
    await select.selectOption(directive);

    // Set IP address (first text input in the row)
    const addressInput = targetRow.locator('input[type="text"]').first();
    await addressInput.fill(ip);
    await this.page.waitForTimeout(100);
  }

  /**
   * Add an allowed IP address.
   */
  async addAllowedIp(ip: string): Promise<void> {
    await this.addRuleItem('allow', ip);
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
    await this.addRuleItem('deny', ip);
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
    await Promise.race([
      this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.long }),
      this.errorMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.long }),
    ]).catch(() => null);
    // Wait for React Query to refetch the list after modal closes
    await this.page.waitForLoadState('networkidle');
    // Extra wait for list to re-render with new data
    await this.page.waitForTimeout(500);
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
   * The access list cards expose an icon-only edit button (aria-label / title = "Edit").
   */
  async clickList(name: string): Promise<void> {
    const list = this.getListByName(name);
    const editBtn = list.getByRole('button', { name: /edit/i }).first();
    if (await editBtn.isVisible()) {
      await editBtn.click();
    } else {
      await list.click();
    }
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Delete an access list.
   * The access list component uses a browser confirm() dialog.
   */
  async deleteList(name: string): Promise<void> {
    const list = this.getListByName(name);
    const deleteBtn = list.getByRole('button', { name: /delete/i }).first();

    // Set up dialog handler for the browser confirm() dialog
    this.page.once('dialog', async dialog => {
      await dialog.accept();
    });

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      const menuBtn = list.locator('button[title*="menu"], button:has(svg)').last();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /delete/i }).click();
      }
    }

    await this.page.waitForTimeout(500);
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

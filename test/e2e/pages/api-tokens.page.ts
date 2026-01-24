import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * API Tokens management page object model.
 */
export class ApiTokensPage extends BasePage {
  // Page elements
  readonly pageTitle: Locator;
  readonly addTokenButton: Locator;

  // Token list
  readonly tokenList: Locator;
  readonly tokenItems: Locator;
  readonly emptyState: Locator;
  readonly loadingState: Locator;

  // Form modal elements
  readonly modal: Locator;
  readonly nameInput: Locator;
  readonly expiresAtInput: Locator;
  readonly saveButton: Locator;
  readonly cancelButton: Locator;

  // Permissions
  readonly permissionsSection: Locator;
  readonly readAllCheckbox: Locator;
  readonly writeAllCheckbox: Locator;
  readonly permissionCheckboxes: Locator;

  // Token display (after creation)
  readonly tokenDisplay: Locator;
  readonly copyTokenButton: Locator;
  readonly tokenWarning: Locator;

  // Actions
  readonly revokeButton: Locator;
  readonly deleteButton: Locator;

  // Status messages
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /api.*token/i }).first();
    this.addTokenButton = page.locator('button').filter({ hasText: /add|new|create|generate/i }).first();

    // Token list
    this.tokenList = page.locator('main .space-y-4, main .grid, main > div, table').first();
    this.tokenItems = page.locator('[class*="card"], tr, .bg-white.rounded, .dark\\:bg-slate-800').filter({
      has: page.locator('text=/token|•••|\\*\\*\\*/i'),
    });
    this.emptyState = page.locator('text=/no.*token|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Form modal
    this.modal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.nameInput = page.locator('input[name*="name"], input[placeholder*="name"]').first();
    this.expiresAtInput = page.locator('input[type="date"], input[name*="expires"]').first();
    this.saveButton = page.locator('button').filter({ hasText: /save|create|generate/i }).first();
    this.cancelButton = page.locator('button').filter({ hasText: /cancel|close/i }).first();

    // Permissions
    this.permissionsSection = page.locator('section, div').filter({ hasText: /permission/i }).first();
    this.readAllCheckbox = page.locator('input[type="checkbox"]').filter({
      has: page.locator('text=/read.*all|all.*read/i'),
    }).first();
    this.writeAllCheckbox = page.locator('input[type="checkbox"]').filter({
      has: page.locator('text=/write.*all|all.*write/i'),
    }).first();
    this.permissionCheckboxes = page.locator('input[type="checkbox"][name*="permission"]');

    // Token display
    this.tokenDisplay = page.locator('code, [class*="token-display"], input[readonly]').first();
    this.copyTokenButton = page.locator('button').filter({ hasText: /copy/i }).first();
    this.tokenWarning = page.locator('text=/save.*token|only.*shown.*once|copy.*now/i');

    // Actions
    this.revokeButton = page.locator('button').filter({ hasText: /revoke/i }).first();
    this.deleteButton = page.locator('button').filter({ hasText: /delete/i }).first();

    // Status messages
    this.successMessage = page.locator('text=/success|created|generated/i');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
  }

  /**
   * Navigate to API tokens page.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.settingsApiTokens);
    await this.waitForLoad();
  }

  /**
   * Wait for page to load.
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await Promise.race([
      this.tokenItems.first().waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.emptyState.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.addTokenButton.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }),
    ]);
  }

  /**
   * Click add token button.
   */
  async clickAddToken(): Promise<void> {
    await this.addTokenButton.click();
    await this.modal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Get count of tokens.
   */
  async getTokenCount(): Promise<number> {
    return await this.tokenItems.count();
  }

  /**
   * Get token by name.
   */
  getTokenByName(name: string): Locator {
    return this.page.locator('[class*="card"], tr, .bg-white.rounded, .dark\\:bg-slate-800').filter({
      hasText: name,
    }).first();
  }

  /**
   * Fill token name.
   */
  async fillName(name: string): Promise<void> {
    await this.nameInput.fill(name);
  }

  /**
   * Set token expiration date.
   */
  async setExpiration(date: string): Promise<void> {
    if (await this.expiresAtInput.isVisible()) {
      await this.expiresAtInput.fill(date);
    }
  }

  /**
   * Select read all permission.
   */
  async selectReadAllPermission(): Promise<void> {
    if (await this.readAllCheckbox.isVisible()) {
      const isChecked = await this.readAllCheckbox.isChecked();
      if (!isChecked) {
        await this.readAllCheckbox.click();
      }
    }
  }

  /**
   * Select write all permission.
   */
  async selectWriteAllPermission(): Promise<void> {
    if (await this.writeAllCheckbox.isVisible()) {
      const isChecked = await this.writeAllCheckbox.isChecked();
      if (!isChecked) {
        await this.writeAllCheckbox.click();
      }
    }
  }

  /**
   * Select specific permissions.
   */
  async selectPermissions(permissions: string[]): Promise<void> {
    for (const permission of permissions) {
      const checkbox = this.page.locator(`input[type="checkbox"][value*="${permission}"], label:has-text("${permission}") input[type="checkbox"]`).first();
      if (await checkbox.isVisible()) {
        const isChecked = await checkbox.isChecked();
        if (!isChecked) {
          await checkbox.click();
        }
      }
    }
  }

  /**
   * Create a new API token.
   */
  async createToken(config: {
    name: string;
    permissions?: string[];
    readAll?: boolean;
    writeAll?: boolean;
    expiresAt?: string;
  }): Promise<string | null> {
    await this.clickAddToken();
    await this.fillName(config.name);

    if (config.expiresAt) {
      await this.setExpiration(config.expiresAt);
    }

    if (config.readAll) {
      await this.selectReadAllPermission();
    }

    if (config.writeAll) {
      await this.selectWriteAllPermission();
    }

    if (config.permissions?.length) {
      await this.selectPermissions(config.permissions);
    }

    await this.save();

    // Try to capture the generated token
    if (await this.tokenDisplay.isVisible()) {
      return await this.tokenDisplay.textContent();
    }

    return null;
  }

  /**
   * Copy the displayed token.
   */
  async copyToken(): Promise<void> {
    if (await this.copyTokenButton.isVisible()) {
      await this.copyTokenButton.click();
    }
  }

  /**
   * Save the form.
   */
  async save(): Promise<void> {
    await this.saveButton.click();
    await this.page.waitForTimeout(500);
    // Wait for either token display or error
    await Promise.race([
      this.tokenDisplay.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.errorMessage.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
    ]);
  }

  /**
   * Close the modal (after viewing token).
   */
  async closeModal(): Promise<void> {
    const closeBtn = this.modal.locator('button').filter({ hasText: /close|done|ok/i }).first();
    if (await closeBtn.isVisible()) {
      await closeBtn.click();
    } else if (await this.cancelButton.isVisible()) {
      await this.cancelButton.click();
    }
    await this.modal.waitFor({ state: 'hidden', timeout: TIMEOUTS.short });
  }

  /**
   * Revoke a token by name.
   */
  async revokeToken(name: string): Promise<void> {
    const token = this.getTokenByName(name);
    const revokeBtn = token.locator('button').filter({ hasText: /revoke/i }).first();

    if (await revokeBtn.isVisible()) {
      await revokeBtn.click();
    } else {
      // Try dropdown menu
      const menuBtn = token.locator('button[title*="menu"], button:has(svg)').last();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /revoke/i }).click();
      }
    }

    // Confirm revocation
    const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|revoke/i }).last();
    if (await confirmBtn.isVisible()) {
      await confirmBtn.click();
    }
    await this.waitForLoad();
  }

  /**
   * Delete a token by name.
   */
  async deleteToken(name: string): Promise<void> {
    const token = this.getTokenByName(name);
    const deleteBtn = token.locator('button').filter({ hasText: /delete/i }).first();

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      const menuBtn = token.locator('button[title*="menu"], button:has(svg)').last();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /delete/i }).click();
      }
    }

    // Confirm deletion
    const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|delete/i }).last();
    if (await confirmBtn.isVisible()) {
      await confirmBtn.click();
    }
    await this.waitForLoad();
  }

  /**
   * Check if token exists.
   */
  async tokenExists(name: string): Promise<boolean> {
    return await this.getTokenByName(name).isVisible();
  }

  /**
   * Get token last used time.
   */
  async getTokenLastUsed(name: string): Promise<string | null> {
    const token = this.getTokenByName(name);
    const lastUsed = token.locator('text=/last.*used|used/i').first();
    return await lastUsed.textContent();
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
  async expectApiTokensPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/settings\/api-tokens/);
    await expect(this.addTokenButton).toBeVisible({ timeout: TIMEOUTS.medium });
  }

  /**
   * Verify empty state is shown.
   */
  async expectEmptyState(): Promise<void> {
    await expect(this.emptyState).toBeVisible();
  }
}

import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Backup & Restore page object model.
 */
export class BackupPage extends BasePage {
  // Page elements
  readonly pageTitle: Locator;

  // Create backup section
  readonly createBackupButton: Locator;
  readonly backupProgressIndicator: Locator;

  // Backup list
  readonly backupList: Locator;
  readonly backupItems: Locator;
  readonly emptyState: Locator;
  readonly loadingState: Locator;

  // Backup item actions
  readonly downloadButton: Locator;
  readonly restoreButton: Locator;
  readonly deleteButton: Locator;

  // Restore modal
  readonly restoreModal: Locator;
  readonly confirmRestoreButton: Locator;
  readonly cancelRestoreButton: Locator;
  readonly restoreWarning: Locator;

  // Upload backup section
  readonly uploadSection: Locator;
  readonly fileInput: Locator;
  readonly uploadButton: Locator;

  // Status messages
  readonly successMessage: Locator;
  readonly errorMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /backup|restore/i }).first();

    // Create backup section
    this.createBackupButton = page.locator('button').filter({ hasText: /create.*backup|new.*backup|backup.*now/i }).first();
    this.backupProgressIndicator = page.locator('.animate-spin, [class*="progress"]');

    // Backup list
    this.backupList = page.locator('main .space-y-4, main .grid, table, main > div').first();
    this.backupItems = page.locator('[class*="card"], tr, .bg-white.rounded, .dark\\:bg-slate-800').filter({
      has: page.locator('text=/\\.zip|\\.tar|backup|\\d{4}-\\d{2}-\\d{2}/i'),
    });
    this.emptyState = page.locator('text=/no.*backup|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Backup item actions
    this.downloadButton = page.locator('button, a').filter({ hasText: /download/i }).first();
    this.restoreButton = page.locator('button').filter({ hasText: /restore/i }).first();
    this.deleteButton = page.locator('button').filter({ hasText: /delete/i }).first();

    // Restore modal
    this.restoreModal = page.locator('.fixed.inset-0, [role="dialog"], [class*="modal"]').first();
    this.confirmRestoreButton = page.locator('button').filter({ hasText: /confirm.*restore|yes.*restore|restore/i }).last();
    this.cancelRestoreButton = page.locator('button').filter({ hasText: /cancel/i }).first();
    this.restoreWarning = page.locator('text=/warning|caution|destructive|overwrite/i');

    // Upload backup section
    this.uploadSection = page.locator('section, div').filter({ hasText: /upload|import/i }).first();
    this.fileInput = page.locator('input[type="file"]').first();
    this.uploadButton = page.locator('button').filter({ hasText: /upload|import/i }).first();

    // Status messages
    this.successMessage = page.locator('text=/success|created|complete|restored/i');
    this.errorMessage = page.locator('.text-red-500, .text-red-600, [class*="error"]');
  }

  /**
   * Navigate to backups page.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.settingsBackups);
    await this.waitForLoad();
  }

  /**
   * Wait for page to load.
   */
  async waitForLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await Promise.race([
      this.backupItems.first().waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.emptyState.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.createBackupButton.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }),
    ]);
  }

  /**
   * Create a new backup.
   */
  async createBackup(): Promise<void> {
    await this.createBackupButton.click();
    // Wait for backup to complete
    await this.page.waitForSelector('.animate-spin', { state: 'visible', timeout: TIMEOUTS.short }).catch(() => null);
    await this.page.waitForSelector('.animate-spin', { state: 'hidden', timeout: TIMEOUTS.veryLong }).catch(() => null);
    await this.waitForLoad();
  }

  /**
   * Get count of backups.
   */
  async getBackupCount(): Promise<number> {
    return await this.backupItems.count();
  }

  /**
   * Get backup by filename or date pattern.
   */
  getBackupByName(namePattern: string): Locator {
    return this.page.locator('[class*="card"], tr, .bg-white.rounded, .dark\\:bg-slate-800').filter({
      hasText: new RegExp(namePattern, 'i'),
    }).first();
  }

  /**
   * Get the most recent backup.
   */
  getMostRecentBackup(): Locator {
    return this.backupItems.first();
  }

  /**
   * Download a backup.
   */
  async downloadBackup(namePattern: string): Promise<void> {
    const backup = this.getBackupByName(namePattern);
    const downloadBtn = backup.locator('button, a').filter({ hasText: /download/i }).first();

    if (await downloadBtn.isVisible()) {
      // Setup download listener
      const [download] = await Promise.all([
        this.page.waitForEvent('download'),
        downloadBtn.click(),
      ]);
      // Could save the download if needed
      await download.path();
    }
  }

  /**
   * Restore from a backup (DESTRUCTIVE OPERATION).
   */
  async restoreBackup(namePattern: string): Promise<void> {
    const backup = this.getBackupByName(namePattern);
    const restoreBtn = backup.locator('button').filter({ hasText: /restore/i }).first();

    if (await restoreBtn.isVisible()) {
      await restoreBtn.click();
    } else {
      // Try dropdown menu
      const menuBtn = backup.locator('button[title*="menu"], button:has(svg)').last();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /restore/i }).click();
      }
    }

    // Wait for confirmation modal
    await this.restoreModal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
  }

  /**
   * Confirm restore operation.
   */
  async confirmRestore(): Promise<void> {
    await this.confirmRestoreButton.click();
    // Wait for restore to complete
    await this.page.waitForSelector('.animate-spin', { state: 'visible', timeout: TIMEOUTS.short }).catch(() => null);
    await this.page.waitForSelector('.animate-spin', { state: 'hidden', timeout: TIMEOUTS.veryLong }).catch(() => null);
  }

  /**
   * Cancel restore operation.
   */
  async cancelRestore(): Promise<void> {
    await this.cancelRestoreButton.click();
    await this.restoreModal.waitFor({ state: 'hidden', timeout: TIMEOUTS.short });
  }

  /**
   * Delete a backup.
   */
  async deleteBackup(namePattern: string): Promise<void> {
    const backup = this.getBackupByName(namePattern);
    const deleteBtn = backup.locator('button').filter({ hasText: /delete/i }).first();

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      // Try dropdown menu
      const menuBtn = backup.locator('button[title*="menu"], button:has(svg)').last();
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
   * Upload a backup file.
   */
  async uploadBackup(filePath: string): Promise<void> {
    await this.fileInput.setInputFiles(filePath);
    if (await this.uploadButton.isVisible()) {
      await this.uploadButton.click();
    }
    await this.page.waitForTimeout(1000);
  }

  /**
   * Check if backup exists.
   */
  async backupExists(namePattern: string): Promise<boolean> {
    return await this.getBackupByName(namePattern).isVisible();
  }

  /**
   * Get backup size.
   */
  async getBackupSize(namePattern: string): Promise<string | null> {
    const backup = this.getBackupByName(namePattern);
    const sizeText = await backup.locator('text=/\\d+.*[KMG]?B|bytes/i').first().textContent();
    return sizeText;
  }

  /**
   * Get backup date.
   */
  async getBackupDate(namePattern: string): Promise<string | null> {
    const backup = this.getBackupByName(namePattern);
    const dateText = await backup.locator('text=/\\d{4}-\\d{2}-\\d{2}|\\d{1,2}\\/\\d{1,2}\\/\\d{4}/').first().textContent();
    return dateText;
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
   * Verify page is loaded correctly.
   */
  async expectBackupPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/settings\/backups/);
    await expect(this.createBackupButton).toBeVisible({ timeout: TIMEOUTS.medium });
  }

  /**
   * Verify empty state is shown.
   */
  async expectEmptyState(): Promise<void> {
    await expect(this.emptyState).toBeVisible();
  }
}

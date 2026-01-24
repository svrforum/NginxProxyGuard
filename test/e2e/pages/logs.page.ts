import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Logs page object model.
 */
export class LogsPage extends BasePage {
  // Sub-navigation
  readonly accessTab: Locator;
  readonly wafEventsTab: Locator;
  readonly botFilterTab: Locator;
  readonly exploitBlocksTab: Locator;
  readonly systemTab: Locator;
  readonly auditTab: Locator;
  readonly rawFilesTab: Locator;

  // Log list
  readonly logList: Locator;
  readonly logItems: Locator;
  readonly emptyState: Locator;
  readonly loadingState: Locator;

  // Filters
  readonly searchInput: Locator;
  readonly dateFilter: Locator;
  readonly statusFilter: Locator;
  readonly filterButton: Locator;
  readonly clearFiltersButton: Locator;

  // Log details
  readonly logDetailModal: Locator;
  readonly logDetailClose: Locator;

  // Pagination
  readonly prevPageButton: Locator;
  readonly nextPageButton: Locator;
  readonly pageInfo: Locator;

  constructor(page: Page) {
    super(page);

    // Sub-navigation tabs
    this.accessTab = page.locator('button, [role="tab"]').filter({ hasText: /^access$/i }).first();
    this.wafEventsTab = page.locator('button, [role="tab"]').filter({ hasText: /waf.*event/i }).first();
    this.botFilterTab = page.locator('button, [role="tab"]').filter({ hasText: /bot.*filter/i }).first();
    this.exploitBlocksTab = page.locator('button, [role="tab"]').filter({ hasText: /exploit.*block/i }).first();
    this.systemTab = page.locator('button, [role="tab"]').filter({ hasText: /system/i }).first();
    this.auditTab = page.locator('button, [role="tab"]').filter({ hasText: /audit/i }).first();
    this.rawFilesTab = page.locator('button, [role="tab"]').filter({ hasText: /raw.*file/i }).first();

    // Log list
    this.logList = page.locator('table, [class*="log-list"], [class*="logs"]').first();
    this.logItems = page.locator('tr, [class*="log-item"], [class*="log-row"]');
    this.emptyState = page.locator('text=/no.*log|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Filters
    this.searchInput = page.locator('input[type="search"], input[placeholder*="search"]');
    this.dateFilter = page.locator('input[type="date"], button').filter({ has: page.locator('text=/date|period/i') }).first();
    this.statusFilter = page.locator('select, button').filter({ has: page.locator('text=/status/i') }).first();
    this.filterButton = page.locator('button').filter({ hasText: /filter|apply/i }).first();
    this.clearFiltersButton = page.locator('button').filter({ hasText: /clear|reset/i }).first();

    // Log details
    this.logDetailModal = page.locator('[class*="modal"], [role="dialog"]');
    this.logDetailClose = this.logDetailModal.locator('button').filter({ hasText: /close/i }).first();

    // Pagination
    this.prevPageButton = page.locator('button').filter({ hasText: /prev|<|previous/i }).first();
    this.nextPageButton = page.locator('button').filter({ hasText: /next|>|following/i }).first();
    this.pageInfo = page.locator('text=/page.*\\d+|\\d+.*of.*\\d+/i');
  }

  /**
   * Navigate to access logs.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.logsAccess);
  }

  /**
   * Navigate to WAF events.
   */
  async gotoWafEvents(): Promise<void> {
    await super.goto(ROUTES.logsWafEvents);
  }

  /**
   * Navigate to bot filter logs.
   */
  async gotoBotFilter(): Promise<void> {
    await super.goto(ROUTES.logsBotFilter);
  }

  /**
   * Navigate to exploit blocks.
   */
  async gotoExploitBlocks(): Promise<void> {
    await super.goto(ROUTES.logsExploitBlocks);
  }

  /**
   * Navigate to system logs.
   */
  async gotoSystem(): Promise<void> {
    await super.goto(ROUTES.logsSystem);
  }

  /**
   * Navigate to audit logs.
   */
  async gotoAudit(): Promise<void> {
    await super.goto(ROUTES.logsAudit);
  }

  /**
   * Navigate to raw files.
   */
  async gotoRawFiles(): Promise<void> {
    await super.goto(ROUTES.logsRawFiles);
  }

  /**
   * Switch to access tab.
   */
  async switchToAccess(): Promise<void> {
    await this.accessTab.click();
    await this.page.waitForURL(/\/logs\/access/);
  }

  /**
   * Switch to WAF events tab.
   */
  async switchToWafEvents(): Promise<void> {
    await this.wafEventsTab.click();
    await this.page.waitForURL(/\/logs\/waf-events/);
  }

  /**
   * Switch to system tab.
   */
  async switchToSystem(): Promise<void> {
    await this.systemTab.click();
    await this.page.waitForURL(/\/logs\/system/);
  }

  /**
   * Switch to audit tab.
   */
  async switchToAudit(): Promise<void> {
    await this.auditTab.click();
    await this.page.waitForURL(/\/logs\/audit/);
  }

  /**
   * Get count of log entries.
   */
  async getLogCount(): Promise<number> {
    return await this.logItems.count();
  }

  /**
   * Search logs by text.
   */
  async searchLogs(query: string): Promise<void> {
    if (await this.searchInput.isVisible()) {
      await this.searchInput.fill(query);
      await this.page.waitForTimeout(500); // Debounce
    }
  }

  /**
   * Clear search filter.
   */
  async clearSearch(): Promise<void> {
    if (await this.searchInput.isVisible()) {
      await this.searchInput.clear();
      await this.page.waitForTimeout(500);
    }
  }

  /**
   * Click on a log entry to view details.
   */
  async viewLogDetails(index: number = 0): Promise<void> {
    const logItem = this.logItems.nth(index);
    if (await logItem.isVisible()) {
      await logItem.click();
      await this.logDetailModal.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });
    }
  }

  /**
   * Close log detail modal.
   */
  async closeLogDetails(): Promise<void> {
    if (await this.logDetailModal.isVisible()) {
      await this.logDetailClose.click();
      await this.logDetailModal.waitFor({ state: 'hidden', timeout: TIMEOUTS.short });
    }
  }

  /**
   * Go to next page.
   */
  async nextPage(): Promise<void> {
    if (await this.nextPageButton.isEnabled()) {
      await this.nextPageButton.click();
      await this.page.waitForTimeout(500);
    }
  }

  /**
   * Go to previous page.
   */
  async prevPage(): Promise<void> {
    if (await this.prevPageButton.isEnabled()) {
      await this.prevPageButton.click();
      await this.page.waitForTimeout(500);
    }
  }

  /**
   * Verify logs page is loaded correctly.
   */
  async expectLogsPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/logs/);
  }

  /**
   * Wait for logs to load.
   */
  async waitForLogsLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await Promise.race([
      this.logItems.first().waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.emptyState.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.page.waitForTimeout(TIMEOUTS.short),
    ]);
  }
}

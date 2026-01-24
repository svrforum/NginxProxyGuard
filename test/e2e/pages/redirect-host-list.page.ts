import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Redirect Host List page object model.
 */
export class RedirectHostListPage extends BasePage {
  // Page header
  readonly pageTitle: Locator;
  readonly addHostButton: Locator;
  readonly searchInput: Locator;
  readonly filterButton: Locator;

  // Host list
  readonly hostList: Locator;
  readonly hostItems: Locator;
  readonly emptyState: Locator;
  readonly loadingState: Locator;

  // Bulk actions
  readonly selectAllCheckbox: Locator;
  readonly bulkDeleteButton: Locator;
  readonly bulkSyncButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page header
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /redirect.*host/i }).first();
    this.addHostButton = page.locator('button').filter({ hasText: /add|new|create/i }).first();
    this.searchInput = page.locator('input[type="search"], input[placeholder*="search"], input[placeholder*="Search"]');
    this.filterButton = page.locator('button').filter({ hasText: /filter/i });

    // Host list
    this.hostList = page.locator('main .space-y-4, main .grid, main > div').first();
    this.hostItems = page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      has: page.locator('text=/\\.(com|local|net|org|io)|redirect|301|302|307|308/i'),
    });
    this.emptyState = page.locator('text=/no.*redirect|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Bulk actions
    this.selectAllCheckbox = page.locator('input[type="checkbox"]').first();
    this.bulkDeleteButton = page.locator('button').filter({ hasText: /delete.*selected/i });
    this.bulkSyncButton = page.locator('button').filter({ hasText: /sync.*selected/i });
  }

  /**
   * Navigate to redirect hosts list.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.redirectHosts);
    await this.waitForHostsLoad();
  }

  /**
   * Wait for hosts to load.
   */
  async waitForHostsLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await Promise.race([
      this.hostItems.first().waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.emptyState.waitFor({ state: 'visible', timeout: TIMEOUTS.medium }).catch(() => null),
      this.page.waitForTimeout(TIMEOUTS.short),
    ]);
  }

  /**
   * Click add new host button.
   */
  async clickAddHost(): Promise<void> {
    await this.addHostButton.click();
    await this.page.waitForSelector('[class*="modal"], [role="dialog"], .fixed.inset-0', {
      state: 'visible',
      timeout: TIMEOUTS.medium,
    });
  }

  /**
   * Get count of visible redirect hosts.
   */
  async getHostCount(): Promise<number> {
    return await this.hostItems.count();
  }

  /**
   * Search for hosts by name.
   */
  async searchHosts(query: string): Promise<void> {
    if (await this.searchInput.isVisible()) {
      await this.searchInput.fill(query);
      await this.page.waitForTimeout(500);
      await this.waitForHostsLoad();
    }
  }

  /**
   * Clear search filter.
   */
  async clearSearch(): Promise<void> {
    if (await this.searchInput.isVisible()) {
      await this.searchInput.clear();
      await this.waitForHostsLoad();
    }
  }

  /**
   * Get host card by domain name.
   */
  getHostByDomain(domain: string): Locator {
    return this.page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      hasText: domain,
    }).first();
  }

  /**
   * Click on a host to edit.
   */
  async clickHost(domain: string): Promise<void> {
    const hostCard = this.getHostByDomain(domain);
    await hostCard.click();
    await this.page.waitForSelector('[class*="modal"], [role="dialog"], .fixed.inset-0', {
      state: 'visible',
      timeout: TIMEOUTS.medium,
    });
  }

  /**
   * Get redirect code displayed for a host.
   */
  async getHostRedirectCode(domain: string): Promise<number | null> {
    const hostCard = this.getHostByDomain(domain);
    const codeText = await hostCard.locator('text=/301|302|303|307|308/').first().textContent();
    return codeText ? parseInt(codeText, 10) : null;
  }

  /**
   * Get target domain displayed for a host.
   */
  async getHostTargetDomain(domain: string): Promise<string | null> {
    const hostCard = this.getHostByDomain(domain);
    const targetLocator = hostCard.locator('text=/https?:\\/\\//').first();
    return await targetLocator.textContent();
  }

  /**
   * Delete a host by domain name.
   */
  async deleteHost(domain: string): Promise<void> {
    const hostCard = this.getHostByDomain(domain);
    const deleteBtn = hostCard.locator('button').filter({ hasText: /delete/i }).first();

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      const menuBtn = hostCard.locator('button[title*="menu"], button:has(svg[class*="dots"])').first();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /delete/i }).click();
      }
    }

    // Confirm deletion
    const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|delete/i }).last();
    await confirmBtn.click();
    await this.waitForHostsLoad();
  }

  /**
   * Check if a host exists by domain.
   */
  async hostExists(domain: string): Promise<boolean> {
    const hostCard = this.getHostByDomain(domain);
    return await hostCard.isVisible();
  }

  /**
   * Get host enabled/disabled status.
   */
  async isHostEnabled(domain: string): Promise<boolean> {
    const hostCard = this.getHostByDomain(domain);
    const enabledIndicator = hostCard.locator('[class*="green"], .bg-green, text=/enabled/i').first();
    return await enabledIndicator.isVisible();
  }

  /**
   * Toggle host enabled state.
   */
  async toggleHostEnabled(domain: string): Promise<void> {
    const hostCard = this.getHostByDomain(domain);
    const toggle = hostCard.locator('input[type="checkbox"], button[role="switch"]').first();
    if (await toggle.isVisible()) {
      await toggle.click();
      await this.page.waitForTimeout(500);
    }
  }

  /**
   * Verify page is loaded correctly.
   */
  async expectRedirectHostList(): Promise<void> {
    await expect(this.page).toHaveURL(/\/redirect-hosts/);
    await expect(this.addHostButton).toBeVisible({ timeout: TIMEOUTS.medium });
  }

  /**
   * Verify empty state is shown.
   */
  async expectEmptyState(): Promise<void> {
    await expect(this.emptyState).toBeVisible();
  }

  /**
   * Verify hosts are displayed.
   */
  async expectHostsDisplayed(): Promise<void> {
    const count = await this.getHostCount();
    expect(count).toBeGreaterThan(0);
  }
}

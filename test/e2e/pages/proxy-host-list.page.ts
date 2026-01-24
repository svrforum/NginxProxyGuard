import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Proxy Host List page object model.
 */
export class ProxyHostListPage extends BasePage {
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
    this.pageTitle = page.locator('h1, h2').filter({ hasText: /proxy.*host/i }).first();
    this.addHostButton = page.locator('button').filter({ hasText: /add|new|create/i }).first();
    this.searchInput = page.locator('input[type="search"], input[placeholder*="search"], input[placeholder*="Search"]');
    this.filterButton = page.locator('button').filter({ hasText: /filter/i });

    // Host list - the main container with host items
    this.hostList = page.locator('main .space-y-4, main .grid, main > div').first();
    this.hostItems = page.locator('[class*="card"], .bg-white.rounded, .dark\\:bg-slate-800').filter({
      has: page.locator('text=/\\.(com|local|net|org|io)/i'),
    });
    this.emptyState = page.locator('text=/no.*host|empty|no.*data/i');
    this.loadingState = page.locator('.animate-spin, .animate-pulse');

    // Bulk actions
    this.selectAllCheckbox = page.locator('input[type="checkbox"]').first();
    this.bulkDeleteButton = page.locator('button').filter({ hasText: /delete.*selected/i });
    this.bulkSyncButton = page.locator('button').filter({ hasText: /sync.*selected/i });
  }

  /**
   * Navigate to proxy hosts list.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.proxyHosts);
    await this.waitForHostsLoad();
  }

  /**
   * Wait for hosts to load.
   */
  async waitForHostsLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    // Wait for either hosts to appear or empty state
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
    // Wait for form modal to appear
    await this.page.waitForSelector('[class*="modal"], [role="dialog"], .fixed.inset-0', {
      state: 'visible',
      timeout: TIMEOUTS.medium,
    });
  }

  /**
   * Get count of visible proxy hosts.
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
      await this.page.waitForTimeout(500); // Debounce
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
    // Wait for form/modal
    await this.page.waitForSelector('[class*="modal"], [role="dialog"], .fixed.inset-0', {
      state: 'visible',
      timeout: TIMEOUTS.medium,
    });
  }

  /**
   * Get edit button for a specific host.
   */
  getEditButton(domain: string): Locator {
    const hostCard = this.getHostByDomain(domain);
    return hostCard.locator('button').filter({ hasText: /edit/i }).first();
  }

  /**
   * Get delete button for a specific host.
   */
  getDeleteButton(domain: string): Locator {
    const hostCard = this.getHostByDomain(domain);
    return hostCard.locator('button').filter({ hasText: /delete/i }).first();
  }

  /**
   * Get test button for a specific host.
   */
  getTestButton(domain: string): Locator {
    const hostCard = this.getHostByDomain(domain);
    return hostCard.locator('button[title*="test"], button:has(svg[class*="play"])').first();
  }

  /**
   * Delete a host by domain name.
   */
  async deleteHost(domain: string): Promise<void> {
    const hostCard = this.getHostByDomain(domain);
    // Look for delete button or three-dot menu
    const deleteBtn = hostCard.locator('button').filter({ hasText: /delete/i }).first();

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      // Try finding in dropdown menu
      const menuBtn = hostCard.locator('button[title*="menu"], button:has(svg[class*="dots"])').first();
      if (await menuBtn.isVisible()) {
        await menuBtn.click();
        await this.page.locator('button, [role="menuitem"]').filter({ hasText: /delete/i }).click();
      }
    }

    // Confirm deletion in dialog
    const confirmBtn = this.page.locator('button').filter({ hasText: /confirm|yes|delete/i }).last();
    await confirmBtn.click();

    // Wait for host to be removed
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
   * Get host status indicator.
   */
  async getHostStatus(domain: string): Promise<'online' | 'offline' | 'unknown'> {
    const hostCard = this.getHostByDomain(domain);
    const statusIndicator = hostCard.locator('[class*="green"], [class*="red"], .bg-green, .bg-red').first();

    if (await statusIndicator.isVisible()) {
      const classes = await statusIndicator.getAttribute('class') || '';
      if (classes.includes('green')) return 'online';
      if (classes.includes('red')) return 'offline';
    }
    return 'unknown';
  }

  /**
   * Verify page is loaded correctly.
   */
  async expectProxyHostList(): Promise<void> {
    await expect(this.page).toHaveURL(/\/proxy-hosts/);
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

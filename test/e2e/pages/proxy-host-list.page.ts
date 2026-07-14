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
    this.addHostButton = page.locator('button').filter({ hasText: /add\s*proxy\s*host/i }).first();
    // Search input: type="text" with search icon (pl-9 padding-left for icon), or type="search"
    this.searchInput = page.locator('input[type="search"], input[type="text"].pl-9, input[type="text"][class*="pl-9"]').first();
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
      await this.page.waitForTimeout(800); // Wait for debounce (UI uses 300ms) + API response
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
   * Get host row by domain name (supports both table and card layouts).
   */
  getHostByDomain(domain: string): Locator {
    // Try table row first (primary layout), then card-based fallback
    return this.page.locator('tr, [class*="card"], .bg-white.rounded').filter({
      hasText: domain,
    }).first();
  }

  /**
   * Click on a host to edit (clicks the edit button in the actions column).
   * The edit button is an icon-only button with a title attribute set via i18n.
   */
  async clickHost(domain: string): Promise<void> {
    const hostRow = this.getHostByDomain(domain);
    await hostRow.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });

    // The edit button is the second action button in the row (after test config).
    // It has a pencil SVG icon and a title attribute ("Edit" in English, "수정" in Korean).
    const editButton = hostRow.locator('button[title="Edit"], button[title="수정"]').first();
    if (await editButton.isVisible()) {
      await editButton.click();
    } else {
      // Fallback: use accessible name matching (title provides accessible name for icon-only buttons)
      const roleButton = hostRow.getByRole('button', { name: /Edit|수정/ });
      if (await roleButton.first().isVisible()) {
        await roleButton.first().click();
      } else {
        // Last resort: click the second button in the actions column (edit is second after test)
        const actionButtons = hostRow.locator('td:last-child button, div.flex.justify-end button');
        const secondButton = actionButtons.nth(1);
        await secondButton.click();
      }
    }
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
    // Icon-only button; accessible name / title comes from i18n ("Edit" / "수정").
    return hostCard.locator('button[title="Edit"], button[title="수정"]').first();
  }

  /**
   * Get delete button for a specific host.
   */
  getDeleteButton(domain: string): Locator {
    const hostCard = this.getHostByDomain(domain);
    // Icon-only button; accessible name / title comes from i18n ("Delete" / "삭제").
    return hostCard.locator('button[title="Delete"], button[title="삭제"]').first();
  }

  /**
   * Get test button for a specific host.
   */
  getTestButton(domain: string): Locator {
    const hostCard = this.getHostByDomain(domain);
    return hostCard.locator('button[title*="test"], button:has(svg[class*="play"])').first();
  }

  /**
   * Delete a host by domain name. Uses native confirm() dialog.
   */
  async deleteHost(domain: string): Promise<void> {
    const hostRow = this.getHostByDomain(domain);
    await hostRow.waitFor({ state: 'visible', timeout: TIMEOUTS.medium });

    // Delete button is the last action button in the row, with hover:text-red styling.
    // It has a title attribute "Delete" (en) or "삭제" (ko).
    const deleteBtn = hostRow.locator('button[title="Delete"], button[title="삭제"]').first();

    // Set up dialog handler before clicking delete (native confirm dialog)
    this.page.once('dialog', async (dialog) => {
      await dialog.accept();
    });

    if (await deleteBtn.isVisible()) {
      await deleteBtn.click();
    } else {
      // Fallback: click the last button in the actions area (delete is typically last)
      const lastBtn = hostRow.locator('td:last-child button, div.flex.justify-end button').last();
      await lastBtn.click();
    }

    // Wait for host to be removed
    await this.page.waitForTimeout(1000);
    await this.page.waitForLoadState('networkidle');
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

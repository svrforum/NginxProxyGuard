import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Dashboard page object model.
 */
export class DashboardPage extends BasePage {
  // Statistics cards
  readonly statsSection: Locator;
  readonly totalHostsCard: Locator;
  readonly activeHostsCard: Locator;
  readonly certificatesCard: Locator;
  readonly requestsCard: Locator;

  // System status section
  readonly systemStatusSection: Locator;
  readonly nginxStatus: Locator;
  readonly apiStatus: Locator;
  readonly databaseStatus: Locator;

  // Quick actions
  readonly quickActionsSection: Locator;
  readonly addHostButton: Locator;
  readonly viewLogsButton: Locator;

  // Charts/Visualizations
  readonly trafficChart: Locator;
  readonly requestsChart: Locator;

  constructor(page: Page) {
    super(page);

    // Statistics cards in "Hosts Overview" section
    this.statsSection = page.locator('main section, main .grid').first();
    // Locate by the text labels in the Hosts Overview section
    this.totalHostsCard = page.locator('div').filter({ has: page.locator('text="Proxy Hosts"') }).first();
    this.activeHostsCard = page.locator('div').filter({ has: page.locator('text="Redirect Hosts"') }).first();
    this.certificatesCard = page.locator('div').filter({ has: page.locator('text="Certificates"') }).first();
    this.requestsCard = page.locator('div').filter({ has: page.locator('text="Requests (24h)"') }).first();

    // System status
    this.systemStatusSection = page.locator('section, div').filter({ hasText: /system.*status|status/i }).first();
    this.nginxStatus = page.locator('text=/nginx/i').first();
    this.apiStatus = page.locator('text=/api/i').first();
    this.databaseStatus = page.locator('text=/database|postgres/i').first();

    // Quick actions
    this.quickActionsSection = page.locator('section').filter({ hasText: /quick.*action/i });
    this.addHostButton = page.locator('button, a').filter({ hasText: /add.*host|new.*host/i }).first();
    this.viewLogsButton = page.locator('button, a').filter({ hasText: /view.*log|log/i }).first();

    // Charts
    this.trafficChart = page.locator('canvas, svg[class*="chart"], [class*="chart"]').first();
    this.requestsChart = page.locator('canvas, svg[class*="chart"], [class*="chart"]').nth(1);
  }

  /**
   * Navigate to dashboard.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.dashboard);
  }

  /**
   * Get total hosts count from dashboard.
   * Format is like "Proxy Hosts 0 / 0" where first number is enabled, second is total
   */
  async getTotalHostsCount(): Promise<number> {
    const text = await this.totalHostsCard.textContent() || '0';
    // Match pattern like "0 / 0" - second number is total
    const match = text.match(/(\d+)\s*\/\s*(\d+)/);
    if (match) {
      return parseInt(match[2], 10); // Return total (second number)
    }
    // Fallback to first number found
    const simpleMatch = text.match(/\d+/);
    return simpleMatch ? parseInt(simpleMatch[0], 10) : 0;
  }

  /**
   * Get active/enabled hosts count from dashboard.
   * Format is like "Proxy Hosts 0 / 0" where first number is enabled
   */
  async getActiveHostsCount(): Promise<number> {
    const text = await this.totalHostsCard.textContent() || '0';
    // Match pattern like "0 / 0" - first number is enabled
    const match = text.match(/(\d+)\s*\/\s*(\d+)/);
    if (match) {
      return parseInt(match[1], 10); // Return enabled (first number)
    }
    // Fallback to first number found
    const simpleMatch = text.match(/\d+/);
    return simpleMatch ? parseInt(simpleMatch[0], 10) : 0;
  }

  /**
   * Get certificates count from dashboard.
   */
  async getCertificatesCount(): Promise<number> {
    const text = await this.certificatesCard.textContent() || '0';
    const match = text.match(/\d+/);
    return match ? parseInt(match[0], 10) : 0;
  }

  /**
   * Click add host quick action.
   */
  async clickAddHost(): Promise<void> {
    await this.addHostButton.click();
  }

  /**
   * Click view logs quick action.
   */
  async clickViewLogs(): Promise<void> {
    await this.viewLogsButton.click();
    await this.page.waitForURL(/\/logs/);
  }

  /**
   * Verify dashboard is loaded correctly.
   */
  async expectDashboard(): Promise<void> {
    await expect(this.page).toHaveURL(/\/dashboard/);
    // Dashboard should have some content loaded
    await expect(this.statsSection).toBeVisible({ timeout: TIMEOUTS.medium });
  }

  /**
   * Verify system status indicators are visible.
   */
  async expectSystemStatus(): Promise<void> {
    // At least one status indicator should be visible
    const hasStatus = await this.nginxStatus.isVisible() ||
      await this.apiStatus.isVisible() ||
      await this.databaseStatus.isVisible();
    expect(hasStatus).toBeTruthy();
  }

  /**
   * Refresh dashboard data.
   */
  async refresh(): Promise<void> {
    await this.page.reload();
    await this.waitForPageLoad();
  }
}

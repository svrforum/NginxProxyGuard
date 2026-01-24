import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * Certificates page object model.
 */
export class CertificatesPage extends BasePage {
  // Sub-navigation
  readonly listTab: Locator;
  readonly historyTab: Locator;
  readonly dnsProvidersTab: Locator;

  // Certificate list
  readonly certificateList: Locator;
  readonly certificateItems: Locator;
  readonly addCertificateButton: Locator;
  readonly emptyState: Locator;

  // Certificate details
  readonly certificateDomain: Locator;
  readonly certificateExpiry: Locator;
  readonly certificateStatus: Locator;

  constructor(page: Page) {
    super(page);

    // Sub-navigation tabs
    this.listTab = page.locator('button, [role="tab"]').filter({ hasText: /list|certificate/i }).first();
    this.historyTab = page.locator('button, [role="tab"]').filter({ hasText: /history/i }).first();
    this.dnsProvidersTab = page.locator('button, [role="tab"]').filter({ hasText: /dns.*provider/i }).first();

    // Certificate list
    this.certificateList = page.locator('main .space-y-4, main .grid, main > div').first();
    this.certificateItems = page.locator('[class*="card"], .bg-white.rounded').filter({
      has: page.locator('text=/\\.(com|local|net|org|io)|certificate|ssl/i'),
    });
    this.addCertificateButton = page.locator('button').filter({ hasText: /add|new|create|request/i }).first();
    this.emptyState = page.locator('text=/no.*certificate|empty|no.*data/i');

    // Certificate details
    this.certificateDomain = page.locator('[class*="domain"], .font-medium');
    this.certificateExpiry = page.locator('text=/expire|valid.*until/i');
    this.certificateStatus = page.locator('[class*="status"], .badge');
  }

  /**
   * Navigate to certificates list.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.certificatesList);
  }

  /**
   * Navigate to certificate history.
   */
  async gotoHistory(): Promise<void> {
    await super.goto(ROUTES.certificatesHistory);
  }

  /**
   * Navigate to DNS providers.
   */
  async gotoDnsProviders(): Promise<void> {
    await super.goto(ROUTES.certificatesDnsProviders);
  }

  /**
   * Get count of certificates.
   */
  async getCertificateCount(): Promise<number> {
    return await this.certificateItems.count();
  }

  /**
   * Click add certificate button.
   */
  async clickAddCertificate(): Promise<void> {
    await this.addCertificateButton.click();
    await this.page.waitForSelector('[class*="modal"], [role="dialog"], .fixed.inset-0', {
      state: 'visible',
      timeout: TIMEOUTS.medium,
    });
  }

  /**
   * Verify page is loaded correctly.
   */
  async expectCertificatesPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/certificates/);
  }

  /**
   * Switch to list tab.
   */
  async switchToList(): Promise<void> {
    await this.listTab.click();
    await this.page.waitForURL(/\/certificates\/list/);
  }

  /**
   * Switch to history tab.
   */
  async switchToHistory(): Promise<void> {
    await this.historyTab.click();
    await this.page.waitForURL(/\/certificates\/history/);
  }

  /**
   * Switch to DNS providers tab.
   */
  async switchToDnsProviders(): Promise<void> {
    await this.dnsProvidersTab.click();
    await this.page.waitForURL(/\/certificates\/dns-providers/);
  }
}

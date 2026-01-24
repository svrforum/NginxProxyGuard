import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './base.page';
import { ROUTES, TIMEOUTS } from '../fixtures/test-data';

/**
 * WAF settings page object model.
 */
export class WAFPage extends BasePage {
  // Sub-navigation
  readonly settingsTab: Locator;
  readonly bannedIpsTab: Locator;
  readonly uriBlocksTab: Locator;
  readonly exploitRulesTab: Locator;
  readonly fail2banTab: Locator;
  readonly testerTab: Locator;

  // WAF Settings section
  readonly wafSettingsSection: Locator;
  readonly globalWafToggle: Locator;
  readonly wafModeSelect: Locator;
  readonly paranoiaLevelSelect: Locator;
  readonly saveButton: Locator;

  // Banned IPs section
  readonly bannedIpList: Locator;
  readonly bannedIpItems: Locator;
  readonly addBanButton: Locator;
  readonly unbanButton: Locator;

  // URI Blocks section
  readonly uriBlockList: Locator;
  readonly addUriBlockButton: Locator;

  // Exploit Rules section
  readonly exploitRulesList: Locator;
  readonly ruleToggle: Locator;

  // WAF Tester section
  readonly testerInput: Locator;
  readonly testButton: Locator;
  readonly testResult: Locator;

  constructor(page: Page) {
    super(page);

    // Sub-navigation tabs
    this.settingsTab = page.locator('button, [role="tab"]').filter({ hasText: /setting|rule/i }).first();
    this.bannedIpsTab = page.locator('button, [role="tab"]').filter({ hasText: /banned.*ip/i }).first();
    this.uriBlocksTab = page.locator('button, [role="tab"]').filter({ hasText: /uri.*block/i }).first();
    this.exploitRulesTab = page.locator('button, [role="tab"]').filter({ hasText: /exploit.*rule/i }).first();
    this.fail2banTab = page.locator('button, [role="tab"]').filter({ hasText: /fail2ban/i }).first();
    this.testerTab = page.locator('button, [role="tab"]').filter({ hasText: /test/i }).first();

    // WAF Settings
    this.wafSettingsSection = page.locator('main section, main .space-y-6').first();
    this.globalWafToggle = page.locator('input[type="checkbox"], button[role="switch"]').first();
    this.wafModeSelect = page.locator('select').filter({ has: page.locator('option:has-text("Detection")') }).first();
    this.paranoiaLevelSelect = page.locator('select').filter({ has: page.locator('option:has-text("1"), option:has-text("2")') }).first();
    this.saveButton = page.locator('button').filter({ hasText: /save|apply/i }).first();

    // Banned IPs
    this.bannedIpList = page.locator('table, [class*="list"]').first();
    this.bannedIpItems = page.locator('tr, [class*="item"]').filter({ has: page.locator('text=/\\d+\\.\\d+\\.\\d+\\.\\d+/') });
    this.addBanButton = page.locator('button').filter({ hasText: /add.*ban|ban.*ip/i }).first();
    this.unbanButton = page.locator('button').filter({ hasText: /unban|remove/i }).first();

    // URI Blocks
    this.uriBlockList = page.locator('table, [class*="list"]').first();
    this.addUriBlockButton = page.locator('button').filter({ hasText: /add.*block|block.*uri/i }).first();

    // Exploit Rules
    this.exploitRulesList = page.locator('[class*="rules"], [class*="list"]').first();
    this.ruleToggle = page.locator('input[type="checkbox"], button[role="switch"]');

    // WAF Tester
    this.testerInput = page.locator('input[type="text"], textarea').first();
    this.testButton = page.locator('button').filter({ hasText: /test|check/i }).first();
    this.testResult = page.locator('[class*="result"], [class*="output"]').first();
  }

  /**
   * Navigate to WAF settings.
   */
  async goto(): Promise<void> {
    await super.goto(ROUTES.wafSettings);
  }

  /**
   * Navigate to banned IPs.
   */
  async gotoBannedIps(): Promise<void> {
    await super.goto(ROUTES.wafBannedIps);
  }

  /**
   * Navigate to URI blocks.
   */
  async gotoUriBlocks(): Promise<void> {
    await super.goto(ROUTES.wafUriBlocks);
  }

  /**
   * Navigate to exploit rules.
   */
  async gotoExploitRules(): Promise<void> {
    await super.goto(ROUTES.wafExploitRules);
  }

  /**
   * Navigate to WAF tester.
   */
  async gotoTester(): Promise<void> {
    await super.goto(ROUTES.wafTester);
  }

  /**
   * Navigate to fail2ban.
   */
  async gotoFail2ban(): Promise<void> {
    await super.goto(ROUTES.wafFail2ban);
  }

  /**
   * Switch to settings tab.
   */
  async switchToSettings(): Promise<void> {
    await this.settingsTab.click();
    await this.page.waitForURL(/\/waf\/settings/);
  }

  /**
   * Switch to banned IPs tab.
   */
  async switchToBannedIps(): Promise<void> {
    await this.bannedIpsTab.click();
    await this.page.waitForURL(/\/waf\/banned-ips/);
  }

  /**
   * Switch to tester tab.
   */
  async switchToTester(): Promise<void> {
    await this.testerTab.click();
    await this.page.waitForURL(/\/waf\/tester/);
  }

  /**
   * Get count of banned IPs.
   */
  async getBannedIpCount(): Promise<number> {
    return await this.bannedIpItems.count();
  }

  /**
   * Test a payload using WAF tester.
   */
  async testPayload(payload: string): Promise<void> {
    await this.gotoTester();
    if (await this.testerInput.isVisible()) {
      await this.testerInput.fill(payload);
      await this.testButton.click();
      await this.page.waitForTimeout(1000);
    }
  }

  /**
   * Verify WAF page is loaded correctly.
   */
  async expectWAFPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/waf/);
  }
}

import { test, expect } from '@playwright/test';
import { ProxyHostListPage } from '../../pages/proxy-host-list.page';
import { ProxyHostFormPage } from '../../pages/proxy-host-form.page';
import { TestDataFactory } from '../../utils/test-data-factory';
import { APIHelper } from '../../utils/api-helper';
import { ROUTES } from '../../fixtures/test-data';
import { readHostModsecConfig, grepProxyConfigs, rateZoneName } from '../../utils/config-helper';

/**
 * #198 "global default + per-host tri-state override" — the behaviour the other
 * security specs do NOT cover: the global-default MANAGER pages and, crucially,
 * the INHERIT state (a host following the global default). Override/Disable are
 * already covered by waf.spec / bot-filter.spec.
 *
 * The resolution (global default → effective host config) happens in the service
 * layer before templating, so it is only observable in the rendered config file
 * (the API GET returns stored fields, e.g. waf_use_global=true, not the resolved
 * values). We therefore assert on the config the manager wrote — see config-helper.
 *
 * Serial + reset-to-off in afterEach: these tests mutate global singletons that
 * every host reads, so they must not leak into other (parallel) spec files.
 */
test.describe.serial('Global default security + per-host inherit (#198)', () => {
  let listPage: ProxyHostListPage;
  let formPage: ProxyHostFormPage;
  let apiHelper: APIHelper;

  test.beforeEach(async ({ page, request }) => {
    listPage = new ProxyHostListPage(page);
    formPage = new ProxyHostFormPage(page);
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Return the singletons to "off" so inheriting hosts in other specs are
    // unaffected, then remove hosts created here.
    await apiHelper.setGlobalWAF({ enabled: false }).catch(() => {});
    await apiHelper.setGlobalRateLimit({ enabled: false }).catch(() => {});
    await apiHelper.cleanupTestHosts();
  });

  // ---------- Global WAF manager page (new UI) ----------
  test('global WAF manager: enabling + setting mode persists (UI → API)', async ({ page }) => {
    await page.goto(ROUTES.wafGlobalWaf);

    // Enable toggle (custom pill button); its inner fields then appear.
    const enableToggle = page.locator('button.h-6.w-11.rounded-full').first();
    await enableToggle.waitFor({ state: 'visible' });
    await enableToggle.click();

    // Choose the non-default mode (Blocking) to prove the field round-trips.
    await page.locator('label').filter({ hasText: 'Blocking' }).first().click();

    await page.getByRole('button', { name: 'Save', exact: true }).first().click();

    await expect.poll(async () => (await apiHelper.getGlobalWAF()).enabled).toBe(true);
    const g = await apiHelper.getGlobalWAF();
    expect(g.mode).toBe('blocking');
  });

  // ---------- Per-host INHERIT follows the global WAF default ----------
  test('per-host Inherit follows the global WAF default (resolved config)', async () => {
    // Global default: detection mode, PL2, threshold 7 — all distinctive.
    await apiHelper.setGlobalWAF({ enabled: true, mode: 'detection', paranoia_level: 2, anomaly_threshold: 7 });

    const data = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost(data);

    // Drive the tri-state UI to Inherit (the third state, otherwise untested).
    await listPage.goto();
    await listPage.clickHost(data.domain_names[0]);
    await formPage.setWAF('inherit');
    await formPage.save();

    // Stored state: host is marked as inheriting.
    const hosts = await apiHelper.getProxyHosts();
    const host = hosts.find((h) => h.domain_names.includes(data.domain_names[0]));
    expect(host?.waf_use_global).toBe(true);

    // Resolved config PROVES the global default was applied to this host.
    await expect.poll(() => readHostModsecConfig(host!.id), { timeout: 10_000 })
      .toContain('SecRuleEngine DetectionOnly');
    const modsec = readHostModsecConfig(host!.id);
    expect(modsec).toContain('tx.blocking_paranoia_level=2');
    expect(modsec).toContain('tx.inbound_anomaly_score_threshold=7');

    // Sanity: mark unused to satisfy noUnusedLocals-style lint expectations.
    expect(created.id).toBeTruthy();
  });

  // ---------- Regression #202: enabling global WAF for an ALREADY-inheriting host ----------
  // The order that broke in the wild: a host is set to Inherit FIRST (while the
  // global default is off → no modsec file), THEN the operator enables the global
  // WAF default. That fires SyncAllConfigs, whose fan-out must regenerate the
  // per-host modsec file for hosts whose RESOLVED WAF flips on — otherwise the
  // proxy conf references a modsec file that was never written and `nginx -t`
  // fails, so the enable is rejected. (The other inherit test enables global
  // BEFORE the host inherits, so it exercises the per-host path and misses this.)
  test('enabling global WAF for an already-inheriting host does not fail nginx -t (#202)', async () => {
    const data = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost({ ...data, waf_use_global: true });

    // With the bug, this PUT returns 500 ("nginx config test failed") and throws.
    await apiHelper.setGlobalWAF({ enabled: true, mode: 'detection', paranoia_level: 2, anomaly_threshold: 7 });

    // The inheriting host's modsec file must now exist and reflect the global default.
    await expect.poll(() => readHostModsecConfig(created.id), { timeout: 10_000 })
      .toContain('SecRuleEngine DetectionOnly');
  });

  // ---------- Per-host DISABLE beats an enabled global WAF default ----------
  test('per-host Disable beats an enabled global WAF default', async () => {
    await apiHelper.setGlobalWAF({ enabled: true, mode: 'blocking' });

    const data = TestDataFactory.createProxyHost();
    await apiHelper.createProxyHost(data);

    await listPage.goto();
    await listPage.clickHost(data.domain_names[0]);
    await formPage.toggleWAF(false); // Disable
    await formPage.save();

    const hosts = await apiHelper.getProxyHosts();
    const host = hosts.find((h) => h.domain_names.includes(data.domain_names[0]));
    // WAF off for this host despite the global default being on → no active engine.
    await expect.poll(() => readHostModsecConfig(host!.id), { timeout: 10_000 })
      .not.toContain('SecRuleEngine On');
  });

  // ---------- Global rate-limit manager page (new UI) ----------
  test('global rate-limit manager: enabling persists (UI → API)', async ({ page }) => {
    await page.goto(ROUTES.wafGlobalRateLimit);

    const enableToggle = page.locator('button.h-6.w-11.rounded-full').first();
    await enableToggle.waitFor({ state: 'visible' });
    await enableToggle.click();

    await page.getByRole('button', { name: 'Save', exact: true }).first().click();

    await expect.poll(async () => (await apiHelper.getGlobalRateLimit()).enabled).toBe(true);
  });

  // ---------- Per-host INHERIT follows the global rate-limit default ----------
  test('per-host Inherit follows the global rate-limit default (resolved config)', async () => {
    const RPS = 33; // distinctive value no other host uses
    await apiHelper.setGlobalRateLimit({ enabled: true, requests_per_second: RPS, burst_size: 10 });

    // A freshly created host has no per-host rate-limit override and no disable
    // flag → it inherits, so its rendered conf must carry the global rate.
    const data = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost(data);

    const zone = rateZoneName(created.id);
    await expect.poll(() => grepProxyConfigs(zone), { timeout: 10_000 })
      .toContain(`rate=${RPS}r/s`);
  });
});

import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { TestDataFactory } from '../../utils/test-data-factory';

/**
 * Regression: issue #122
 *
 * After the Phase-2 "post-reload health probe" was added (PR #119), proxy-host
 * create/edit started failing whenever the operator had set Direct IP Access
 * Action = "Block (444)". The probe targeted `http://127.0.0.1:<port>/`; with
 * block_444 active nginx's catch-all does `return 444;` (drops the connection
 * silently), so curl came back with exit 52 / http_code=000. The reload engine
 * interpreted that as a failed reload and rolled back, surfacing
 *   "post-reload health probe failed: http probe: nginx did not accept
 *    connection on :<port>: exit status 52 (output: 000)"
 * to the user — even though nginx was perfectly healthy.
 *
 * These tests pin the fix: probe `/health` specifically, so the IP-block policy
 * on `/` no longer masks a live nginx as dead.
 *
 * Note: beforeAll flips the Direct IP policy to block_444 and afterAll restores
 * it. Each test creates its own APIHelper because Playwright disallows reusing
 * a { request } fixture from beforeAll inside a test.
 */
test.describe('Health probe with block_444 Direct IP policy (#122)', () => {
  let originalDirectIPAction: string | undefined;

  test.beforeAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const apiHelper = new APIHelper(ctx);
    try {
      await apiHelper.login();
      const current = await apiHelper.getGlobalSettings();
      originalDirectIPAction = current.direct_ip_access_action;
      await apiHelper.updateGlobalSettings({ direct_ip_access_action: 'block_444' });
    } finally {
      await ctx.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const apiHelper = new APIHelper(ctx);
    try {
      await apiHelper.login();
      if (originalDirectIPAction) {
        await apiHelper.updateGlobalSettings({ direct_ip_access_action: originalDirectIPAction });
      }
    } finally {
      await ctx.dispose();
    }
  });

  test('creating a proxy host succeeds (probe does not misread 444 drop as failure)', async ({ request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();
    const data = TestDataFactory.createProxyHost();

    const created = await apiHelper.createProxyHost(data);

    try {
      expect(created.id).toBeTruthy();
      expect(created.domain_names).toContain(data.domain_names[0]);
    } finally {
      await apiHelper.deleteProxyHost(created.id);
    }
  });

  test('editing a proxy host succeeds while block_444 is active', async ({ request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();
    const data = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost(data);

    try {
      const updated = await apiHelper.updateProxyHost(created.id, {
        forward_port: (data.forward_port ?? 8080) + 1,
      });

      expect(updated.id).toBe(created.id);
      expect(updated.forward_port).toBe((data.forward_port ?? 8080) + 1);
    } finally {
      await apiHelper.deleteProxyHost(created.id);
    }
  });

  test('deleting a proxy host succeeds while block_444 is active', async ({ request }) => {
    const apiHelper = new APIHelper(request);
    await apiHelper.login();
    const data = TestDataFactory.createProxyHost();
    const created = await apiHelper.createProxyHost(data);

    await apiHelper.deleteProxyHost(created.id);

    const listing = await apiHelper.getProxyHosts();
    expect(listing.find(h => h.id === created.id)).toBeUndefined();
  });
});

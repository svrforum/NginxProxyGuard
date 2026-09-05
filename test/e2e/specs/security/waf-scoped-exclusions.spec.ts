import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import { APIHelper } from '../../utils/api-helper';
import { TestDataFactory } from '../../utils/test-data-factory';

/**
 * Scoped WAF rule exclusions (#231) let an operator exempt one path or one
 * argument instead of switching a CRS rule off for a whole host. The storage key
 * is (host, rule, scope_type, scope_value), so several exemptions on one rule are
 * normal.
 *
 * The lookup, the duplicate test and the delete all keyed on the rule alone,
 * which made the second exemption fail outright and made removing one wipe the
 * rest (#286). These tests pin the behaviour that was missing.
 */
const API = 'http://127.0.0.1:19080';
const RULE = 942370; // SQLi rule the issue reporter used
const OTHER_RULE = 941100;

test.describe.configure({ mode: 'serial' });

test.describe('Scoped WAF rule exclusions (#286)', () => {
  let api: APIHelper;
  let token: string;
  let hostId = '';

  test.beforeAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const helper = new APIHelper(ctx);
    await helper.login();
    const created = await ctx.post(`${API}/api/v1/proxy-hosts`, {
      headers: { Authorization: `Bearer ${await helper.getToken()}` },
      data: {
        domain_names: [TestDataFactory.generateDomain('waf-scope')],
        forward_host: '127.0.0.1',
        forward_port: 19080,
        forward_scheme: 'http',
        waf_enabled: true,
        enabled: true,
      },
    });
    expect(created.ok(), `host creation failed: ${created.status()}`).toBeTruthy();
    hostId = (await created.json()).id;
    await ctx.dispose();
  });

  test.afterAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    const helper = new APIHelper(ctx);
    await helper.login();
    const auth = { Authorization: `Bearer ${await helper.getToken()}` };
    if (hostId) await ctx.delete(`${API}/api/v1/proxy-hosts/${hostId}`, { headers: auth });
    await ctx.dispose();
  });

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    token = await api.getToken();
  });

  const auth = () => ({ Authorization: `Bearer ${token}` });

  function disable(
    request: import('@playwright/test').APIRequestContext,
    ruleId: number,
    body: Record<string, unknown>
  ) {
    return request.post(`${API}/api/v1/waf/hosts/${hostId}/rules/${ruleId}/disable`, {
      headers: auth(),
      data: body,
    });
  }

  /** The rule as the policy screen sees it. */
  async function readRule(
    request: import('@playwright/test').APIRequestContext,
    ruleId: number
  ): Promise<{ enabled: boolean; scopes: string[] }> {
    const res = await request.get(`${API}/api/v1/waf/rules?proxy_host_id=${hostId}`, {
      headers: auth(),
    });
    const body = await res.json();
    for (const cat of body.categories ?? []) {
      for (const rule of cat.rules ?? []) {
        if (rule.id === ruleId) {
          return {
            enabled: rule.enabled,
            scopes: (rule.exclusions ?? []).map(
              (e: { scope_type: string; scope_value?: string }) => `${e.scope_type}:${e.scope_value ?? ''}`
            ),
          };
        }
      }
    }
    // Returning a plausible default here would make two of the assertions below
    // pass for the wrong reason — "enabled" is exactly what they expect.
    throw new Error(`rule ${ruleId} not present in /waf/rules for host ${hostId}`);
  }

  test('accepts a second scope on the same rule', async ({ request }) => {
    expect((await disable(request, RULE, { scope_type: 'uri', scope_value: '/api/a' })).status()).toBe(201);
    // This is the reported failure: it answered 500 with a Scan column mismatch,
    // because the lookup keyed on the rule and could not read a stored scope.
    expect((await disable(request, RULE, { scope_type: 'uri', scope_value: '/api/b' })).status()).toBe(201);

    const rule = await readRule(request, RULE);
    expect(rule.scopes.sort()).toEqual(['uri:/api/a', 'uri:/api/b']);

    // The stored rows are only half the feature — assert the artifact they exist
    // to produce, so a merge that de-duplicates by rule id cannot pass this.
    const conf = execSync(
      `docker compose -f ../../docker-compose.e2e-test.yml exec -T nginx cat /etc/nginx/modsec/host_${hostId}.conf`,
      { encoding: 'utf8' }
    );
    expect(conf).toContain('@beginsWith /api/a');
    expect(conf).toContain('@beginsWith /api/b');
    // Each scoped exclusion is its own SecRule and needs its own id.
    const ids = [...conf.matchAll(/id:(\d{7})/g)].map((m) => m[1]);
    expect(new Set(ids).size, 'generated rule ids must be unique').toBe(ids.length);
  });

  test('a narrow exclusion leaves the rule enabled', async ({ request }) => {
    // The rule still protects every path other than /api/a and /api/b, so
    // reporting it as disabled overstated the exemption.
    const rule = await readRule(request, RULE);
    expect(rule.enabled).toBe(true);
  });

  test('rejects only an identical scope as a duplicate', async ({ request }) => {
    const res = await disable(request, RULE, { scope_type: 'uri', scope_value: '/api/a' });
    expect(res.status()).toBe(409);
  });

  test('a host scope disables the whole rule', async ({ request }) => {
    expect((await disable(request, RULE, { scope_type: 'host' })).status()).toBe(201);
    const rule = await readRule(request, RULE);
    expect(rule.enabled).toBe(false);
    expect(rule.scopes.sort()).toEqual(['host:', 'uri:/api/a', 'uri:/api/b']);
  });

  test('removing one scope keeps the others', async ({ request }) => {
    const res = await request.delete(
      `${API}/api/v1/waf/hosts/${hostId}/rules/${RULE}/disable?scope_type=uri&scope_value=${encodeURIComponent('/api/a')}`,
      { headers: auth() }
    );
    expect(res.status()).toBe(204);

    const rule = await readRule(request, RULE);
    // The delete used to key on the rule alone, taking /api/b and the host
    // exclusion with it.
    expect(rule.scopes.sort()).toEqual(['host:', 'uri:/api/b']);
  });

  test('removing an absent scope is a 404, not a silent success', async ({ request }) => {
    const res = await request.delete(
      `${API}/api/v1/waf/hosts/${hostId}/rules/${RULE}/disable?scope_type=uri&scope_value=${encodeURIComponent('/nope')}`,
      { headers: auth() }
    );
    expect(res.status()).toBe(404);
  });

  test('omitting the scope re-enables the rule outright', async ({ request }) => {
    const res = await request.delete(`${API}/api/v1/waf/hosts/${hostId}/rules/${RULE}/disable`, {
      headers: auth(),
    });
    expect(res.status()).toBe(204);

    const rule = await readRule(request, RULE);
    expect(rule.enabled).toBe(true);
    expect(rule.scopes).toEqual([]);
  });

  test('rejects a scope value that could break out of the directive', async ({ request }) => {
    // scope_value is rendered into a ModSecurity rule, so it is validated before
    // it can reach a config file.
    for (const bad of ['no-leading-slash', '/has space', '/quote"break']) {
      const res = await disable(request, OTHER_RULE, { scope_type: 'uri', scope_value: bad });
      expect(res.status(), `expected 400 for ${bad}`).toBe(400);
    }
  });
});

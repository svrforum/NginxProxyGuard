import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import * as net from 'net';
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

  /** Send a plain GET through the proxy and return the status (0 = no reply). */
  function rawGet(host: string, path: string): Promise<number> {
    return new Promise((resolve) => {
      const socket = net.createConnection({ host: '127.0.0.1', port: Number(process.env.E2E_PROXY_HTTP_PORT || 18080) });
      socket.setTimeout(8000);
      let buf = '';
      const done = (v: number) => { socket.destroy(); resolve(v); };
      socket.on('connect', () => {
        socket.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      });
      socket.on('data', (c) => {
        buf += c.toString('utf8');
        const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
        if (m) done(Number(m[1]));
      });
      socket.on('close', () => done(0));
      socket.on('error', () => done(0));
      socket.on('timeout', () => done(0));
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
    // Anchored and terminated at a path boundary. A raw prefix test also
    // exempted /api/a-admin and /api/apikeys — paths nobody named. (#286)
    // Matched on the normalized path, not REQUEST_URI, which also covered
    // /api/a/../admin; a chained rule keeps the rule for ..;, \ and %2e.
    expect(conf).toContain('SecRule REQUEST_FILENAME "@rx \\A/api/a(?:/|\\z)"');
    expect(conf).toContain('SecRule REQUEST_FILENAME "@rx \\A/api/b(?:/|\\z)"');
    expect(conf).not.toContain('REQUEST_URI');
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

  test('a path scope stops at a path boundary, so prefix siblings keep the rule', async ({ request }) => {
    // A string assertion on the directive cannot tell a correct boundary class
    // from a wrong one. This sends real requests: with the rule exempted under
    // /api/a, a sibling that merely shares those bytes must still be blocked.
    // Before #286 the directive was a raw prefix test and /api/a-x was exempt.
    const host = TestDataFactory.generateDomain('waf-boundary');
    const created = await request.post(`${API}/api/v1/proxy-hosts`, {
      headers: auth(),
      data: {
        domain_names: [host],
        forward_host: '127.0.0.1',
        forward_port: 19080,
        forward_scheme: 'http',
        waf_enabled: true,
        waf_mode: 'blocking',
        waf_paranoia_level: 1,
        waf_anomaly_threshold: 5,
        enabled: true,
      },
    });
    expect(created.ok(), `host creation failed: ${created.status()}`).toBeTruthy();
    const boundaryHostId = (await created.json()).id;

    try {
      // The scopes exempt the anomaly-blocking rule itself, so a probe passes
      // inside a scope whichever detection rules it trips, and is blocked
      // outside. Exempting one detection rule (942100) made the result depend
      // on that rule alone catching the probe, which this CRS build no longer
      // does for a tautology at PL1 — with or without any exclusion.
      const res = await request.post(
        `${API}/api/v1/waf/hosts/${boundaryHostId}/rules/949110/disable`,
        { headers: auth(), data: { scope_type: 'uri', scope_value: '/api/a' } }
      );
      expect(res.status()).toBe(201);
      // A second scope shows whether a path that only looks like /api/b is let
      // through too. On REQUEST_URI, /api/b/../../x was.
      const blocking = await request.post(
        `${API}/api/v1/waf/hosts/${boundaryHostId}/rules/949110/disable`,
        { headers: auth(), data: { scope_type: 'uri', scope_value: '/api/b' } }
      );
      expect(blocking.status()).toBe(201);

      // ModSecurity does not re-parse its rules on `nginx -s reload`, so the
      // exclusion only goes live after the proxy restarts.
      execSync('docker restart npg-test-proxy', { stdio: 'ignore' });
      await new Promise((r) => setTimeout(r, 8000));

      // Blocked at PL1 (942190 and others) on every path no scope covers.
      const payload = "?id=1%27%20UNION%20SELECT%20a,b%20FROM%20users--";
      const probe = (path: string) => rawGet(host, `${path}${payload}`);

      expect(await probe('/api/a/x'), '/api/a/x is inside the scope').not.toBe(403);
      expect(await probe('/api/a'), 'the scope root itself').not.toBe(403);
      expect(await probe('/api/a-x'), '/api/a-x only shares the prefix').toBe(403);
      expect(await probe('/api/abc'), '/api/abc only shares the prefix').toBe(403);
      expect(await probe('/other'), 'unrelated path').toBe(403);

      // nginx and the backend serve each of these as /x (or, for ..; and the
      // backslash, a Tomcat or Windows backend does), so the scope is decided
      // on the normalized path and the rule keeps blocking.
      expect(await probe('/api/b/x'), '/api/b/x is inside the 949110 scope').not.toBe(403);
      for (const path of ['/api/b/../../x', '/api/b/%2e%2e/%2e%2e/x', '/api/b/..;/x', '/api/b/..%5cx']) {
        expect(await probe(path), `${path} only looks like it is under /api/b`).toBe(403);
      }
    } finally {
      await request.delete(`${API}/api/v1/proxy-hosts/${boundaryHostId}`, { headers: auth() });
    }
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

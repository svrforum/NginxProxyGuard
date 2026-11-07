import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';
import { NGINX_HTTP_PORT } from '../../fixtures/test-data';

/**
 * Priority allow and URI block exception entries are geo blocks since v2.62.0:
 * each entry matches the range it names. Before, a range was a regex on its
 * leading octets (a /32 let its whole /24 through) and an IPv6 range never
 * matched. A URI block exception also keeps the host's ForwardAuth login,
 * except under one of the host's auth bypass paths.
 *
 * Each host proxies to the API itself (127.0.0.1:19080, which nginx reaches
 * from the host network), so a request NPG lets through gets the API's 404
 * and one it blocks gets NPG's 403. Requests carry X-Forwarded-For from
 * loopback, which nginx always trusts as the client address.
 */
const API = 'http://127.0.0.1:19080';
// What the API answers for the paths below, none of which it serves.
const PASSED = 404;
// A client in no list of these tests.
const OUTSIDER = '192.0.2.1';
// Hosts and auth providers this file creates. The sweep in afterAll deletes
// only these: the other spec file using the r1- prefix may be running in
// parallel.
const OWN_HOST_PREFIXES = ['r1-uri-', 'r1-prio-', 'r1-fa-'];
const OWN_PROVIDER_PREFIX = 'r1-fa-';

test.describe.configure({ mode: 'serial' });

interface Head {
  status: number;
  headers: string;
}

/** Send a GET with an explicit Host and client address; resolve with the response head. */
function probeHead(host: string, path: string, forwardedFor: string, extra = ''): Promise<Head> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: NGINX_HTTP_PORT });
    socket.setTimeout(6000);
    let buf = '';
    const done = (head: Head) => {
      socket.destroy();
      resolve(head);
    };
    socket.on('connect', () => {
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nX-Forwarded-For: ${forwardedFor}\r\n${extra}Connection: close\r\n\r\n`
      );
    });
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const end = buf.indexOf('\r\n\r\n');
      if (end < 0) return;
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      done({ status: m ? Number(m[1]) : 0, headers: buf.slice(0, end) });
    });
    // 0 stands for no response (closed, refused or timed out).
    socket.on('close', () => done({ status: 0, headers: '' }));
    socket.on('error', () => done({ status: 0, headers: '' }));
    socket.on('timeout', () => done({ status: 0, headers: '' }));
  });
}

async function probe(host: string, path: string, forwardedFor: string, extra = ''): Promise<number> {
  return (await probeHead(host, path, forwardedFor, extra)).status;
}

async function eventually(fn: () => Promise<boolean>, what: string, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`never: ${what}`);
}

test.describe('IP list matching (v2.62.0)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  const createdHosts: string[] = [];
  const createdProviders: string[] = [];

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(async ({ request }) => {
    // Hosts first: a provider a host still uses cannot go.
    for (const id of createdHosts.splice(0)) {
      await api.deleteProxyHost(id).catch(() => undefined);
    }
    for (const id of createdProviders.splice(0)) {
      await request.delete(`${API}/api/v1/auth-providers/${id}`, { headers }).catch(() => undefined);
    }
  });

  test.afterAll(async ({ playwright }) => {
    // Rows a failed or refused save kept, such as a host whose create threw
    // before the test could note its id. Hosts first, as above.
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      const helper = new APIHelper(ctx);
      await helper.login();
      for (const h of await helper.getProxyHosts()) {
        if (OWN_HOST_PREFIXES.some((p) => h.domain_names?.[0]?.startsWith(p))) {
          await helper.deleteProxyHost(h.id).catch(() => undefined);
        }
      }
      const auth = { Authorization: `Bearer ${await helper.getToken()}` };
      const res = await ctx.get('/api/v1/auth-providers?per_page=100', { headers: auth });
      const providers: Array<{ id: string; name: string }> = res.ok() ? ((await res.json()).data ?? []) : [];
      for (const p of providers.filter((p) => p.name.startsWith(OWN_PROVIDER_PREFIX))) {
        await ctx.delete(`/api/v1/auth-providers/${p.id}`, { headers: auth }).catch(() => undefined);
      }
    } finally {
      await ctx.dispose();
    }
  });

  async function createHost(prefix: string, extra: Record<string, unknown> = {}) {
    const domain = `${prefix}-${Date.now()}.example.com`;
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 19080,
      enabled: true,
      ...extra,
    });
    createdHosts.push(host.id);
    return { id: host.id, domain };
  }

  test('a /32 URI block exception lets only that address through', async ({ request }) => {
    const { id, domain } = await createHost('r1-uri');
    const res = await request.put(`${API}/api/v1/proxy-hosts/${id}/uri-block`, {
      headers,
      data: {
        enabled: true,
        exception_ips: ['203.0.113.5/32', '2001:db8:1::/48'],
        rules: [{ pattern: '/admin', match_type: 'prefix', description: 'e2e', enabled: true }],
      },
    });
    expect(res.ok()).toBeTruthy();
    // A URI block save reloads nginx after a short debounce.
    await eventually(async () => (await probe(domain, '/admin', OUTSIDER)) === 403, 'the URI block is live');

    expect(await probe(domain, '/admin', '203.0.113.5')).toBe(PASSED);
    expect(await probe(domain, '/admin', '203.0.113.6'), 'same /24, outside the /32').toBe(403);
    expect(await probe(domain, '/admin', '2001:db8:1::7'), 'inside the IPv6 range').toBe(PASSED);
    expect(await probe(domain, '/admin', '2001:db8:2::7'), 'outside the IPv6 range').toBe(403);
  });

  test("a rule's own exception IPs let it through for that rule only (#343)", async ({ request }) => {
    const { id, domain } = await createHost('r1-uri');
    const url = `${API}/api/v1/proxy-hosts/${id}/uri-block`;
    const res = await request.put(url, {
      headers,
      data: {
        enabled: true,
        exception_ips: [],
        rules: [
          { pattern: '/user/login', match_type: 'prefix', description: 'e2e login', enabled: true,
            exception_ips: [' 203.0.113.5 ', '2001:DB8:1::/48', '203.0.113.5'] },
          { pattern: '/admin', match_type: 'prefix', description: 'e2e admin', enabled: true },
        ],
      },
    });
    expect(res.ok()).toBeTruthy();
    const saved = await res.json();
    expect(saved.rules[0].exception_ips, 'saved normalized, each once').toEqual(['203.0.113.5', '2001:db8:1::/48']);
    expect(saved.rules[1].exception_ips ?? []).toEqual([]);
    await eventually(async () => (await probe(domain, '/admin', OUTSIDER)) === 403, 'the URI block is live');

    expect(await probe(domain, '/user/login', '203.0.113.5')).toBe(PASSED);
    expect(await probe(domain, '/user/login', '2001:db8:1::7'), 'inside the IPv6 range').toBe(PASSED);
    expect(await probe(domain, '/user/login', OUTSIDER)).toBe(403);
    expect(await probe(domain, '/admin', '203.0.113.5'), 'the other rule keeps blocking it').toBe(403);

    const refused = await request.put(url, {
      headers,
      data: {
        enabled: true,
        rules: [{ pattern: '/user/login', match_type: 'prefix', enabled: true, exception_ips: ['office.example.com'] }],
      },
    });
    expect(refused.status(), 'an entry that is no address').toBe(400);
    expect(await probe(domain, '/user/login', '203.0.113.5'), 'the refused save changed nothing').toBe(PASSED);
  });

  test('a priority allow /32 bypasses the bot filter for that address only', async ({ request }) => {
    const { id, domain } = await createHost('r1-prio');
    const ua = 'User-Agent: R1BadBot/1.0\r\n';
    await api.setBotFilter(id, { customBlockedAgents: 'R1BadBot' });
    await eventually(async () => (await probe(domain, '/', '198.51.100.7', ua)) === 403, 'the bot filter is live');

    // Priority allow rides on the geo row, which keeps it with geo itself off;
    // set it through the endpoint the UI uses.
    const res = await request.post(`${API}/api/v1/proxy-hosts/${id}/geo`, {
      headers,
      data: { mode: 'blacklist', countries: ['AQ'], enabled: false, allowed_ips: ['198.51.100.7/32', '2001:db8:1::/48'] },
    });
    expect(res.ok()).toBeTruthy();
    await eventually(
      async () => (await probe(domain, '/', '198.51.100.7', ua)) === PASSED,
      'the priority address passes the bot filter'
    );

    expect(await probe(domain, '/', '198.51.100.8', ua), 'same /24, outside the /32').toBe(403);
    expect(await probe(domain, '/', '2001:db8:1::7', ua), 'inside the IPv6 range').toBe(PASSED);
    expect(await probe(domain, '/', '2001:db8:2::7', ua), 'outside the IPv6 range').toBe(403);
  });

  test('a URI block exception still goes through the host login', async ({ request }) => {
    // The verifier is the API's own /api/v1/auth/me: 200 with a session token, 401 without.
    const providerRes = await request.post(`${API}/api/v1/auth-providers`, {
      headers,
      data: {
        name: `r1-fa-${Date.now()}`,
        type: 'custom',
        provider_url: API,
        timeout_ms: 3000,
        enabled: true,
        config: {
          verify_path: '/api/v1/auth/me',
          signin_mode: 'redirect_template',
          signin_redirect: 'https://login.example.com/',
        },
      },
    });
    expect(providerRes.status()).toBe(201);
    const provider = await providerRes.json();
    createdProviders.push(provider.id);

    const { id, domain } = await createHost('r1-fa', {
      auth_provider_id: provider.id,
      auth_bypass_paths: ['/api'],
    });
    const res = await request.put(`${API}/api/v1/proxy-hosts/${id}/uri-block`, {
      headers,
      data: {
        enabled: true,
        exception_ips: ['203.0.113.5'],
        rules: [
          { pattern: '/admin', match_type: 'prefix', description: 'e2e', enabled: true },
          { pattern: '/api/config', match_type: 'prefix', description: 'e2e under the auth bypass', enabled: true },
        ],
      },
    });
    expect(res.ok()).toBeTruthy();
    await eventually(async () => (await probe(domain, '/admin', OUTSIDER)) === 403, 'the URI block is live');

    // An exception lifts the URI block, not the login.
    const signIn = await probeHead(domain, '/admin', '203.0.113.5');
    expect(signIn.status, 'an exception without a login is sent to sign in').toBe(302);
    expect(signIn.headers).toMatch(/^location: https:\/\/login\.example\.com\/\r?$/im);
    const token = await api.getToken();
    expect(await probe(domain, '/admin', '203.0.113.5', `Authorization: Bearer ${token}\r\n`), 'logged in').toBe(PASSED);
    expect(await probe(domain, '/admin', '203.0.113.6'), 'not an exception: NPG 403').toBe(403);
    expect(await probe(domain, '/admin', '203.0.113.50'), 'an address that only begins like the exception: NPG 403').toBe(403);

    // Under one of the host's auth bypass paths the host asks for no login,
    // so an exception there reaches the upstream without one.
    expect(await probe(domain, '/api/config', '203.0.113.5'), 'exception under the bypass path').toBe(PASSED);
    expect(await probe(domain, '/api/config', '203.0.113.6'), 'not an exception: NPG 403').toBe(403);
  });
});

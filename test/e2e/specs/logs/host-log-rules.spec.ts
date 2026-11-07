import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';
import { NGINX_HTTP_PORT } from '../../fixtures/test-data';

/**
 * The hosts' log rules (#347): the access log lines a host's rules name are
 * not stored, and a line NPG blocked always is.
 *
 * Each host proxies to the API itself (127.0.0.1:19080), so a request NPG
 * lets through gets the API's answer and one a URI block refuses gets NPG's
 * 403. That 403 is also how a test knows the host's server block is live:
 * before it, the catch-all answers, whose lines belong to no host and so to
 * no host's rules. The collector reads lines in order, so once a request
 * sent last is stored, every earlier one has been decided, and a skipped one
 * is known to be absent.
 */
const API = 'http://127.0.0.1:19080';
// A client address of our own (loopback is a trusted proxy), so no ban or
// jail the other specs keep counts these requests.
const CLIENT = '203.0.113.47';
const OWN_HOST_PREFIX = 'logrules-';

test.describe.configure({ mode: 'serial' });

/** Send a request with an explicit method, Host and raw path; resolve with the status (0: no response). */
function send(host: string, method: string, path: string): Promise<number> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: NGINX_HTTP_PORT });
    socket.setTimeout(6000);
    let buf = '';
    const done = (status: number) => {
      socket.destroy();
      resolve(status);
    };
    socket.on('connect', () => {
      socket.write(`${method} ${path} HTTP/1.1\r\nHost: ${host}\r\nX-Forwarded-For: ${CLIENT}\r\nConnection: close\r\n\r\n`);
    });
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      if (m) done(Number(m[1]));
    });
    socket.on('close', () => done(0));
    socket.on('error', () => done(0));
    socket.on('timeout', () => done(0));
  });
}

async function eventually(fn: () => Promise<boolean>, what: string, ms = 25000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`never: ${what}`);
}

test.describe('Host log rules (#347)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  const createdHosts: string[] = [];

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(async () => {
    for (const id of createdHosts.splice(0)) {
      await api.deleteProxyHost(id).catch(() => undefined);
    }
  });

  test.afterAll(async ({ playwright }) => {
    // Hosts a failed test could not note.
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      const helper = new APIHelper(ctx);
      await helper.login();
      for (const h of await helper.getProxyHosts()) {
        if (h.domain_names?.[0]?.startsWith(OWN_HOST_PREFIX)) {
          await helper.deleteProxyHost(h.id).catch(() => undefined);
        }
      }
    } finally {
      await ctx.dispose();
    }
  });

  /** A host with a URI block on /dav/blocked, once its server block answers. */
  async function liveHost(request: import('@playwright/test').APIRequestContext) {
    const domain = `${OWN_HOST_PREFIX}${Date.now()}.example.com`;
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 19080,
      waf_enabled: false,
      block_exploits: false,
      enabled: true,
    });
    createdHosts.push(host.id);
    const res = await request.put(`${API}/api/v1/proxy-hosts/${host.id}/uri-block`, {
      headers,
      data: { enabled: true, rules: [{ pattern: '/dav/blocked', match_type: 'prefix', description: 'e2e', enabled: true }] },
    });
    expect(res.ok()).toBeTruthy();
    await eventually(async () => (await send(domain, 'GET', '/dav/blocked/ready')) === 403, 'the host is live');
    return { id: host.id as string, domain };
  }

  async function storedURIs(domain: string): Promise<string[]> {
    return (await api.getLogs({ host: domain, limit: 100 })).map((r) => r.request_uri ?? '');
  }

  /** Wait until the request sent last is stored; then return what is. */
  async function storedAfter(domain: string, sentinel: string): Promise<string[]> {
    let uris: string[] = [];
    await eventually(async () => {
      uris = await storedURIs(domain);
      return uris.includes(sentinel);
    }, `${sentinel} is stored`);
    return uris;
  }

  test("the rules leave out the lines they name, but not a blocked line or a path spelled around them", async ({ request }) => {
    const { id, domain } = await liveHost(request);
    const res = await request.put(`${API}/api/v1/log-rules/${id}`, {
      headers,
      data: { skip_statuses: [' 207 '], skip_methods: ['options'], skip_paths: ['/dav/', '/dav/'] },
    });
    expect(res.status()).toBe(200);
    const saved = await res.json();
    expect(saved.skip_statuses).toEqual(['207']);
    expect(saved.skip_methods).toEqual(['OPTIONS']);
    expect(saved.skip_paths).toEqual(['/dav/']);

    const tag = Date.now();
    expect(await send(domain, 'GET', `/dav/skipped-${tag}`)).not.toBe(0);
    expect(await send(domain, 'OPTIONS', `/skipped-method-${tag}`)).not.toBe(0);
    expect(await send(domain, 'GET', `/dav/../kept-dotted-${tag}`)).not.toBe(0);
    expect(await send(domain, 'GET', `/dav/blocked/kept-${tag}`)).toBe(403);
    expect(await send(domain, 'GET', `/kept-last-${tag}`)).not.toBe(0);
    const uris = await storedAfter(domain, `/kept-last-${tag}`);

    expect(uris, 'a dot segment out of the skipped path').toContain(`/dav/../kept-dotted-${tag}`);
    expect(uris, 'a line NPG blocked').toContain(`/dav/blocked/kept-${tag}`);
    expect(uris, 'under a skipped path').not.toContain(`/dav/skipped-${tag}`);
    expect(uris, 'a skipped method').not.toContain(`/skipped-method-${tag}`);

    const list = await request.get(`${API}/api/v1/log-rules`, { headers });
    expect(list.ok()).toBeTruthy();
    const entry = (await list.json()).find((e: { proxy_host_id: string }) => e.proxy_host_id === id);
    expect(entry?.domain_names).toEqual([domain]);
    expect(entry?.skip_paths).toEqual(['/dav/']);
  });

  test('skip_all stores only what NPG blocked, and rules that skip nothing store every line again', async ({ request }) => {
    const { id, domain } = await liveHost(request);
    const url = `${API}/api/v1/log-rules/${id}`;
    expect((await request.put(url, { headers, data: { skip_all: true } })).status()).toBe(200);

    const tag = Date.now();
    expect(await send(domain, 'GET', `/plain-${tag}`)).not.toBe(0);
    expect(await send(domain, 'GET', `/dav/blocked/last-${tag}`)).toBe(403);
    const uris = await storedAfter(domain, `/dav/blocked/last-${tag}`);
    expect(uris, 'skip_all').not.toContain(`/plain-${tag}`);

    const cleared = await request.put(url, { headers, data: { skip_all: false } });
    expect(cleared.status()).toBe(200);
    expect((await cleared.json()).skip_all).toBe(false);
    expect(await send(domain, 'GET', `/plain-again-${tag}`)).not.toBe(0);
    await storedAfter(domain, `/plain-again-${tag}`);
  });

  test("a ForwardAuth host's sign-in redirect is kept under a 3xx rule", async ({ request }) => {
    // The verifier is the API's own /api/v1/auth/me: 401 without a session.
    const providerRes = await request.post(`${API}/api/v1/auth-providers`, {
      headers,
      data: {
        name: `${OWN_HOST_PREFIX}fa-${Date.now()}`,
        type: 'custom',
        provider_url: API,
        timeout_ms: 3000,
        enabled: true,
        config: { verify_path: '/api/v1/auth/me', signin_mode: 'redirect_template', signin_redirect: 'https://login.example.com/' },
      },
    });
    expect(providerRes.status()).toBe(201);
    const provider = await providerRes.json();
    const domain = `${OWN_HOST_PREFIX}fa-${Date.now()}.example.com`;
    try {
      const host = await api.createProxyHost({
        domain_names: [domain],
        forward_scheme: 'http',
        forward_host: '127.0.0.1',
        forward_port: 19080,
        waf_enabled: false,
        block_exploits: false,
        enabled: true,
        auth_provider_id: provider.id,
      });
      createdHosts.push(host.id);
      await eventually(async () => (await send(domain, 'GET', '/signin-ready')) === 302, 'the host asks for a login');
      expect((await request.put(`${API}/api/v1/log-rules/${host.id}`, { headers, data: { skip_statuses: ['3xx'] } })).status()).toBe(200);

      // NPG's 302 to the sign-in page has no block reason and no upstream.
      const tag = Date.now();
      expect(await send(domain, 'GET', `/signin-${tag}`)).toBe(302);
      const uris = await storedAfter(domain, `/signin-${tag}`);
      expect(uris).toContain(`/signin-${tag}`);
    } finally {
      for (const id of createdHosts.splice(0)) await api.deleteProxyHost(id).catch(() => undefined);
      await request.delete(`${API}/api/v1/auth-providers/${provider.id}`, { headers }).catch(() => undefined);
    }
  });

  test('entries that are not valid are refused, and so is a host that does not exist', async ({ request }) => {
    const { id } = await liveHost(request);
    const url = `${API}/api/v1/log-rules/${id}`;
    for (const data of [{ skip_statuses: ['abc'] }, { skip_methods: ['GET POST'] }, { skip_paths: ['/dav/../admin'] }, { skip_paths: ['dav'] }]) {
      expect((await request.put(url, { headers, data })).status(), JSON.stringify(data)).toBe(400);
    }
    const unknown = await request.put(`${API}/api/v1/log-rules/00000000-0000-4000-8000-00000000ffff`, { headers, data: { skip_all: true } });
    expect(unknown.status()).toBe(404);
    const rules = await (await request.get(url, { headers })).json();
    expect(rules.skip_all).toBe(false);
    expect(rules.skip_statuses).toEqual([]);
  });
});

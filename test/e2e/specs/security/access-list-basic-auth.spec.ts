import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';
import { NGINX_HTTP_PORT } from '../../fixtures/test-data';

/**
 * Basic auth accounts in access lists (#387). A host using a list with
 * accounts answers 401 with a Basic challenge until one of them is sent,
 * leaves the ACME path open, and cannot be given ForwardAuth (both answer a
 * missing login with 401). Each host proxies to the API itself
 * (127.0.0.1:19080), so a request NPG lets through gets the API's 404.
 */
const API = 'http://127.0.0.1:19080';
const PASSED = 404;
const PREFIX = 'ba387-';

test.describe.configure({ mode: 'serial' });

function probe(host: string, path: string, extra = ''): Promise<{ status: number; headers: string }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: NGINX_HTTP_PORT });
    socket.setTimeout(6000);
    let buf = '';
    const done = (r: { status: number; headers: string }) => {
      socket.destroy();
      resolve(r);
    };
    socket.on('connect', () => {
      socket.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\n${extra}Connection: close\r\n\r\n`);
    });
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const end = buf.indexOf('\r\n\r\n');
      if (end < 0) return;
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      done({ status: m ? Number(m[1]) : 0, headers: buf.slice(0, end) });
    });
    socket.on('close', () => done({ status: 0, headers: '' }));
    socket.on('error', () => done({ status: 0, headers: '' }));
    socket.on('timeout', () => done({ status: 0, headers: '' }));
  });
}

const basic = (user: string, password: string) =>
  `Authorization: Basic ${Buffer.from(`${user}:${password}`).toString('base64')}\r\n`;

async function eventually(fn: () => Promise<boolean>, what: string, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`never: ${what}`);
}

test.describe('Access list basic auth (#387)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  const hosts: string[] = [];
  const lists: string[] = [];
  const providers: string[] = [];

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(async ({ request }) => {
    for (const id of hosts.splice(0)) await api.deleteProxyHost(id).catch(() => undefined);
    for (const id of providers.splice(0)) {
      await request.delete(`${API}/api/v1/auth-providers/${id}`, { headers }).catch(() => undefined);
    }
    for (const id of lists.splice(0)) await api.deleteAccessList(id).catch(() => undefined);
  });

  async function createList(request: import('@playwright/test').APIRequestContext, body: Record<string, unknown>) {
    const res = await request.post(`${API}/api/v1/access-lists`, { headers, data: { name: `${PREFIX}${Date.now()}`, ...body } });
    expect(res.status(), await res.text()).toBe(201);
    const list = await res.json();
    lists.push(list.id);
    return list as { id: string; auth_users?: { username: string }[] };
  }

  async function createHost(accessListId: string) {
    const domain = `${PREFIX}${Date.now()}.example.com`;
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 19080,
      enabled: true,
      access_list_id: accessListId,
    });
    hosts.push(host.id);
    return { id: host.id, domain };
  }

  test('asks for an account, keeps ACME open, and keeps a password left empty', async ({ request }) => {
    const list = await createList(request, { auth_users: [{ username: 'alice', password: 'alice-pass-1' }] });
    expect(list.auth_users?.map((u) => u.username)).toEqual(['alice']);
    expect(JSON.stringify(list)).not.toContain('$6$');
    const { domain } = await createHost(list.id);

    await eventually(async () => (await probe(domain, '/x')).status === 401, 'host asks for the password');
    expect((await probe(domain, '/x')).headers).toMatch(/WWW-Authenticate: Basic/i);
    expect((await probe(domain, '/x', basic('alice', 'wrong-pass'))).status).toBe(401);
    expect((await probe(domain, '/x', basic('alice', 'alice-pass-1'))).status).toBe(PASSED);
    expect((await probe(domain, '/.well-known/acme-challenge/none')).status).not.toBe(401);

    // An update that sends alice without a password keeps hers.
    const res = await request.put(`${API}/api/v1/access-lists/${list.id}`, {
      headers,
      data: { auth_users: [{ username: 'alice' }, { username: 'bob', password: 'bob-pass-22' }] },
    });
    expect(res.status(), await res.text()).toBe(200);
    await eventually(async () => (await probe(domain, '/x', basic('bob', 'bob-pass-22'))).status === PASSED, 'bob gets in');
    expect((await probe(domain, '/x', basic('alice', 'alice-pass-1'))).status).toBe(PASSED);

    // A new account needs a password.
    const bad = await request.put(`${API}/api/v1/access-lists/${list.id}`, { headers, data: { auth_users: [{ username: 'carol' }] } });
    expect(bad.status()).toBe(400);
  });

  test('cannot share a host with ForwardAuth', async ({ request }) => {
    const list = await createList(request, { auth_users: [{ username: 'alice', password: 'alice-pass-1' }] });
    const { id } = await createHost(list.id);
    const pr = await request.post(`${API}/api/v1/auth-providers`, {
      headers,
      data: { name: `${PREFIX}fa-${Date.now()}`, type: 'custom', provider_url: 'http://127.0.0.1:19080/verify', enabled: true },
    });
    expect(pr.status(), await pr.text()).toBe(201);
    const provider = await pr.json();
    providers.push(provider.id);

    const res = await request.put(`${API}/api/v1/proxy-hosts/${id}`, { headers, data: { auth_provider_id: provider.id } });
    expect(res.status()).toBe(409);
  });
});

import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';
import { NGINX_HTTP_PORT } from '../../fixtures/test-data';

/**
 * Custom error pages (#335). A custom page replaces NPG's built-in one on the
 * proxy hosts, with a CSP that keeps scripts from running on the site's
 * origin; a reset brings the built-in page back. A client an access list
 * refuses sees the block page too: it used to get nginx's bare 403, because
 * the list's rules were inherited by the block page's own location.
 */
const API = 'http://127.0.0.1:19080';
const PREFIX = 'ep335-';

test.describe.configure({ mode: 'serial' });

/** GET through the proxy with an explicit Host; resolve with the whole response. */
function fetchRaw(host: string, path = '/'): Promise<{ status: number; head: string; body: string }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: NGINX_HTTP_PORT });
    socket.setTimeout(6000);
    let buf = '';
    const finish = () => {
      socket.destroy();
      const end = buf.indexOf('\r\n\r\n');
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      resolve({ status: m ? Number(m[1]) : 0, head: end < 0 ? buf : buf.slice(0, end), body: end < 0 ? '' : buf.slice(end + 4) });
    };
    socket.on('connect', () => socket.write(`GET ${path} HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`));
    socket.on('data', (chunk) => (buf += chunk.toString('utf8')));
    socket.on('close', finish);
    socket.on('error', finish);
    socket.on('timeout', finish);
  });
}

async function eventually(fn: () => Promise<boolean>, what: string, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`never: ${what}`);
}

test.describe('Custom error pages (#335)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  const hosts: string[] = [];
  const lists: string[] = [];

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(async ({ request }) => {
    for (const s of [403, 502]) await request.delete(`${API}/api/v1/settings/error-pages/${s}`, { headers }).catch(() => undefined);
    for (const id of hosts.splice(0)) await api.deleteProxyHost(id).catch(() => undefined);
    for (const id of lists.splice(0)) await api.deleteAccessList(id).catch(() => undefined);
  });

  test('a custom page replaces the built-in one, scripts blocked, and resets', async ({ request }) => {
    const lr = await request.post(`${API}/api/v1/access-lists`, {
      headers,
      data: { name: `${PREFIX}${Date.now()}`, items: [{ directive: 'deny', address: 'all' }] },
    });
    expect(lr.status(), await lr.text()).toBe(201);
    const list = await lr.json();
    lists.push(list.id);
    const denied = `${PREFIX}403-${Date.now()}.example.com`;
    const down = `${PREFIX}502-${Date.now()}.example.com`;
    for (const [domain, port, extra] of [
      [denied, 19080, { access_list_id: list.id }],
      [down, 18998, {}],
    ] as const) {
      const h = await api.createProxyHost({ domain_names: [domain], forward_scheme: 'http', forward_host: '127.0.0.1', forward_port: port, enabled: true, ...extra });
      hosts.push(h.id);
    }

    // The access list's refusal gets NPG's block page, not nginx's bare one.
    await eventually(async () => {
      const r = await fetchRaw(denied);
      return r.status === 403 && !/Content-Security-Policy/i.test(r.head);
    }, 'access list refuses with the built-in page');
    const builtIn = await fetchRaw(denied);
    expect(builtIn.body).not.toContain('<center>nginx</center>');
    expect(builtIn.head).not.toMatch(/Content-Security-Policy/i);

    for (const [status, marker] of [[403, 'CUSTOM-403'], [502, 'CUSTOM-502']] as const) {
      const res = await request.put(`${API}/api/v1/settings/error-pages/${status}`, {
        headers,
        data: { html: `<html><body><h1>${marker}</h1><script>alert(1)</script></body></html>` },
      });
      expect(res.status(), await res.text()).toBe(200);
    }
    // Each save reloads nginx; under a full parallel run the reload can land a
    // moment after the API answers.
    await eventually(async () => (await fetchRaw(denied)).body.includes('CUSTOM-403'), 'custom 403 is live');
    await eventually(async () => (await fetchRaw(down)).body.includes('CUSTOM-502'), 'custom 502 is live');
    const custom403 = await fetchRaw(denied);
    expect(custom403.status).toBe(403);
    expect(custom403.body).toContain('CUSTOM-403');
    expect(custom403.head).toMatch(/Content-Security-Policy: default-src 'none';.*sandbox/i);
    const custom502 = await fetchRaw(down);
    expect(custom502.status).toBe(502);
    expect(custom502.body).toContain('CUSTOM-502');

    expect((await request.put(`${API}/api/v1/settings/error-pages/500`, { headers, data: { html: '<p>x</p>' } })).status()).toBe(400);
    expect((await request.put(`${API}/api/v1/settings/error-pages/503`, { headers, data: { html: '  ' } })).status()).toBe(400);

    const reset = await request.delete(`${API}/api/v1/settings/error-pages/403`, { headers });
    expect(reset.status()).toBe(200);
    await eventually(async () => !(await fetchRaw(denied)).body.includes('CUSTOM-403'), 'built-in 403 is back');
    const after = await fetchRaw(denied);
    expect(after.body).not.toContain('CUSTOM-403');
    expect(after.head).not.toMatch(/Content-Security-Policy/i);
  });
});

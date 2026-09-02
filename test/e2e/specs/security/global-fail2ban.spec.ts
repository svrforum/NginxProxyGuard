import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';

/**
 * The global jail (#275) acts on requests that matched no configured host —
 * the catch-all traffic a per-host jail structurally cannot see, which is why
 * putting 444 in a host's fail codes never fired.
 *
 * Its bans carry no proxy host and therefore apply to EVERY host, so most of
 * what is tested here is what it must NOT do. A false positive is an
 * instance-wide outage.
 */
const NGINX_HOST = '127.0.0.1';
const NGINX_PORT = Number(process.env.E2E_PROXY_HTTP_PORT || 18080);
const API = 'http://127.0.0.1:19080';
const GLOBAL = '/api/v1/settings/global-fail2ban';

// One shared singleton and a shared ban table — parallel runs would read each
// other's writes.
test.describe.configure({ mode: 'serial' });

/** Send a request with an explicit Host and forwarded client address. */
function probe(host: string, path: string, forwardedFor: string): Promise<number> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: NGINX_HOST, port: NGINX_PORT });
    socket.setTimeout(6000);
    let buf = '';
    const done = (v: number) => {
      socket.destroy();
      resolve(v);
    };
    socket.on('connect', () => {
      socket.write(
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\n` +
          `X-Forwarded-For: ${forwardedFor}\r\nConnection: close\r\n\r\n`
      );
    });
    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      if (m) done(Number(m[1]));
    });
    // 444 closes without a response, which is the normal catch-all answer.
    socket.on('close', () => done(0));
    socket.on('error', () => done(0));
    socket.on('timeout', () => done(0));
  });
}

test.describe('Global fail2ban jail (#275)', () => {
  let apiHelper: APIHelper;
  let token: string;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
    token = await apiHelper.getToken();
  });

  test.afterAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext();
    try {
      const helper = new APIHelper(ctx);
      await helper.login();
      const auth = { Authorization: `Bearer ${await helper.getToken()}` };
      // Leave the instance disarmed and the precondition unset, whatever failed.
      await ctx.put(`${API}${GLOBAL}`, {
        headers: auth,
        data: { enabled: false, action: 'log', fail_codes: '400,444', max_retries: 5 },
      });
      await ctx.put(`${API}/api/v1/system-settings`, {
        headers: auth,
        data: { trusted_proxy_cidrs: '' },
      });
    } finally {
      await ctx.dispose();
    }
  });

  test('ships disabled, in log mode, with the measured default codes', async ({ request }) => {
    const res = await request.get(`${API}${GLOBAL}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.ok()).toBe(true);
    const cfg = await res.json();
    // A jail that bans on every host must not arrive armed.
    expect(cfg.enabled).toBe(false);
    expect(cfg.action).toBe('log');
    expect(cfg.fail_codes).toBe('400,444');
  });

  test.describe('Enabling requires trusted proxies', () => {
    test('refuses to enable while trusted proxies are unconfigured', async ({ request }) => {
      await request.put(`${API}/api/v1/system-settings`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { trusted_proxy_cidrs: '', trusted_proxy_preset: 'none' },
      });

      const res = await request.put(`${API}${GLOBAL}`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { enabled: true },
      });
      // This is the only real protection for a CDN deployment: with no trusted
      // proxy set, every request carries the edge address, and one global ban
      // would block every visitor behind that edge on every host.
      expect(res.status()).toBe(400);
      expect(String((await res.json()).error)).toMatch(/Trusted Proxies/i);

      const after = await (
        await request.get(`${API}${GLOBAL}`, { headers: { Authorization: `Bearer ${token}` } })
      ).json();
      expect(after.enabled, 'a refused enable must not have been persisted').toBe(false);
    });

    test('allows other fields to be changed while disabled', async ({ request }) => {
      const res = await request.put(`${API}${GLOBAL}`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { fail_codes: '444' },
      });
      expect(res.status()).toBe(200);
    });

    test('allows enabling once trusted proxies are set', async ({ request }) => {
      await request.put(`${API}/api/v1/system-settings`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { trusted_proxy_cidrs: '203.0.113.0/24' },
      });
      const res = await request.put(`${API}${GLOBAL}`, {
        headers: { Authorization: `Bearer ${token}` },
        data: { enabled: true },
      });
      expect(res.status()).toBe(200);
      expect((await res.json()).enabled).toBe(true);
    });
  });

  test.describe('Validation', () => {
    const rejected: Record<string, unknown>[] = [
      { fail_codes: '4o1' },
      { fail_codes: '401;403' },
      { action: 'banhammer' },
      { max_retries: 0 },
      { find_time: -5 },
      { ban_time: -1 },
    ];
    for (const body of rejected) {
      test(`rejects ${JSON.stringify(body)}`, async ({ request }) => {
        const res = await request.put(`${API}${GLOBAL}`, {
          headers: { Authorization: `Bearer ${token}` },
          data: body,
        });
        expect(res.status()).toBe(400);
        // A bad enum used to surface as 500 because the validation error did
        // not wrap the sentinel the handler classifies on.
        expect(String((await res.json()).error ?? '')).not.toMatch(/database/i);
      });
    }
  });

  test.describe('What it acts on', () => {
    const SCANNER_IP = '198.51.100.201';
    const VISITOR_IP = '198.51.100.202';
    let redirectHostId = '';

    test.beforeAll(async ({ playwright }) => {
      const ctx = await playwright.request.newContext();
      const helper = new APIHelper(ctx);
      await helper.login();
      const auth = { Authorization: `Bearer ${await helper.getToken()}` };

      await ctx.put(`${API}/api/v1/system-settings`, {
        headers: auth,
        data: { trusted_proxy_cidrs: '203.0.113.0/24' },
      });
      await ctx.put(`${API}${GLOBAL}`, {
        headers: auth,
        data: { enabled: true, action: 'block', fail_codes: '444', max_retries: 3, find_time: 600 },
      });

      const created = await ctx.post(`${API}/api/v1/redirect-hosts`, {
        headers: auth,
        data: {
          domain_names: ['e2e-redirect-275.example.local'],
          forward_domain_name: 'example.com',
          redirect_code: 301,
          enabled: true,
        },
      });
      if (created.ok()) redirectHostId = (await created.json()).id;

      // The collector refreshes its host snapshot on a 30s ticker; the jail
      // reads its config on the same cadence.
      await new Promise((r) => setTimeout(r, 35000));
      await ctx.dispose();
    });

    test.afterAll(async ({ playwright }) => {
      const ctx = await playwright.request.newContext();
      const helper = new APIHelper(ctx);
      await helper.login();
      const auth = { Authorization: `Bearer ${await helper.getToken()}` };
      if (redirectHostId) {
        await ctx.delete(`${API}/api/v1/redirect-hosts/${redirectHostId}`, { headers: auth });
      }
      for (const ip of [SCANNER_IP, VISITOR_IP]) {
        const list = await ctx.get(`${API}/api/v1/banned-ips?per_page=200`, { headers: auth });
        if (!list.ok()) continue;
        const payload = await list.json();
        for (const row of payload.data ?? []) {
          if (row.ip_address === ip) {
            await ctx.delete(`${API}/api/v1/banned-ips/${row.id}`, { headers: auth });
          }
        }
      }
      await ctx.dispose();
    });

    async function isBanned(request: import('@playwright/test').APIRequestContext, ip: string) {
      const res = await request.get(`${API}/api/v1/banned-ips?per_page=200`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok()) return false;
      const payload = await res.json();
      return (payload.data ?? []).some((r: { ip_address: string }) => r.ip_address === ip);
    }

    test('bans an address that keeps hitting no configured host', async ({ request }) => {
      for (let i = 0; i < 4; i++) {
        await probe('e2e-nobody-275.example.invalid', `/scan-${i}`, SCANNER_IP);
      }
      await expect
        .poll(() => isBanned(request, SCANNER_IP), { timeout: 30000 })
        .toBe(true);
    });

    test('does NOT ban a visitor to a redirect host', async ({ request }) => {
      // Redirect hosts are configured hosts. Their visitors are not scanners,
      // and their 404s / cleartext-to-TLS 400s are unattributed today — which
      // is exactly how a naive predicate would ban real people everywhere.
      for (let i = 0; i < 8; i++) {
        await probe('e2e-redirect-275.example.local', `/missing-${i}`, VISITOR_IP);
      }
      await new Promise((r) => setTimeout(r, 8000));
      expect(await isBanned(request, VISITOR_IP)).toBe(false);
    });
  });
});

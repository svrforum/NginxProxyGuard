import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';

/**
 * The banned-IP list's type filter (#394) runs on the server, so the total and
 * page count describe the filtered bans. It used to filter one 50-row page in
 * the browser while the page count still covered every type.
 */
const API = 'http://127.0.0.1:19080/api/v1';
const IPS = ['198.51.100.201', '198.51.100.202', '198.51.100.203'];

test.describe.configure({ mode: 'serial' });

test.describe('Banned IP type filter (#394)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  const ids: string[] = [];

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(async ({ request }) => {
    for (const id of ids.splice(0)) {
      await request.delete(`${API}/banned-ips/${id}`, { headers }).catch(() => undefined);
    }
  });

  test('narrows the list, the total and the page count to one type', async ({ request }) => {
    const reasons = ['e2e-394 WAF rule probe', 'e2e-394 WAF rule probe', 'e2e-394 note'];
    for (let i = 0; i < IPS.length; i++) {
      const res = await request.post(`${API}/banned-ips`, {
        headers,
        data: { ip_address: IPS[i], reason: reasons[i], ban_time: 600 },
      });
      expect(res.status(), await res.text()).toBe(201);
      ids.push((await res.json()).id);
    }

    type Ban = { ip_address: string; reason?: string; is_auto_banned: boolean };
    const list = async (type: string) => {
      const res = await request.get(`${API}/banned-ips?filter=global&type=${type}&per_page=100`, { headers });
      expect(res.status()).toBe(200);
      return (await res.json()) as { data: Ban[] | null; total: number; total_pages: number };
    };
    const ip = (b: Ban) => b.ip_address.replace(/\/32$/, '');

    const waf = await list('waf');
    const wafIPs = (waf.data ?? []).map(ip);
    expect(wafIPs).toEqual(expect.arrayContaining(IPS.slice(0, 2)));
    expect(wafIPs).not.toContain(IPS[2]);
    for (const b of waf.data ?? []) expect(b.reason?.toLowerCase()).toMatch(/waf|modsec|rule/);
    expect(waf.total).toBe((waf.data ?? []).length);
    expect(waf.total_pages).toBe(1);

    const manual = await list('manual');
    expect((manual.data ?? []).map(ip)).toEqual(expect.arrayContaining(IPS));
    for (const b of manual.data ?? []) expect(b.is_auto_banned).toBe(false);
    expect(manual.total).toBe((manual.data ?? []).length);

    const all = await list('all');
    expect(all.total).toBeGreaterThanOrEqual(manual.total);

    expect((await request.get(`${API}/banned-ips?type=bogus`, { headers })).status()).toBe(400);
  });
});

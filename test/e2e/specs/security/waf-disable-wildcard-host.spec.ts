import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';

/**
 * WAF events carry the request's Host, and the log viewer's per-host disable
 * finds the proxy host from it. On a wildcard host ("*.example.com") or a
 * domain saved with capitals, that lookup wanted an exact stored name and
 * answered "Proxy host not found for domain".
 */
const API = 'http://127.0.0.1:19080/api/v1';

test.describe('WAF per-host disable on wildcard and mixed-case hosts', () => {
  test('finds the host nginx serves the request from', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const headers = { Authorization: `Bearer ${await api.getToken()}` };

    const base = { forward_scheme: 'http', forward_host: '127.0.0.1', forward_port: 9, waf_enabled: true };
    const wild = await api.createProxyHost({ ...base, domain_names: ['*.wild-dis.example.com'] });
    const upper = await api.createProxyHost({ ...base, domain_names: ['Upper-Dis.example.com'] });

    const disable = (host: string) =>
      request.post(`${API}/waf/rules/disable-by-host`, {
        headers,
        data: { host, rule_id: 920430, reason: 'e2e wildcard lookup' },
      });

    try {
      expect((await disable('f.wild-dis.example.com')).status()).toBe(201);
      expect((await disable('upper-dis.example.com')).status()).toBe(201);
      // A wildcard does not cover its own apex, same as nginx.
      expect((await disable('wild-dis.example.com')).status()).toBe(404);

      const byDomain = await request.get(`${API}/proxy-hosts/by-domain/a.b.wild-dis.example.com`, { headers });
      expect(byDomain.status()).toBe(200);
      expect((await byDomain.json()).id).toBe(wild.id);
    } finally {
      await api.deleteProxyHost(wild.id).catch(() => undefined);
      await api.deleteProxyHost(upper.id).catch(() => undefined);
    }
  });
});

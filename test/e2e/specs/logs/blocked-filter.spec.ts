import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { pollForLog, triggerUntil } from '../../utils/log-helper';
import { TestDataFactory } from '../../utils/test-data-factory';
import { API_ENDPOINTS } from '../../fixtures/test-data';

/**
 * #407: block_reason=blocked lists every blocked request, whatever the reason.
 * A WAF block leaves its access row at block_reason 'none' (ModSecurity answers
 * before nginx can tag the row), so the filter follows the dashboard's blocked
 * count: a row with a reason, or a 403 that never reached an upstream.
 */
test.describe('Access log "blocked" filter (#407)', () => {
  let api: APIHelper;

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
  });

  test.afterEach(async () => {
    await api.cleanupTestHosts();
  });

  test('includes a WAF block and leaves out a request that reached the upstream', async ({ request }) => {
    const domain = TestDataFactory.generateDomain('blocked-filter');
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      // Unreachable, so a request that passes every check ends as a 502 with
      // an upstream address.
      forward_host: '127.0.0.1',
      forward_port: 1,
      enabled: true,
    });
    await api.enableWAF(host.id, { mode: 'blocking', paranoiaLevel: 1 });

    await triggerUntil({
      host: domain,
      path: "/?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
    }, r => r.status === 403, { describe: 'the SQLi probe to be blocked by ModSecurity' });
    await triggerUntil({ host: domain, path: '/passed' }, r => r.status === 502, {
      describe: 'a plain request to reach the dead upstream',
    });

    const wafRow = await pollForLog(api, {
      host: domain, expectedLogType: 'access', expectedStatus: 403, uriContains: 'UNION', timeoutMs: 15_000,
    });
    const passedRow = await pollForLog(api, {
      host: domain, expectedLogType: 'access', expectedStatus: 502, uriContains: '/passed', timeoutMs: 15_000,
    });

    const blocked = await api.getLogs({ host: domain, block_reason: 'blocked', limit: 200 });
    const ids = blocked.map(r => r.id);
    expect(ids, 'the WAF-blocked request').toContain(wafRow.id);
    expect(ids, 'the request that reached the upstream').not.toContain(passedRow.id);

    // The stats behind the list use the same filter. They are cached per
    // filter for minutes, so each is read once: a probe still landing can only
    // add to the unfiltered count.
    const headers = { Authorization: `Bearer ${await api.getToken()}` };
    const statsTotal = async (extra: string) => {
      const res = await request.get(
        `${API_ENDPOINTS.logs}/stats?log_type=access&host=${encodeURIComponent(domain)}${extra}`,
        { headers },
      );
      expect(res.ok(), `stats ${extra || '(all)'}`).toBeTruthy();
      return (await res.json()).total_logs as number;
    };
    const blockedTotal = await statsTotal('&block_reason=blocked');
    const allTotal = await statsTotal('');
    expect(blockedTotal, 'blocked requests in the stats').toBeGreaterThanOrEqual(1);
    expect(blockedTotal, 'the passed request stays out of the blocked stats').toBeLessThan(allTotal);
  });
});

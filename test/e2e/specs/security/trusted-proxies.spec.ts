import { test, expect } from '@playwright/test';
import { execFileSync } from 'child_process';
import { APIHelper } from '../../utils/api-helper';

/**
 * Trusted proxies (#278) decide whose forwarded-client-address header nginx
 * believes. Everything that judges a visitor by address reads the result —
 * GeoIP country rules, access lists, banned IPs, fail2ban attribution, rate
 * limiting and ModSecurity's REMOTE_ADDR — so these tests assert against the
 * real nginx.conf the proxy container is consuming, not against API echoes.
 *
 * The invariant that matters most is the boring one: an install that never
 * touches the setting must render exactly what it rendered before the setting
 * existed.
 */
function readProxyNginxConf(): string {
  return execFileSync(
    'sudo',
    ['docker', 'exec', 'npg-test-proxy', 'cat', '/etc/nginx/nginx.conf'],
    { encoding: 'utf8' }
  );
}

/**
 * A settings save schedules an ORDERED background worker that regenerates
 * nginx.conf and reloads — the API returns before the file changes, and the UI
 * says "Saved. Applying...". Every assertion about the file therefore has to
 * wait for the write rather than read straight after the PUT.
 */
async function expectConfEventually(
  predicate: (conf: string) => boolean,
  description: string,
  timeoutMs = 30000
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  let conf = '';
  while (Date.now() < deadline) {
    conf = readProxyNginxConf();
    if (predicate(conf)) return conf;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`nginx.conf never satisfied: ${description}\n--- real_ip section ---\n${realIPSection(conf)}`);
}

function realIPSection(conf: string): string {
  const start = conf.indexOf('set_real_ip_from');
  if (start < 0) return '(no set_real_ip_from found)';
  const end = conf.indexOf('real_ip_recursive', start);
  return conf.slice(start, end < 0 ? start + 800 : end + 30);
}

// The real-IP block is one shared http-level stanza, so parallel mutation
// would make these tests read each other's writes.
test.describe.configure({ mode: 'serial' });

const BUILTINS = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '::1',
  'fc00::/7',
];

test.describe('Trusted Proxies (#278)', () => {
  let apiHelper: APIHelper;

  test.beforeEach(async ({ request }) => {
    apiHelper = new APIHelper(request);
    await apiHelper.login();
  });

  test.afterEach(async () => {
    // Always put the instance back on defaults: leaving a preset applied would
    // change what every later spec's client address resolves to.
    try {
      await apiHelper.updateSystemSettings({
        trusted_proxy_preset: 'none',
        trusted_proxy_cidrs: '',
        real_ip_header: 'X-Forwarded-For',
      } as Record<string, unknown>);
      // Wait for the restore to land, or the next test reads this test's config.
      await expectConfEventually(
        (c) => c.includes('real_ip_header X-Forwarded-For;') && !c.includes('Operator-configured proxies'),
        'defaults restored'
      );
    } catch {
      // Ignore cleanup errors
    }
  });

  test.describe('Defaults', () => {
    test('render the same real-IP block as before the setting existed', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_preset: 'none',
        trusted_proxy_cidrs: '',
        real_ip_header: 'X-Forwarded-For',
      } as Record<string, unknown>);

      const conf = readProxyNginxConf();
      for (const range of BUILTINS) {
        expect(conf).toContain(`set_real_ip_from ${range};`);
      }
      expect(conf).toContain('real_ip_header X-Forwarded-For;');
      // The empty-value regression: `real_ip_header ;` fails nginx -t, and
      // because the generator rolls back, the install silently falls back to
      // the image-seeded nginx.conf with every global setting unapplied.
      expect(conf).not.toContain('real_ip_header ;');
      // Nothing extra when no preset and no custom entries.
      expect(conf).not.toContain('Operator-configured proxies');
    });

    test('report resolved values, not raw columns', async () => {
      const settings = (await apiHelper.getSystemSettings()) as Record<string, unknown>;
      expect(settings.real_ip_header).toBe('X-Forwarded-For');
      expect(settings.trusted_proxy_preset).toBe('none');
      expect(Array.isArray(settings.trusted_proxy_builtins)).toBe(true);
      expect(settings.trusted_proxy_builtins).toEqual(BUILTINS);
    });
  });

  test.describe('Applying trusted proxies', () => {
    test('adds custom ranges after the built-ins, keeping the built-ins', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_cidrs: '203.0.113.0/24\n198.51.100.7',
      } as Record<string, unknown>);

      const conf = await expectConfEventually(
        (c) => c.includes('set_real_ip_from 203.0.113.0/24;') && c.includes('set_real_ip_from 198.51.100.7;'),
        'both custom ranges present'
      );
      for (const range of BUILTINS) {
        expect(conf).toContain(`set_real_ip_from ${range};`);
      }
      // Built-ins first: a Docker or LAN peer must resolve through the ranges
      // that have always been trusted, whatever the operator added.
      expect(conf.indexOf('10.0.0.0/8')).toBeLessThan(conf.indexOf('203.0.113.0/24'));
    });

    test('the Cloudflare preset contributes its published ranges', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_preset: 'cloudflare',
      } as Record<string, unknown>);

      const settings = (await apiHelper.getSystemSettings()) as Record<string, unknown>;
      const presetRanges = settings.trusted_proxy_preset_ranges as string[];
      expect(presetRanges.length).toBeGreaterThan(10);

      const conf = await expectConfEventually(
        (c) => presetRanges.every((r) => c.includes(`set_real_ip_from ${r};`)),
        'all Cloudflare preset ranges present'
      );
      // Built-ins survive the preset — a tunnel/Docker deployment still works.
      expect(conf).toContain('set_real_ip_from 127.0.0.0/8;');
    });

    test('changes the header nginx reads', async () => {
      await apiHelper.updateSystemSettings({
        real_ip_header: 'CF-Connecting-IP',
      } as Record<string, unknown>);

      const conf = await expectConfEventually(
        (c) => c.includes('real_ip_header CF-Connecting-IP;'),
        'header switched to CF-Connecting-IP'
      );
      expect(conf).not.toContain('real_ip_header X-Forwarded-For;');
    });

    test('does not repeat a range that is already built in', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_cidrs: '10.0.0.0/8',
      } as Record<string, unknown>);

      // Nothing new appears, so wait for the reload to settle before counting.
      await new Promise((r) => setTimeout(r, 10000));
      const conf = readProxyNginxConf();
      const occurrences = conf.split('set_real_ip_from 10.0.0.0/8;').length - 1;
      expect(occurrences).toBe(1);
    });

    test('clearing the list returns to the built-ins only', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_cidrs: '203.0.113.0/24',
      } as Record<string, unknown>);
      await expectConfEventually(
        (c) => c.includes('set_real_ip_from 203.0.113.0/24;'),
        'custom range applied before clearing'
      );

      await apiHelper.updateSystemSettings({
        trusted_proxy_cidrs: '',
      } as Record<string, unknown>);
      await expectConfEventually(
        (c) => !c.includes('set_real_ip_from 203.0.113.0/24;'),
        'custom range removed'
      );
    });
  });

  test.describe('Validation', () => {
    // Every rejection here is a security control: a value that reaches
    // nginx.conf unvalidated either breaks the reload for every host on the
    // instance, or widens who may forge a client address.
    const rejected: { name: string; body: Record<string, unknown> }[] = [
      { name: 'trust the entire IPv4 internet', body: { trusted_proxy_cidrs: '0.0.0.0/0' } },
      { name: 'trust the entire IPv6 internet', body: { trusted_proxy_cidrs: '::/0' } },
      { name: 'a single oversized block', body: { trusted_proxy_cidrs: '240.0.0.0/4' } },
      { name: 'an unparseable entry', body: { trusted_proxy_cidrs: 'not-an-ip' } },
      { name: 'a bad prefix length', body: { trusted_proxy_cidrs: '203.0.113.0/33' } },
      { name: 'a header outside the allowlist', body: { real_ip_header: 'X-Evil' } },
      { name: 'a header carrying an injected directive', body: { real_ip_header: 'X-Real-IP; return 200' } },
      { name: 'an unknown preset', body: { trusted_proxy_preset: 'fastly' } },
    ];

    for (const { name, body } of rejected) {
      test(`rejects ${name} with 400`, async ({ request }) => {
        const res = await request.put('/api/v1/system-settings', {
          data: body,
          headers: { Authorization: `Bearer ${await apiHelper.getToken()}` },
        });
        expect(res.status()).toBe(400);
        const payload = await res.json();
        // The message must name what was wrong; a bare "database error" is the
        // failure mode this validation exists to prevent.
        expect(String(payload.error ?? '')).not.toMatch(/database/i);
        expect(String(payload.error ?? '').length).toBeGreaterThan(10);
      });
    }

    test('a rejected value never reaches nginx.conf', async ({ request }) => {
      await request.put('/api/v1/system-settings', {
        data: { real_ip_header: 'X-Evil' },
        headers: { Authorization: `Bearer ${await apiHelper.getToken()}` },
      });
      // A rejected value must never be written at all, so give the worker the
      // same window a successful save would have had, then assert nothing changed.
      await new Promise((r) => setTimeout(r, 10000));
      const conf = readProxyNginxConf();
      expect(conf).not.toContain('X-Evil');
      expect(conf).toContain('real_ip_header X-Forwarded-For;');
    });

    test('accepts an ordinary operator allocation', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_cidrs: '203.0.113.0/24\n198.51.100.0/22\n# a comment\n',
      } as Record<string, unknown>);
      const settings = (await apiHelper.getSystemSettings()) as Record<string, unknown>;
      expect(String(settings.trusted_proxy_cidrs)).toContain('203.0.113.0/24');
    });
  });

  test.describe('nginx stays valid', () => {
    test('the generated config passes nginx -t with a preset applied', async () => {
      await apiHelper.updateSystemSettings({
        trusted_proxy_preset: 'cloudflare',
        trusted_proxy_cidrs: '203.0.113.0/24',
        real_ip_header: 'CF-Connecting-IP',
      } as Record<string, unknown>);

      await expectConfEventually(
        (c) => c.includes('real_ip_header CF-Connecting-IP;'),
        'preset + header applied'
      );
      // nginx -t reports on stderr, so assert on the exit status: execFileSync
      // throws on a non-zero exit, which is exactly "the config is invalid".
      expect(() =>
        execFileSync('sudo', ['docker', 'exec', 'npg-test-proxy', 'nginx', '-t'], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      ).not.toThrow();
    });
  });
});

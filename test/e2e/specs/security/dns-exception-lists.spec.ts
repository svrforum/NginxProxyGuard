import { test, expect, type APIRequestContext, type Browser, type Page } from '@playwright/test';
import { execFileSync } from 'child_process';
import * as net from 'net';
import { ProxyHostFormPage, ProxyHostListPage } from '../../pages';
import { APIHelper, type DNSEntryStatusData } from '../../utils/api-helper';
import { pollForLog } from '../../utils/log-helper';
import { NGINX_HTTP_PORT, ROUTES } from '../../fixtures/test-data';

/**
 * Domains in the four exception lists (#320): URI block exceptions, priority
 * allow, rate limit exceptions and the global trusted list. What a domain
 * there lets its address past, what it never gets past (bans, the WAF, an
 * access list's own deny, the login of a host), the screens that save it,
 * names an older version stored in an IP field, and roles.
 *
 * The API container resolves exempt.e2e.example through extra_hosts in
 * docker-compose.e2e-test.yml, so nothing here is looked up on the internet;
 * a test that saved any other name would send a public DNS query
 * (partner.e2e.example, also listed there, is only sent in saves the domain
 * limit refuses). Its
 * address and the clients below are in 100.64.32.0/24, CGNAT: the address
 * policy refuses the documentation ranges as reserved and allows CGNAT, so a
 * domain can only resolve to such an address here. scripts/pii-scan.sh lists
 * them as IPv4 to check by eye; they are nobody's address.
 *
 * Each host proxies to the API itself (127.0.0.1:19080, which nginx reaches
 * from the host network), so a request NPG lets through gets the API's 404
 * and one it blocks gets NPG's 403. Clients are simulated with
 * X-Forwarded-For from loopback, which nginx always trusts.
 *
 * No test changes what the name resolves to. If an earlier run of the other
 * DNS spec or a manual check left the name pointing elsewhere, beforeAll puts
 * it back by rewriting the API container's /etc/hosts in place: it is a bind
 * mount, so never sed -i. Go reads it again at most 5 s later.
 *
 * The global singletons this file changes are the trusted IPs and domains in
 * system_settings, and the per-list domain limit in its dns_entry_settings;
 * afterEach puts them back as beforeAll found them (without this file's own
 * leftovers).
 */
const API = 'http://127.0.0.1:19080';
const UI = process.env.BASE_URL || 'https://localhost:18181';
const API_CONTAINER = process.env.NPG_TEST_API_CONTAINER || 'npg-test-api';
const DB_CONTAINER = process.env.NPG_TEST_DB_CONTAINER || 'npg-test-db';
const VALKEY_CONTAINER = process.env.NPG_TEST_VALKEY_CONTAINER || 'npg-test-valkey';
// What the API answers for the paths below, none of which it serves.
const PASSED = 404;
// Hosts, lists, auth providers, bans, users and roles of this file start with
// it. The sweeps delete only those: other spec files run alongside.
const PREFIX = 'r3-dns-';
const EXEMPT = 'exempt.e2e.example';
const EXEMPT_IP = '100.64.32.30';
// A second name, only ever sent over the domain limit.
const PARTNER = 'partner.e2e.example';
// The per-list domain limit (dns_entry_settings.max_per_list) while a test
// goes over it with two names. beforeAll takes this value for what a run
// stopped in such a test left, and puts the default back.
const LOW_MAX_PER_LIST = 1;
const DEFAULT_MAX_PER_LIST = 16;
// A static URI block exception and a static priority allow entry.
const STATIC_IP = '100.64.32.31';
// A client no list of this file allows.
const OUTSIDER = '100.64.32.11';
// Static entries next to the names; nobody sends from them.
const STATIC_PRIORITY_IP = '192.0.2.44';
const STATIC_TRUSTED_IP = '192.0.2.45';
const BAD_BOT = 'User-Agent: R3DnsBadBot/1.0\r\n';
const SQLI = "/?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--";
// Built-in roles (database/migration.go).
const ROLE_OPERATOR = '00000000-0000-0000-0000-0000000000a2';
const ROLE_VIEWER = '00000000-0000-0000-0000-0000000000a3';
// The host form and the global geo screen ask for the GeoIP status, which
// needs settings:read, so a viewer or an operator gets a 403 there. main does
// the same; it is older than #320 and left to its own fix.
const KNOWN_403 = new Set(['GET /api/v1/system-settings/geoip/status']);

test.describe.configure({ mode: 'serial' });

interface Head {
  status: number;
  headers: string;
}

/** Send a GET with an explicit Host and client address; resolve with the response head (status 0 = no answer). */
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
        `GET ${path} HTTP/1.1\r\nHost: ${host}\r\nX-Forwarded-For: ${forwardedFor}\r\n${extra}Connection: close\r\n\r\n`,
      );
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

async function probe(host: string, path: string, forwardedFor: string, extra = ''): Promise<number> {
  return (await probeHead(host, path, forwardedFor, extra)).status;
}

/** n requests for "/" sent at once from one client; their statuses. */
function burst(host: string, forwardedFor: string, n: number): Promise<number[]> {
  return Promise.all(Array.from({ length: n }, () => probe(host, '/', forwardedFor)));
}

async function eventually(fn: () => Promise<boolean>, what: string, ms = 20000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`never: ${what}`);
}

function uuid(id: string): string {
  if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error(`not a UUID: ${id}`);
  return id;
}

/** One SQL statement against the e2e database, output trimmed. Values are this file's constants or checked UUIDs. */
function sql(statement: string): string {
  return execFileSync(
    'docker',
    ['exec', DB_CONTAINER, 'psql', '-U', 'postgres', '-d', 'nginx_guard_test', '-tAc', statement],
    { encoding: 'utf-8' },
  ).trim();
}

/** Drops one key of the API's cache, after SQL changed the row behind it. */
function dropCached(key: string): void {
  execFileSync('docker', ['exec', VALKEY_CONTAINER, 'valkey-cli', 'DEL', key], { encoding: 'utf-8' });
}

/** A host's priority allow as stored: "<allowed_ips>|<allowed_hostnames>", each comma-joined. */
function storedPriorityAllow(hostId: string): string {
  return sql(
    `SELECT COALESCE(array_to_string(allowed_ips, ','), '') || '|' || COALESCE(array_to_string(allowed_hostnames, ','), '') ` +
      `FROM geo_restrictions WHERE proxy_host_id = '${uuid(hostId)}'`,
  );
}

function readHosts(): string {
  return execFileSync('docker', ['exec', API_CONTAINER, 'cat', '/etc/hosts'], { encoding: 'utf-8' });
}

/** The address the API container's /etc/hosts gives name, or '' without a line for it. */
function hostsEntry(name: string): string {
  for (const line of readHosts().split('\n')) {
    const [addr, first] = line.trim().split(/\s+/);
    if (first === name) return addr;
  }
  return '';
}

/** Points name at addr in the API container's /etc/hosts. The file is a bind mount, so it is rewritten in place. */
function setHostsEntry(name: string, addr: string): void {
  const kept = readHosts()
    .split('\n')
    .filter((line) => line.trim() !== '' && line.trim().split(/\s+/)[1] !== name);
  kept.push(`${addr}\t${name}`);
  execFileSync('docker', ['exec', '-i', API_CONTAINER, 'sh', '-c', 'cat > /etc/hosts'], {
    input: `${kept.join('\n')}\n`,
    encoding: 'utf-8',
  });
}

type Named = { id: string; name?: string; username?: string; reason?: string; domain_names?: string[] };

async function listOf(ctx: APIRequestContext, path: string, headers: Record<string, string>): Promise<Named[]> {
  const res = await ctx.get(path, { headers });
  if (!res.ok()) return [];
  const body = await res.json();
  return (Array.isArray(body) ? body : body.data) ?? [];
}

/** The trusted list of system_settings: the IP text and the domains. */
interface Trusted {
  ips: string;
  names: string[];
}

async function readTrusted(ctx: APIRequestContext, headers: Record<string, string>): Promise<Trusted> {
  const res = await ctx.get(`${API}/api/v1/system-settings`, { headers });
  expect(res.status(), 'GET /api/v1/system-settings').toBe(200);
  const s = await res.json();
  return { ips: s.global_trusted_ips ?? '', names: s.global_trusted_hostnames ?? [] };
}

/** The trusted list without what this file puts in it. */
function withoutOurs(t: Trusted): Trusted {
  const ours = new Set([EXEMPT, STATIC_TRUSTED_IP]);
  return {
    ips: t.ips
      .split('\n')
      .filter((line) => !ours.has(line.trim()))
      .join('\n'),
    names: t.names.filter((n) => n !== EXEMPT),
  };
}

function sameTrusted(a: Trusted, b: Trusted): boolean {
  return a.ips === b.ips && a.names.join(',') === b.names.join(',');
}

async function readMaxPerList(ctx: APIRequestContext, headers: Record<string, string>): Promise<number> {
  const res = await ctx.get(`${API}/api/v1/system-settings`, { headers });
  expect(res.status(), 'GET /api/v1/system-settings').toBe(200);
  return (await res.json()).dns_entry_settings.max_per_list;
}

async function putMaxPerList(ctx: APIRequestContext, headers: Record<string, string>, limit: number): Promise<void> {
  const res = await ctx.put(`${API}/api/v1/system-settings`, { headers, data: { dns_entry_settings: { max_per_list: limit } } });
  expect(res.ok(), `max_per_list ${limit}: ${await res.text()}`).toBeTruthy();
}

/** Deletes what this file makes, by prefix: what a failed earlier run left, or a test's own at its end. */
async function sweep(ctx: APIRequestContext, headers: Record<string, string>): Promise<void> {
  const del = (path: string) => ctx.delete(`${API}${path}`, { headers }).catch(() => undefined);
  for (const b of await listOf(ctx, `${API}/api/v1/banned-ips`, headers)) {
    if (b.reason?.startsWith(PREFIX)) await del(`/api/v1/banned-ips/${b.id}`);
  }
  // Hosts before the lists and the auth providers they use.
  for (const h of await listOf(ctx, `${API}/api/v1/proxy-hosts?per_page=100`, headers)) {
    if (h.domain_names?.[0]?.startsWith(PREFIX)) await del(`/api/v1/proxy-hosts/${h.id}`);
  }
  for (const p of await listOf(ctx, `${API}/api/v1/auth-providers?per_page=100`, headers)) {
    if (p.name?.startsWith(PREFIX)) await del(`/api/v1/auth-providers/${p.id}`);
  }
  for (const l of await listOf(ctx, `${API}/api/v1/access-lists?per_page=100`, headers)) {
    if (l.name?.startsWith(PREFIX)) await del(`/api/v1/access-lists/${l.id}`);
  }
  // Users before roles: a role a user still has cannot go.
  for (const u of await listOf(ctx, `${API}/api/v1/users`, headers)) {
    if (u.username?.startsWith(PREFIX)) await del(`/api/v1/users/${u.id}`);
  }
  for (const r of await listOf(ctx, `${API}/api/v1/roles`, headers)) {
    if (r.name?.startsWith(PREFIX)) await del(`/api/v1/roles/${r.id}`);
  }
}

// The password an account made by createRoleUser ends up with.
const ROLE_USER_PASSWORD = 'E2e-Next-Pass-34!';

interface RoleUser {
  id: string;
  username: string;
  token: string;
}

/** An account an administrator made with role roleId, past its forced password change. */
async function createRoleUser(
  request: APIRequestContext,
  headers: Record<string, string>,
  roleId: string,
  label: string,
): Promise<RoleUser> {
  const username = `${PREFIX}${label}-${Date.now()}`;
  const first = 'E2e-First-Pass-12!';
  const created = await request.post(`${API}/api/v1/users`, { headers, data: { username, password: first, role_id: roleId } });
  expect(created.status(), await created.text()).toBe(201);
  const id = (await created.json()).id as string;
  const login = await request.post(`${API}/api/v1/auth/login`, { data: { username, password: first } });
  expect(login.ok(), `login of ${username}`).toBeTruthy();
  const token = (await login.json()).token as string;
  // Such an account may do nothing else until it picks its own password.
  const changed = await request.post(`${API}/api/v1/auth/change-password`, {
    headers: { Authorization: `Bearer ${token}` },
    data: { current_password: first, new_password: ROLE_USER_PASSWORD, new_password_confirm: ROLE_USER_PASSWORD },
  });
  expect(changed.status(), await changed.text()).toBe(200);
  return { id, username, token };
}

/** A browser context signed in with token, in English, recording every 403 the UI gets from the API. */
async function openAs(browser: Browser, token: string): Promise<{ page: Page; forbidden: string[]; close: () => Promise<void> }> {
  const context = await browser.newContext({ baseURL: UI, ignoreHTTPSErrors: true });
  await context.addInitScript((t: string) => {
    window.localStorage.setItem('npg_token', t);
    window.localStorage.setItem('npg_language', 'en');
  }, token);
  const page = await context.newPage();
  const forbidden: string[] = [];
  page.on('response', (res) => {
    if (res.status() === 403 && res.url().includes('/api/')) {
      forbidden.push(`${res.request().method()} ${new URL(res.url()).pathname}`);
    }
  });
  return { page, forbidden, close: () => context.close() };
}

/** A domain's chip in a domain field. */
function chip(page: Page, name: string) {
  return page.getByTestId('dns-hostnames-field').locator(`[data-testid="dns-name-chip"][data-hostname="${name}"]`);
}

/** Types name into the domain field on screen and adds it. */
async function addDomain(page: Page, name: string): Promise<void> {
  const field = page.getByTestId('dns-hostnames-field');
  await field.getByRole('textbox', { name: 'Domains' }).fill(name);
  await field.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(chip(page, name)).toBeVisible();
}

/** Opens a host's form from the host list, once the form has read the host's geo record. */
async function openHostForm(page: Page, hostId: string, domain: string): Promise<ProxyHostFormPage> {
  const list = new ProxyHostListPage(page);
  await list.goto();
  const geoRead = page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === `/api/v1/proxy-hosts/${hostId}/geo`,
  );
  await list.clickHost(domain);
  await geoRead;
  const form = new ProxyHostFormPage(page);
  await form.expectForm();
  return form;
}

/** Opens a host's dialog on the URI block screen; returns its domain field. */
async function openURIBlockDialog(page: Page, domain: string) {
  await page.goto(ROUTES.wafUriBlocks);
  await page.getByRole('button', { name: 'Per-Host Rules' }).click();
  // The host filter above the table lists the same name as an option.
  await page.getByRole('table').getByText(domain, { exact: true }).click();
  const field = page.getByTestId('dns-hostnames-field');
  await expect(field).toBeVisible();
  return field;
}

test.describe('Domains in the four exception lists (#320)', () => {
  let api: APIHelper;
  let headers: Record<string, string>;
  // The trusted list as beforeAll found it, without this file's leftovers.
  let trustedBefore: Trusted;
  // The per-list domain limit as beforeAll found it, likewise.
  let maxPerListBefore: number;

  test.beforeAll(async ({ playwright }) => {
    if (!hostsEntry(EXEMPT)) {
      throw new Error(
        `${EXEMPT} is not in ${API_CONTAINER}'s /etc/hosts: recreate the e2e api from docker-compose.e2e-test.yml, whose extra_hosts lists it`,
      );
    }
    if (hostsEntry(EXEMPT) !== EXEMPT_IP) setHostsEntry(EXEMPT, EXEMPT_IP);
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      const helper = new APIHelper(ctx);
      await helper.login();
      const auth = { Authorization: `Bearer ${await helper.getToken()}` };
      await sweep(ctx, auth);
      const found = await readTrusted(ctx, auth);
      trustedBefore = withoutOurs(found);
      if (!sameTrusted(found, trustedBefore)) {
        const res = await ctx.put(`${API}/api/v1/system-settings`, {
          headers: auth,
          data: { global_trusted_ips: trustedBefore.ips, global_trusted_hostnames: trustedBefore.names },
        });
        expect(res.ok(), `put the trusted list back: ${await res.text()}`).toBeTruthy();
      }
      const limit = await readMaxPerList(ctx, auth);
      maxPerListBefore = limit === LOW_MAX_PER_LIST ? DEFAULT_MAX_PER_LIST : limit;
      if (limit !== maxPerListBefore) await putMaxPerList(ctx, auth, maxPerListBefore);
      const overview = await ctx.get(`${API}/api/v1/dns-entries`, { headers: auth });
      expect(overview.status(), 'GET /api/v1/dns-entries').toBe(200);
      const body = await overview.json();
      expect(body.env_interval_seconds, 'NPG_DNS_ENTRIES_INTERVAL of the e2e api').toBe(5);
      // A name no list uses keeps its state for 7 days: start it from none, so
      // the first save has to look it up itself.
      const entry = (body.entries ?? []).find((e: { hostname: string }) => e.hostname === EXEMPT);
      if (!entry || ((entry.uses ?? []).length === 0 && !entry.hidden_uses)) {
        sql(`DELETE FROM dns_entry_states WHERE hostname = '${EXEMPT}'`);
      }
    } finally {
      await ctx.dispose();
    }
  });

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    headers = { Authorization: `Bearer ${await api.getToken()}` };
  });

  test.afterEach(async ({ request }) => {
    await sweep(request, headers);
    if (!sameTrusted(await readTrusted(request, headers), trustedBefore)) {
      await setTrusted(request, { global_trusted_ips: trustedBefore.ips, global_trusted_hostnames: trustedBefore.names });
    }
    if ((await readMaxPerList(request, headers)) !== maxPerListBefore) await putMaxPerList(request, headers, maxPerListBefore);
  });

  test.afterAll(async ({ playwright }) => {
    const ctx = await playwright.request.newContext({ baseURL: API });
    try {
      const helper = new APIHelper(ctx);
      await helper.login();
      const auth = { Authorization: `Bearer ${await helper.getToken()}` };
      await sweep(ctx, auth);
      if (!sameTrusted(await readTrusted(ctx, auth), trustedBefore)) {
        await ctx.put(`${API}/api/v1/system-settings`, {
          headers: auth,
          data: { global_trusted_ips: trustedBefore.ips, global_trusted_hostnames: trustedBefore.names },
        });
      }
      if ((await readMaxPerList(ctx, auth)) !== maxPerListBefore) await putMaxPerList(ctx, auth, maxPerListBefore);
    } finally {
      await ctx.dispose();
    }
  });

  async function createHost(label: string, extra: Record<string, unknown> = {}): Promise<{ id: string; domain: string }> {
    const domain = `${PREFIX}${label}-${Date.now()}.example.com`;
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 19080,
      enabled: true,
      ...extra,
    });
    return { id: host.id, domain };
  }

  async function send(request: APIRequestContext, method: 'post' | 'put', path: string, data: unknown) {
    const res = await request[method](`${API}${path}`, { headers, data });
    expect(res.ok(), `${method.toUpperCase()} ${path}: ${res.status()} ${await res.text()}`).toBeTruthy();
    return res.json();
  }

  async function getJSON(request: APIRequestContext, path: string) {
    const res = await request.get(`${API}${path}`, { headers });
    expect(res.status(), `GET ${path}`).toBe(200);
    return res.json();
  }

  const blockAdmin = { pattern: '/admin', match_type: 'prefix', description: 'e2e', enabled: true };

  function setURIBlock(request: APIRequestContext, hostId: string, body: Record<string, unknown>) {
    return send(request, 'put', `/api/v1/proxy-hosts/${hostId}/uri-block`, { enabled: true, rules: [blockAdmin], ...body });
  }

  /** A geo whitelist of SE only: every client of this file is outside it. */
  function setGeo(request: APIRequestContext, hostId: string, body: Record<string, unknown> = {}) {
    return send(request, 'post', `/api/v1/proxy-hosts/${hostId}/geo`, {
      mode: 'whitelist',
      countries: ['SE'],
      enabled: true,
      allow_private_ips: false,
      allow_search_bots: false,
      ...body,
    });
  }

  function setRateLimit(request: APIRequestContext, hostId: string, body: Record<string, unknown> = {}) {
    return send(request, 'put', `/api/v1/proxy-hosts/${hostId}/rate-limit`, {
      enabled: true,
      requests_per_second: 1,
      burst_size: 1,
      ...body,
    });
  }

  function setTrusted(request: APIRequestContext, body: Record<string, unknown>) {
    return send(request, 'put', '/api/v1/system-settings', body);
  }

  /** The DNS state a GET shows for EXEMPT in one of its status arrays. */
  function stateOf(statuses: DNSEntryStatusData[] | null | undefined): DNSEntryStatusData | undefined {
    return (statuses ?? []).find((s) => s.hostname === EXEMPT);
  }

  test('a priority-allow-only domain saved in the host form is live within seconds and survives a save of another tab', async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);
    // Geo blocking stays off: the bot filter shows what priority allow lets through.
    const host = await createHost('prio-form');
    await api.setBotFilter(host.id, { customBlockedAgents: 'R3DnsBadBot' });
    await eventually(async () => (await probe(host.domain, '/', OUTSIDER, BAD_BOT)) === 403, 'the bot filter is live');
    expect(await probe(host.domain, '/', EXEMPT_IP, BAD_BOT), 'before the domain').toBe(403);

    let form = await openHostForm(page, host.id, host.domain);
    await form.switchTab('security');
    await addDomain(page, EXEMPT);
    // The form saves geo with skip_reload; the name must be looked up before
    // that branch (C5), so its state is there when the save answers.
    const geoSaved = page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === `/api/v1/proxy-hosts/${host.id}/geo`,
    );
    const saving = form.save().then(
      () => null,
      (e: unknown) => e,
    );
    const geoRes = await geoSaved;
    const stateAtSave = sql(`SELECT status FROM dns_entry_states WHERE hostname = '${EXEMPT}'`);
    const saveError = await saving;
    if (saveError) throw saveError;
    expect(geoRes.status(), 'the geo save').toBeLessThan(300);
    expect(new URL(geoRes.url()).searchParams.get('skip_reload'), 'the form skips the geo reload').toBe('true');
    expect(stateAtSave, 'the save looked the name up before it answered').toBe('ok');

    // A record with the domain alone (C1): geo itself stays off.
    expect(storedPriorityAllow(host.id)).toBe(`|${EXEMPT}`);
    const geo = await getJSON(request, `/api/v1/proxy-hosts/${host.id}/geo`);
    expect(geo.enabled).toBe(false);
    expect(stateOf(geo.allowed_hostname_status)).toMatchObject({ status: 'ok', addresses: [EXEMPT_IP] });
    await eventually(
      async () => (await probe(host.domain, '/', EXEMPT_IP, BAD_BOT)) === PASSED,
      'the domain address passes the bot filter',
      10_000,
    );
    expect(await probe(host.domain, '/', OUTSIDER, BAD_BOT)).toBe(403);

    // A save from another tab sends the record back with the domain; deleting
    // the record, as for a record without IPs, would drop it.
    form = await openHostForm(page, host.id, host.domain);
    await form.switchTab('advanced');
    await page.getByPlaceholder(/Directives go inside location/).fill('# r3-dns: saved from another tab');
    await form.save();
    const saved = await getJSON(request, `/api/v1/proxy-hosts/${host.id}`);
    expect(saved.advanced_config, 'the other tab was saved').toContain('r3-dns: saved from another tab');
    expect(storedPriorityAllow(host.id)).toBe(`|${EXEMPT}`);
    expect(await probe(host.domain, '/', EXEMPT_IP, BAD_BOT)).toBe(PASSED);
    expect(await probe(host.domain, '/', OUTSIDER, BAD_BOT)).toBe(403);
  });

  test('a URI block exception domain opens only the blocked path for its address', async ({ page, request }) => {
    test.setTimeout(90_000);
    const host = await createHost('uri');
    await setURIBlock(request, host.id, {});
    await eventually(async () => (await probe(host.domain, '/admin', OUTSIDER)) === 403, 'the URI block is live');
    expect(await probe(host.domain, '/admin', EXEMPT_IP), 'before the domain').toBe(403);

    // The host's dialog on the URI block screen saves each change at once.
    const field = await openURIBlockDialog(page, host.domain);
    await addDomain(page, EXEMPT);
    await expect(field.locator(`[data-testid="dns-entry"][data-hostname="${EXEMPT}"] [data-status="ok"]`)).toBeVisible({
      timeout: 15_000,
    });
    expect(sql(`SELECT array_to_string(exception_hostnames, ',') FROM uri_blocks WHERE proxy_host_id = '${uuid(host.id)}'`)).toBe(
      EXEMPT,
    );

    await eventually(async () => (await probe(host.domain, '/admin', EXEMPT_IP)) === PASSED, 'the domain address passes /admin');
    expect(await probe(host.domain, '/admin', OUTSIDER), 'anybody else').toBe(403);
    // Outside the blocked path nothing changes for anybody.
    expect(await probe(host.domain, '/', EXEMPT_IP)).toBe(PASSED);
    expect(await probe(host.domain, '/', OUTSIDER)).toBe(PASSED);
  });

  test('on a ForwardAuth host a domain exception still has to sign in', async ({ request }) => {
    // The verifier is the API's own /api/v1/auth/me: 200 with a session token, 401 without.
    const provider = await send(request, 'post', '/api/v1/auth-providers', {
      name: `${PREFIX}fa-${Date.now()}`,
      type: 'custom',
      provider_url: API,
      timeout_ms: 3000,
      enabled: true,
      config: {
        verify_path: '/api/v1/auth/me',
        signin_mode: 'redirect_template',
        signin_redirect: 'https://login.example.com/',
      },
    });
    const host = await createHost('fa', { auth_provider_id: provider.id });
    await setURIBlock(request, host.id, { exception_hostnames: [EXEMPT] });
    await eventually(async () => (await probe(host.domain, '/admin', OUTSIDER)) === 403, 'the URI block is live');

    // The exception lifts the URI block, not the login.
    const signIn = await probeHead(host.domain, '/admin', EXEMPT_IP);
    expect(signIn.status, 'the domain address without a login is sent to sign in').toBe(302);
    expect(signIn.headers).toMatch(/^location: https:\/\/login\.example\.com\/\r?$/im);
    const login = `Authorization: Bearer ${await api.getToken()}\r\n`;
    expect(await probe(host.domain, '/admin', EXEMPT_IP, login), 'signed in').toBe(PASSED);
    expect(await probe(host.domain, '/admin', OUTSIDER, login), 'a login opens no URI block').toBe(403);
  });

  test('a host with auth_basic in its Advanced Config applies no domain exception and says so', async ({ page, request }) => {
    test.setTimeout(90_000);
    // The login sits in location /, which the URI block exception path does not pass through.
    const host = await createHost('basic', {
      advanced_config: 'auth_basic "r3-dns";\nauth_basic_user_file /etc/nginx/r3-dns.htpasswd;',
    });
    await setURIBlock(request, host.id, { exception_ips: [STATIC_IP], exception_hostnames: [EXEMPT] });
    await eventually(async () => (await probe(host.domain, '/admin', STATIC_IP)) === PASSED, 'the exception IP passes /admin');
    expect(await probe(host.domain, '/admin', EXEMPT_IP), 'the domain is not applied on this host').toBe(403);
    expect(await probe(host.domain, '/admin', OUTSIDER)).toBe(403);

    const block = await getJSON(request, `/api/v1/proxy-hosts/${host.id}/uri-block`);
    expect(block.exception_hostnames).toEqual([EXEMPT]);
    expect(block.exception_hostnames_skipped).toBe(true);

    const field = await openURIBlockDialog(page, host.domain);
    await expect(field.getByTestId('dns-exception-skipped')).toHaveText(
      /Advanced Config asks for a login \(auth_basic or auth_request\), so its domain exceptions are not applied/,
    );
    await expect(field.locator(`[data-testid="dns-name-chip"][data-hostname="${EXEMPT}"]`)).toBeVisible();
  });

  test('a priority-allow domain passes the geo block but the WAF still blocks its SQL injection', async ({ request }) => {
    test.setTimeout(90_000);
    const host = await createHost('geo-waf');
    await api.enableWAF(host.id, { mode: 'blocking', paranoiaLevel: 1 });
    await setGeo(request, host.id, { allowed_ips: [STATIC_IP], allowed_hostnames: [EXEMPT] });
    await eventually(async () => (await probe(host.domain, '/', OUTSIDER)) === 403, 'the geo block is live');
    await eventually(async () => (await probe(host.domain, '/', EXEMPT_IP)) === PASSED, 'the domain address passes the geo block');

    // An IP entry turns the WAF off for its address; a domain does not.
    expect(await probe(host.domain, SQLI, STATIC_IP), 'the priority allow IP skips the WAF').toBe(PASSED);
    expect(await probe(host.domain, SQLI, EXEMPT_IP), 'the WAF still blocks the domain address').toBe(403);
    const row = await pollForLog(api, { host: host.domain, expectedLogType: 'modsec', timeoutMs: 20_000 });
    expect(row.client_ip, 'ModSecurity blocked the domain address').toBe(EXEMPT_IP);
  });

  test('a rate-limit exception domain is never limited while other clients get 429', async ({ request }) => {
    test.setTimeout(90_000);
    const host = await createHost('rl');
    await setRateLimit(request, host.id, { whitelist_hostnames: [EXEMPT] });
    await eventually(async () => (await burst(host.domain, OUTSIDER, 6)).includes(429), 'the rate limit is live');

    for (let round = 0; round < 3; round++) {
      expect(await burst(host.domain, EXEMPT_IP, 8), `round ${round + 1}`).toEqual(Array(8).fill(PASSED));
    }
    expect(await burst(host.domain, OUTSIDER, 6)).toContain(429);

    const limit = await getJSON(request, `/api/v1/proxy-hosts/${host.id}/rate-limit`);
    expect(limit.whitelist_hostnames).toEqual([EXEMPT]);
    expect(stateOf(limit.whitelist_hostname_status)).toMatchObject({ status: 'ok', addresses: [EXEMPT_IP] });
  });

  test("a global trusted domain passes on every host, but a ban and the list's own deny still win", async ({ request }) => {
    test.setTimeout(180_000);
    const geoHost = await createHost('t-geo');
    await setGeo(request, geoHost.id);
    const botHost = await createHost('t-bot');
    await api.setBotFilter(botHost.id, { customBlockedAgents: 'R3DnsBadBot' });
    const rlHost = await createHost('t-rl');
    await setRateLimit(request, rlHost.id);
    const allowList = await api.createAccessList({
      name: `${PREFIX}allow-${Date.now()}`,
      satisfy_any: false,
      items: [{ directive: 'allow', address: STATIC_PRIORITY_IP, kind: 'address', sort_order: 0 }],
    });
    const aclHost = await createHost('t-acl', { access_list_id: allowList.id });
    const denyList = await api.createAccessList({
      name: `${PREFIX}deny-${Date.now()}`,
      satisfy_any: false,
      items: [
        { directive: 'deny', address: EXEMPT_IP, kind: 'address', sort_order: 0 },
        { directive: 'allow', address: '100.64.32.0/24', kind: 'address', sort_order: 1 },
      ],
    });
    const denyHost = await createHost('t-deny', { access_list_id: denyList.id });

    // Before: each host turns both clients away (the deny list only the domain address).
    await eventually(async () => (await probe(geoHost.domain, '/', OUTSIDER)) === 403, 'the geo block is live');
    await eventually(async () => (await probe(botHost.domain, '/', OUTSIDER, BAD_BOT)) === 403, 'the bot filter is live');
    await eventually(async () => (await burst(rlHost.domain, OUTSIDER, 6)).includes(429), 'the rate limit is live');
    await eventually(async () => (await probe(aclHost.domain, '/', OUTSIDER)) === 403, 'the access list is live');
    await eventually(async () => (await probe(denyHost.domain, '/', EXEMPT_IP)) === 403, 'the deny list is live');
    expect(await probe(denyHost.domain, '/', OUTSIDER)).toBe(PASSED);
    expect(await probe(geoHost.domain, '/', EXEMPT_IP)).toBe(403);
    expect(await probe(botHost.domain, '/', EXEMPT_IP, BAD_BOT)).toBe(403);
    expect(await burst(rlHost.domain, EXEMPT_IP, 6)).toContain(429);
    expect(await probe(aclHost.domain, '/', EXEMPT_IP)).toBe(403);

    await setTrusted(request, { global_trusted_hostnames: [EXEMPT] });
    await eventually(async () => (await probe(geoHost.domain, '/', EXEMPT_IP)) === PASSED, 'the geo block lets it in', 30_000);
    await eventually(async () => (await probe(botHost.domain, '/', EXEMPT_IP, BAD_BOT)) === PASSED, 'the bot filter lets it in');
    await eventually(async () => (await probe(aclHost.domain, '/', EXEMPT_IP)) === PASSED, 'the access list lets it in');
    await eventually(async () => !(await burst(rlHost.domain, EXEMPT_IP, 6)).includes(429), 'the rate limit lets it be');
    expect(await burst(rlHost.domain, EXEMPT_IP, 8)).toEqual(Array(8).fill(PASSED));
    // Anybody else is turned away as before.
    expect(await probe(geoHost.domain, '/', OUTSIDER)).toBe(403);
    expect(await probe(botHost.domain, '/', OUTSIDER, BAD_BOT)).toBe(403);
    expect(await probe(aclHost.domain, '/', OUTSIDER)).toBe(403);
    expect(await burst(rlHost.domain, OUTSIDER, 6)).toContain(429);
    // The list's own deny comes before the trusted domains.
    expect(await probe(denyHost.domain, '/', EXEMPT_IP), "the list's own deny").toBe(403);
    expect(await probe(denyHost.domain, '/', OUTSIDER)).toBe(PASSED);

    // A ban beats a trusted domain (a trusted IP would not be banned).
    await send(request, 'post', '/api/v1/banned-ips', {
      ip_address: EXEMPT_IP,
      proxy_host_id: geoHost.id,
      reason: `${PREFIX}ban`,
      ban_time: 600,
    });
    await eventually(async () => (await probe(geoHost.domain, '/', EXEMPT_IP)) === 403, 'the ban wins', 30_000);
    expect(await probe(botHost.domain, '/', EXEMPT_IP, BAD_BOT), 'a host without the ban still trusts it').toBe(PASSED);
  });

  test('taking a domain out of one list closes only that list', async ({ request }) => {
    test.setTimeout(120_000);
    const prioHost = await createHost('one-prio');
    await setGeo(request, prioHost.id, { allowed_hostnames: [EXEMPT] });
    const plainHost = await createHost('one-plain');
    await setGeo(request, plainHost.id);
    await setTrusted(request, { global_trusted_hostnames: [EXEMPT] });
    await eventually(async () => (await probe(prioHost.domain, '/', EXEMPT_IP)) === PASSED, 'priority allow lets it in', 30_000);
    await eventually(async () => (await probe(plainHost.domain, '/', EXEMPT_IP)) === PASSED, 'the trusted list lets it in', 30_000);

    await setTrusted(request, { global_trusted_hostnames: [] });
    await eventually(async () => (await probe(plainHost.domain, '/', EXEMPT_IP)) === 403, 'the trusted list closes', 30_000);
    expect(await probe(prioHost.domain, '/', EXEMPT_IP), 'priority allow stays open').toBe(PASSED);

    const overview = await getJSON(request, '/api/v1/dns-entries');
    const entry = (overview.entries ?? []).find((e: { hostname: string }) => e.hostname === EXEMPT);
    expect((entry?.uses ?? []).map((u: { scope: string }) => u.scope)).toEqual([`prio:${prioHost.id}`]);
    expect(entry?.status).toBe('ok');
  });

  test('a legacy name in priority allow or trusted IPs stays ignored until it is moved to a domain', async ({ page, request }) => {
    test.setTimeout(180_000);
    // Priority allow: what an older version stored, the name in the IP list.
    const host = await createHost('legacy');
    await setGeo(request, host.id, { allowed_ips: [STATIC_PRIORITY_IP] });
    await eventually(async () => (await probe(host.domain, '/', OUTSIDER)) === 403, 'the geo block is live');
    sql(
      `UPDATE geo_restrictions SET allowed_ips = array_append(allowed_ips, '${EXEMPT}') WHERE proxy_host_id = '${uuid(host.id)}'`,
    );
    dropCached(`nginx_proxy_guard:config:geo:host:${uuid(host.id)}`);
    expect((await getJSON(request, `/api/v1/proxy-hosts/${host.id}/geo`)).allowed_ips_ignored).toEqual([EXEMPT]);

    // Saving the host from another tab keeps the entry as it is, still unused.
    let form = await openHostForm(page, host.id, host.domain);
    await form.switchTab('advanced');
    await page.getByPlaceholder(/Directives go inside location/).fill('# r3-dns: legacy entry left alone');
    await form.save();
    expect((await getJSON(request, `/api/v1/proxy-hosts/${host.id}`)).advanced_config).toContain('legacy entry left alone');
    expect(storedPriorityAllow(host.id)).toBe(`${STATIC_PRIORITY_IP},${EXEMPT}|`);
    expect(await probe(host.domain, '/', EXEMPT_IP), 'the legacy name stays unused').toBe(403);

    // Only "Move to domain" makes it a domain.
    form = await openHostForm(page, host.id, host.domain);
    await form.switchTab('security');
    const ignored = page.locator(`[data-testid="dns-ignored-entry"][data-entry="${EXEMPT}"]`);
    await expect(ignored).toBeVisible();
    await ignored.getByRole('button', { name: 'Move to domain' }).click();
    await expect(chip(page, EXEMPT)).toBeVisible();
    await expect(ignored).toHaveCount(0);
    await form.save();
    expect(storedPriorityAllow(host.id)).toBe(`${STATIC_PRIORITY_IP}|${EXEMPT}`);
    expect((await getJSON(request, `/api/v1/proxy-hosts/${host.id}/geo`)).allowed_ips_ignored ?? []).toEqual([]);
    await eventually(async () => (await probe(host.domain, '/', EXEMPT_IP)) === PASSED, 'the moved domain passes the geo block');

    // Trusted IPs: an older version kept a name as a line of the IP text.
    sql(`UPDATE system_settings SET global_trusted_ips = '${STATIC_TRUSTED_IP}' || chr(10) || '${EXEMPT}'`);
    dropCached('nginx_proxy_guard:system_settings:main');
    const settings = await getJSON(request, '/api/v1/system-settings');
    expect(settings.global_trusted_ips_ignored).toEqual([EXEMPT]);
    // A host written now is written with that line: it is left out.
    const other = await createHost('legacy-trusted');
    await setGeo(request, other.id);
    await eventually(async () => (await probe(other.domain, '/', OUTSIDER)) === 403, 'the second geo block is live');
    expect(await probe(other.domain, '/', EXEMPT_IP), 'the legacy line stays unused').toBe(403);

    await page.goto(ROUTES.settingsWafAutoBan);
    const line = page.locator(`[data-testid="dns-ignored-entry"][data-entry="${EXEMPT}"]`);
    await expect(line).toBeVisible();
    await line.getByRole('button', { name: 'Move to domain' }).click();
    await expect(chip(page, EXEMPT)).toBeVisible();
    const put = page.waitForResponse(
      (r) => r.request().method() === 'PUT' && new URL(r.url()).pathname === '/api/v1/system-settings',
    );
    await page.getByRole('button', { name: 'Save Changes' }).click();
    expect((await put).status()).toBe(200);
    const moved = await getJSON(request, '/api/v1/system-settings');
    expect(moved.global_trusted_ips).toBe(STATIC_TRUSTED_IP);
    expect(moved.global_trusted_hostnames).toEqual([EXEMPT]);
    expect(moved.global_trusted_ips_ignored ?? []).toEqual([]);
    await eventually(
      async () => (await probe(other.domain, '/', EXEMPT_IP)) === PASSED,
      'the moved trusted domain passes the geo block',
      30_000,
    );
  });

  test('viewer and operator open the four screens without a 403; a settings-only role sees counts for the other uses', async ({
    browser,
    request,
  }) => {
    test.setTimeout(180_000);
    // The name in a host's URI block exceptions, priority allow and rate limit
    // exceptions, and in the global trusted list.
    const host = await createHost('roles');
    await setURIBlock(request, host.id, { exception_hostnames: [EXEMPT] });
    await setGeo(request, host.id, { mode: 'blacklist', countries: ['AQ'], enabled: false, allowed_hostnames: [EXEMPT] });
    await setRateLimit(request, host.id, { requests_per_second: 50, burst_size: 100, whitelist_hostnames: [EXEMPT] });
    await setTrusted(request, { global_trusted_hostnames: [EXEMPT] });
    const viewer = await createRoleUser(request, headers, ROLE_VIEWER, 'viewer');
    const operator = await createRoleUser(request, headers, ROLE_OPERATOR, 'operator');

    for (const [label, user, canWrite] of [
      ['viewer', viewer, false],
      ['operator', operator, true],
    ] as const) {
      const session = await openAs(browser, user.token);
      try {
        const { page } = session;
        // ② The host's URI block dialog.
        const field = await openURIBlockDialog(page, host.domain);
        await expect(chip(page, EXEMPT)).toBeVisible();
        await expect(field.getByRole('textbox', { name: 'Domains' })).toHaveCount(canWrite ? 1 : 0);
        // ③ and ④ global screens (their domain fields show while the global default is on).
        for (const [route, path] of [
          ['/waf/global-geo', '/api/v1/settings/global-geo'],
          [ROUTES.wafGlobalRateLimit, '/api/v1/settings/global-rate-limit'],
        ]) {
          const read = page.waitForResponse((r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path);
          await page.goto(route);
          expect((await read).status(), `${label}: GET ${path}`).toBe(200);
        }
        // ③ and ④ in the host form, which only a role that may change hosts opens.
        if (canWrite) {
          const form = await openHostForm(page, host.id, host.domain);
          await form.switchTab('security');
          await expect(chip(page, EXEMPT)).toBeVisible();
          await form.switchTab('protection');
          await expect(chip(page, EXEMPT)).toBeVisible();
          await form.cancel({ expectDiscardPrompt: false });
        } else {
          await page.goto(ROUTES.proxyHosts);
        }
        await page.waitForLoadState('networkidle');
        expect(session.forbidden.filter((f) => !KNOWN_403.has(f)), `${label}: 403 answers to the screens`).toEqual([]);
      } finally {
        await session.close();
      }
    }

    // ⑤ belongs to settings. A role with settings:read only sees the trusted
    // use and counts the three host uses it may not read.
    const role = await send(request, 'post', '/api/v1/roles', {
      name: `${PREFIX}settings-reader-${Date.now()}`,
      description: 'e2e',
      permissions: ['settings:read'],
    });
    const reader = await createRoleUser(request, headers, role.id as string, 'reader');
    const limited = await request.get(`${API}/api/v1/dns-entries`, { headers: { Authorization: `Bearer ${reader.token}` } });
    expect(limited.status()).toBe(200);
    const seen = ((await limited.json()).entries ?? []).find((e: { hostname: string }) => e.hostname === EXEMPT);
    expect((seen?.uses ?? []).map((u: { kind: string }) => u.kind)).toEqual(['trusted']);
    expect(seen?.hidden_uses).toBe(3);
    const full = ((await getJSON(request, '/api/v1/dns-entries')).entries ?? []).find(
      (e: { hostname: string }) => e.hostname === EXEMPT,
    );
    expect((full?.uses ?? []).map((u: { kind: string }) => u.kind).sort()).toEqual([
      'priority_allow',
      'rate_limit',
      'trusted',
      'uri_block',
    ]);

    const session = await openAs(browser, reader.token);
    try {
      await session.page.goto('/settings/dns-entries');
      const row = session.page.locator(`[data-testid="dns-overview-row"][data-hostname="${EXEMPT}"]`);
      await expect(row).toContainText('Global trusted');
      await expect(row).toContainText('3 other place(s)');
    } finally {
      await session.close();
    }
  });

  /** The proxy-host save progress dialog's Close button. */
  function closeSaveProgress(page: Page) {
    return page.locator('.fixed.inset-0 button').filter({ hasText: /^close$/i }).click();
  }

  test('the host form shows a priority allow save over the domain limit as refused, and saves it within the limit', async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);
    const host = await createHost('prio-limit');
    await putMaxPerList(request, headers, LOW_MAX_PER_LIST);
    const geoPath = `/api/v1/proxy-hosts/${host.id}/geo`;
    const geoSaved = () =>
      page.waitForResponse((r) => r.request().method() === 'POST' && new URL(r.url()).pathname === geoPath);

    const form = await openHostForm(page, host.id, host.domain);
    await form.switchTab('security');
    await addDomain(page, EXEMPT);
    await addDomain(page, PARTNER);
    let geoRes = geoSaved();
    await form.saveButton.click();
    const refused = await geoRes;
    expect(refused.status(), 'the geo save').toBe(400);
    expect((await refused.json()).code).toBe('limit');

    // The save says what it did not save, and reports no success.
    const notSaved = page.getByRole('heading', { name: /^The host is saved, but its GeoIP restriction and priority allow were not:/ });
    await expect(notSaved).toBeVisible({ timeout: 30_000 });
    await expect(notSaved).toContainText('at most 1');
    await expect(page.getByText('Proxy host saved successfully!')).toHaveCount(0);
    // The cloud provider save, in the same row, may have made it: no entry is stored.
    expect(storedPriorityAllow(host.id), 'no priority allow entry is stored').toMatch(/^\|?$/);

    // Closing it leaves the host's form open, with the refusal under its domains.
    await closeSaveProgress(page);
    await expect(notSaved).toHaveCount(0);
    await form.expectForm();
    await expect(page.getByTestId('dns-name-input').getByRole('alert')).toContainText('Too many domains');

    // Within the limit, the same form saves the domain.
    await page.getByRole('button', { name: `Remove ${PARTNER}` }).click();
    await expect(chip(page, PARTNER)).toHaveCount(0);
    geoRes = geoSaved();
    await form.save();
    expect((await geoRes).status(), 'the geo save within the limit').toBe(200);
    await form.expectClosed();
    expect(storedPriorityAllow(host.id)).toBe(`|${EXEMPT}`);
  });

  test('a new host over the domain limit is created once, and the form says its priority allow was not saved', async ({
    page,
    request,
  }) => {
    test.setTimeout(120_000);
    await putMaxPerList(request, headers, LOW_MAX_PER_LIST);
    const domain = `${PREFIX}prio-limit-new-${Date.now()}.example.com`;
    const creates: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/proxy-hosts') creates.push(r.url());
    });

    const list = new ProxyHostListPage(page);
    const form = new ProxyHostFormPage(page);
    await list.goto();
    await list.clickAddHost();
    await form.fillDomain(domain);
    await form.fillForwardHost('127.0.0.1');
    await form.fillForwardPort(19080);
    await form.switchTab('security');
    await addDomain(page, EXEMPT);
    await addDomain(page, PARTNER);
    await form.switchTab('advanced');
    const geoRes = page.waitForResponse(
      (r) => r.request().method() === 'POST' && /^\/api\/v1\/proxy-hosts\/[0-9a-f-]{36}\/geo$/.test(new URL(r.url()).pathname),
    );
    await form.saveButton.click();
    expect((await geoRes).status(), 'the geo save').toBe(400);

    // The host exists without its priority allow: the form says so, not that it saved.
    const notSaved = page.getByRole('heading', {
      name: /^The host is created, but its GeoIP restriction and priority allow were not saved:/,
    });
    await expect(notSaved).toBeVisible({ timeout: 60_000 });
    await expect(notSaved).toContainText('at most 1');
    await expect(page.getByText('Proxy host saved successfully!')).toHaveCount(0);

    // Closing it closes the form, so there is no second Create to send.
    await closeSaveProgress(page);
    await form.expectClosed();
    const hosts = (
      await listOf(request, `${API}/api/v1/proxy-hosts?per_page=100&search=${encodeURIComponent(domain)}`, headers)
    ).filter((h) => h.domain_names?.[0] === domain);
    expect(hosts, 'hosts with the domain').toHaveLength(1);
    expect(creates, 'creates sent').toHaveLength(1);
    expect(storedPriorityAllow(hosts[0].id), 'no priority allow entry is stored').toMatch(/^\|?$/);
  });
});

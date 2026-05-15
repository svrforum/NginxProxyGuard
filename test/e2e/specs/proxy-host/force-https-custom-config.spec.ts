import { test, expect } from '@playwright/test';
import * as net from 'net';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { APIHelper } from '../../utils/api-helper';

const NGINX_HTTP_HOST = '127.0.0.1';
const NGINX_HTTP_PORT = 18080;

/**
 * Issue #129: Force HTTPS silently no-ops when the user adds a custom
 * `location /` to Advanced Config. The fix moves the HTTP→HTTPS redirect
 * from a `location / { return 301 }` block to a server-level
 * `if ($request_uri !~ "^/.well-known/acme-challenge/|^/api/v1/challenge/")
 * { return 301; }` so it survives any custom location AND preserves
 * Let's Encrypt HTTP-01 cert renewal.
 *
 * NOTE: Backend auto-disables ssl_enabled when certificate_id is missing
 * (see api/internal/nginx/manager.go ~L463). For the redirect to be
 * generated we must attach a real certificate, so this test uploads a
 * self-signed cert covering both test domains and references it on each
 * proxy host.
 */

interface RawHTTPResponse {
  status: number;
  headers: Record<string, string>;
}

// Send a raw HTTP/1.1 request to nginx with an explicit Host header (so it
// routes to the test virtual host) and parse the status line + headers.
// We bypass `request.get()` because Playwright requires a resolvable host
// for the URL, and our test domain only exists inside nginx.
function rawHTTPGet(path: string, hostHeader: string): Promise<RawHTTPResponse> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: NGINX_HTTP_HOST, port: NGINX_HTTP_PORT });
    socket.setTimeout(8000);

    let buf = '';
    let settled = false;
    const done = (v: RawHTTPResponse | Error) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (v instanceof Error) reject(v);
      else resolve(v);
    };

    socket.on('connect', () => {
      socket.write(
        `GET ${path} HTTP/1.1\r\n` +
          `Host: ${hostHeader}\r\n` +
          `Connection: close\r\n` +
          `User-Agent: npg-e2e-issue129\r\n` +
          `Accept: */*\r\n` +
          `\r\n`,
      );
    });

    socket.on('data', (chunk) => {
      buf += chunk.toString('utf8');
      // We only need the head; once we have the blank line separator we can resolve.
      const headEnd = buf.indexOf('\r\n\r\n');
      if (headEnd >= 0) {
        const head = buf.slice(0, headEnd);
        const lines = head.split('\r\n');
        const m = lines[0].match(/^HTTP\/1\.[01] (\d{3})/);
        const status = m ? Number(m[1]) : 0;
        const headers: Record<string, string> = {};
        for (const line of lines.slice(1)) {
          const idx = line.indexOf(':');
          if (idx > 0) {
            headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
          }
        }
        done({ status, headers });
      }
    });

    socket.on('end', () => done(new Error('connection closed before headers')));
    socket.on('error', (err) => done(err));
    socket.on('timeout', () => done(new Error('raw HTTP request timed out')));
  });
}

// Generate a self-signed cert covering the supplied domains. Returns
// PEM-encoded cert + key. Uses the `openssl` binary already required by
// the project's test environment.
function generateSelfSignedCert(domains: string[]): { cert: string; key: string } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'npg-e2e-cert-'));
  try {
    const keyPath = path.join(tmp, 'key.pem');
    const certPath = path.join(tmp, 'cert.pem');
    const sanList = domains.map((d) => `DNS:${d}`).join(',');
    execFileSync(
      'openssl',
      [
        'req', '-x509', '-nodes', '-newkey', 'rsa:2048',
        '-keyout', keyPath,
        '-out', certPath,
        '-days', '2',
        '-subj', `/CN=${domains[0]}`,
        '-addext', `subjectAltName=${sanList}`,
      ],
      { stdio: 'pipe' },
    );
    return {
      cert: fs.readFileSync(certPath, 'utf8'),
      key: fs.readFileSync(keyPath, 'utf8'),
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

test.describe('Issue #129: Force HTTPS with custom location /', () => {
  let apiHelper: APIHelper;
  let apiContext: import('@playwright/test').APIRequestContext;
  let token: string;
  let hostId: string;
  let hostIdNoCustom: string;
  let certificateId: string;
  const testDomain = `e2e-issue129-${Date.now()}.local`;
  const testDomainNoCustom = `e2e-issue129-nocustom-${Date.now()}.local`;

  test.beforeAll(async ({ playwright }) => {
    apiContext = await playwright.request.newContext({
      baseURL: process.env.BASE_URL || 'https://localhost:18181',
      ignoreHTTPSErrors: true,
    });
    apiHelper = new APIHelper(apiContext);
    token = await apiHelper.login();

    // Upload a self-signed cert covering BOTH test domains so the backend
    // does not auto-disable ssl_enabled when we attach this cert to each host.
    const { cert, key } = generateSelfSignedCert([testDomain, testDomainNoCustom]);
    const certResp = await apiContext.post('/api/v1/certificates/upload', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      data: {
        domain_names: [testDomain, testDomainNoCustom],
        certificate_pem: cert,
        private_key_pem: key,
      },
    });
    if (!certResp.ok()) {
      throw new Error(`certificate upload failed: ${certResp.status()} ${await certResp.text()}`);
    }
    const certBody = await certResp.json();
    certificateId = certBody.id;

    // Host A: SSL+ForceHTTPS with custom location /
    const hostA = await apiHelper.createProxyHost({
      domain_names: [testDomain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 9, // discard port — proxying yields 502, but redirect should fire first
      enabled: true,
      ssl_enabled: true,
      ssl_force_https: true,
      certificate_id: certificateId,
      advanced_config: 'location / {\n    proxy_pass http://127.0.0.1:9;\n}\n',
    });
    hostId = hostA.id;

    // Host B: SSL+ForceHTTPS without custom config (regression guard)
    const hostB = await apiHelper.createProxyHost({
      domain_names: [testDomainNoCustom],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 9,
      enabled: true,
      ssl_enabled: true,
      ssl_force_https: true,
      certificate_id: certificateId,
    });
    hostIdNoCustom = hostB.id;
  });

  test.afterAll(async () => {
    if (hostId) await apiHelper.deleteProxyHost(hostId).catch(() => undefined);
    if (hostIdNoCustom) await apiHelper.deleteProxyHost(hostIdNoCustom).catch(() => undefined);
    if (certificateId) {
      await apiContext.delete(`/api/v1/certificates/${certificateId}`, {
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => undefined);
    }
  });

  test('HTTP request to host with custom location / redirects to HTTPS (#129 main case)', async () => {
    const resp = await rawHTTPGet('/anything', testDomain);
    expect(resp.status).toBe(301);
    expect(resp.headers['location']).toMatch(/^https:\/\//);
  });

  test('ACME challenge path is NOT redirected (SSL renewal regression guard)', async () => {
    const resp = await rawHTTPGet('/.well-known/acme-challenge/test-token', testDomain);
    // 404 expected (no token file exists). Critical assertion: NOT 301.
    expect(resp.status).not.toBe(301);
  });

  test('NPG challenge path is NOT redirected', async () => {
    const resp = await rawHTTPGet('/api/v1/challenge/test', testDomain);
    expect(resp.status).not.toBe(301);
  });

  test('Force HTTPS without custom config still redirects (regression guard)', async () => {
    const resp = await rawHTTPGet('/anything', testDomainNoCustom);
    expect(resp.status).toBe(301);
    expect(resp.headers['location']).toMatch(/^https:\/\//);
  });
});

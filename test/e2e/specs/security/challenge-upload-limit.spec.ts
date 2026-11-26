import { test, expect } from '@playwright/test';
import * as net from 'net';
import { APIHelper } from '../../utils/api-helper';
import { TestDataFactory } from '../../utils/test-data-factory';
import { triggerUntil } from '../../utils/log-helper';

/**
 * #402, #404: on a host behind the challenge gate, an upload larger than the
 * global request limit was refused with the gate's 401 (logged as geo_block)
 * even for a visitor who is never challenged, although the host's own limit
 * allowed it. The gate's subrequest shares the upload's Content-Length, and
 * nginx checks it against the gate location's limit, which was the global one.
 */
const NGINX_HOST = '127.0.0.1';
const NGINX_PORT = Number(process.env.E2E_PROXY_HTTP_PORT || 18080);
const GEO_IP_GB = '81.2.69.144';
const GEO_IP_SE = '89.160.20.112';
const PRIVATE_IP = '10.0.0.5';
// Above the 100m global default, below the host's own 2g.
const UPLOAD_BYTES = 150 * 1024 * 1024;

/**
 * Send only the head of an upload and return the first status nginx answers.
 * With "Expect: 100-continue", nginx answers 100 once every check before the
 * upstream has passed and it is ready to read the body.
 */
function uploadHead(host: string, forwardedFor: string): Promise<number> {
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
        `POST /upload HTTP/1.1\r\nHost: ${host}\r\nX-Forwarded-For: ${forwardedFor}\r\n` +
          `Content-Type: application/octet-stream\r\nContent-Length: ${UPLOAD_BYTES}\r\n` +
          `Expect: 100-continue\r\n\r\n`
      );
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

test.describe('Challenge gate and the host upload limit (#402, #404)', () => {
  let api: APIHelper;
  let createdHostId: string | null;

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    createdHostId = null;
  });

  test.afterEach(async () => {
    if (createdHostId) {
      await api.deleteProxyHost(createdHostId).catch(() => {});
    }
  });

  test('lets a visitor who is not challenged upload up to the host limit', async () => {
    const host = await api.createProxyHost({
      domain_names: [TestDataFactory.generateDomain('ch-upload')],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 1,
      enabled: true,
      client_max_body_size: '2g',
    });
    createdHostId = host.id;
    const domain = host.domain_names[0];
    await api.setGeoRestriction(host.id, {
      mode: 'blacklist',
      countries: ['GB'],
      challengeMode: true,
      allowPrivateIPs: true,
    });
    // Until the reload lands, a GB visitor reaches the dead upstream (502).
    await triggerUntil({ host: domain, path: '/', xForwardedFor: GEO_IP_GB }, r => r.status !== 502, {
      describe: 'the geo challenge to take effect',
    });

    // An allowed country and a private address are never challenged.
    expect(await uploadHead(domain, GEO_IP_SE), 'allowed country').toBe(100);
    expect(await uploadHead(domain, PRIVATE_IP), 'private address').toBe(100);
  });
});

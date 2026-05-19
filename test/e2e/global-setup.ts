// Playwright global setup — runs once before any spec.
//
// Verifies that:
//   1) port 18080 (npg-test-proxy HTTP) is reachable, i.e. the e2e stack is up
//      and is the one serving 18080. A leftover container or unrelated host
//      process on 18080 would silently send requests to the wrong target.
//   2) the GeoLite2 test fixture is vendored. Specs that exercise geo
//      restrictions depend on it.
//
// Failure here aborts the run with a clear actionable error.
import { execFileSync } from 'child_process';
import { existsSync, statSync } from 'fs';
import { resolve } from 'path';

const PROXY_PORT = 18080;
const FIXTURE_PATH = resolve(__dirname, 'fixtures', 'geoip-test.mmdb');

// execFileSync avoids shell expansion (no command-injection surface) and
// swallows stderr/non-zero exits so callers can treat them as soft signals.
function runQuiet(cmd: string, args: string[]): string {
  try {
    return execFileSync(cmd, args, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'ignore'] });
  } catch {
    return '';
  }
}

function checkProxyHealthy(): { ok: boolean; reason: string } {
  // Confirm the e2e test stack is up by looking at the container name + status.
  // Avoids hand-rolling a TCP probe; lets us distinguish "stack down" from
  // "stack up but some unrelated daemon stole 18080" — both surface here.
  const ps = runQuiet('docker', [
    'ps',
    '--filter', 'name=^npg-test-proxy$',
    '--format', '{{.Names}} {{.Status}}',
  ]);
  if (!ps.trim()) {
    return {
      ok: false,
      reason: `npg-test-proxy is not running. Bring the e2e stack up:\n  sudo docker compose -f docker-compose.e2e-test.yml up -d --build\nIf a stale stack remains, tear it down first:\n  sudo docker compose -f docker-compose.e2e-test.yml down -v`,
    };
  }
  if (!/healthy|Up/.test(ps)) {
    return { ok: false, reason: `npg-test-proxy state: ${ps.trim()}\nWait for healthcheck or inspect logs:\n  docker logs npg-test-proxy --tail 50` };
  }

  // Verify port 18080 is actually responsive (host-network mode binds the port
  // directly on the host). If something else holds 18080, this fetch returns
  // the wrong content or fails outright.
  const response = runQuiet('curl', [
    '-fsS', '--max-time', '5',
    `http://127.0.0.1:${PROXY_PORT}/health`,
  ]);
  if (!response) {
    return {
      ok: false,
      reason: `Port ${PROXY_PORT} did not respond to /health. Either npg-test-proxy isn't bound to it, or an unrelated process (e.g. SeaweedFS) is holding the port.\nDiagnose with:\n  ss -ltnp 'sport = :${PROXY_PORT}'\n  docker logs npg-test-proxy --tail 50`,
    };
  }
  if (!response.includes('OK')) {
    return {
      ok: false,
      reason: `Port ${PROXY_PORT} responded but body did not include "OK" — wrong process bound to this port? body=${JSON.stringify(response.slice(0, 200))}`,
    };
  }

  return { ok: true, reason: '' };
}

function checkGeoIPFixture(): { ok: boolean; reason: string } {
  if (!existsSync(FIXTURE_PATH)) {
    return {
      ok: false,
      reason: `Missing fixture: ${FIXTURE_PATH}\nDownload it (Apache 2.0):\n  curl -fL -o ${FIXTURE_PATH} https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-Country-Test.mmdb`,
    };
  }
  // Trivial sanity check — must be non-empty.
  const size = statSync(FIXTURE_PATH).size;
  if (size < 1000) {
    return { ok: false, reason: `Fixture exists but is suspiciously small (${size} bytes): ${FIXTURE_PATH}` };
  }
  return { ok: true, reason: '' };
}

async function globalSetup(): Promise<void> {
  const checks = [
    { name: `npg-test-proxy + port ${PROXY_PORT}/health`, fn: checkProxyHealthy },
    { name: 'geoip-test.mmdb fixture', fn: checkGeoIPFixture },
  ];
  const failures: string[] = [];
  for (const c of checks) {
    const result = c.fn();
    if (!result.ok) {
      failures.push(`✗ ${c.name}\n${result.reason}`);
    } else {
      // eslint-disable-next-line no-console
      console.log(`✓ ${c.name}`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`\nE2E preflight failed:\n\n${failures.join('\n\n')}\n`);
  }
}

export default globalSetup;

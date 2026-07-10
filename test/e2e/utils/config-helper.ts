// Read generated nginx / ModSecurity config from inside the e2e proxy container.
//
// The #198 "global default + per-host inherit" feature resolves the effective
// config in the service layer (getHostConfigData) BEFORE templating, so the only
// place the resolved outcome is observable is the rendered config file. The API
// GET only returns a host's STORED fields (e.g. waf_use_global=true), never the
// resolved values — so to prove "inherit actually follows the global default" we
// must inspect the file the manager wrote.
//
// We shell out with execFileSync('docker', ...) — the harness security hook
// rejects exec() but allows execFileSync (see log-helper.ts). `docker` works
// without sudo for the test user on the e2e box.
import { execFileSync } from 'child_process';

const PROXY_CONTAINER = process.env.NPG_TEST_PROXY_CONTAINER || 'npg-test-proxy';

/** cat a file inside the proxy container; returns '' if it does not exist. */
function catInProxy(path: string): string {
  try {
    return execFileSync('docker', ['exec', PROXY_CONTAINER, 'cat', path], {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    // Missing file (e.g. WAF disabled → no per-host modsec config) → treat as empty.
    return '';
  }
}

/**
 * The per-host ModSecurity config, keyed by host UUID. Present only when WAF is
 * effectively enabled for the host (own override OR inherited-from-enabled-global).
 * Encodes mode (`SecRuleEngine On` | `DetectionOnly`), paranoia
 * (`tx.blocking_paranoia_level=N`) and anomaly threshold
 * (`tx.inbound_anomaly_score_threshold=N`).
 */
export function readHostModsecConfig(hostId: string): string {
  return catInProxy(`/etc/nginx/modsec/host_${hostId}.conf`);
}

/**
 * Grep across all rendered confs and return matching lines. Used to find a host's
 * rate-limit zone, whose name is `rate_<hostId with '-' replaced by '_'>` (nginx
 * sanitizeID). The pattern is passed as a direct grep argument (no shell), so
 * there is no interpolation risk; grep exits non-zero on no-match → caught → ''.
 */
export function grepProxyConfigs(pattern: string): string {
  try {
    return execFileSync(
      'docker',
      ['exec', PROXY_CONTAINER, 'grep', '-rhE', pattern, '/etc/nginx/conf.d/'],
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] },
    );
  } catch {
    return '';
  }
}

/** Zone name nginx uses for a host's rate limiter (mirrors sanitizeID). */
export function rateZoneName(hostId: string): string {
  return `rate_${hostId.replace(/-/g, '_')}`;
}

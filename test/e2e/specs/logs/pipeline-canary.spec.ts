// E2E verification of the active pipeline canary (Phase 1 — detection).
//
// PipelineCanary GETs an internal nginx location carrying a unique nonce
// (location = /__npg_canary on the default server), then confirms that nonce
// row reaches logs_partitioned within a deadline. A miss is localized to a
// failing stage. The two assertions here are the operator-facing contract:
//
//   1. POST /api/v1/health/canary forces one synchronous probe and, in a
//      healthy e2e stack, must return {"ok":true,"stage":""}. This is the
//      "test my logging now" button and the deterministic e2e signal that the
//      whole access-log pipeline (nginx write → file tail → DB insert) works.
//   2. GET /api/v1/health/detailed must expose the canary/flush schema under
//      log_collector — pipeline_status plus the per-stream flush counters and
//      nginx_status_reachable. These fields are the only window operators have
//      into silent failures (issues #141/#144/#145/#146 family); dropping them
//      makes future regressions invisible again.
//
// Auth mechanism: same as access-log-pipeline.spec.ts — construct APIHelper
// from the Playwright `request` fixture, log in, then pass the bearer token to
// request.get/post for the health endpoints (which live outside the helper's
// wrapper methods). No hand-rolled auth.

import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';

test.describe('Pipeline canary — healthy probe + health schema', () => {
  let api: APIHelper;

  test.beforeAll(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
    // Force one synchronous probe up front so pipeline_status is deterministically
    // populated for the schema test regardless of background-canary timing.
    const token = await api.getToken();
    await request.post('/api/v1/health/canary', {
      headers: { Authorization: `Bearer ${token}` },
    });
  });

  test('POST /api/v1/health/canary returns ok=true with empty stage', async ({ request }) => {
    const token = await api.getToken();
    const resp = await request.post('/api/v1/health/canary', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();
    expect(body.ok).toBe(true);
    expect(body.stage).toBe('');
  });

  test('GET /api/v1/health/detailed exposes canary pipeline schema', async ({ request }) => {
    const token = await api.getToken();
    const resp = await request.get('/api/v1/health/detailed', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(resp.status()).toBe(200);
    const body = await resp.json();

    expect(body.log_collector).toBeDefined();
    const lc = body.log_collector;
    // A healthy stack must report 'healthy' — the canary above ran successfully.
    expect(body.log_collector.pipeline_status).toBe('healthy');

    // Per-stream flush counters + nginx reachability are non-omitempty fields
    // on the response struct, so they must always be present.
    expect(body.log_collector).toHaveProperty('access_last_flush_seconds_ago');
    expect(body.log_collector).toHaveProperty('modsec_last_flush_seconds_ago');
    expect(body.log_collector).toHaveProperty('error_last_flush_seconds_ago');
    expect(body.log_collector).toHaveProperty('nginx_status_reachable');
    expect(lc).toHaveProperty('auto_heal_attempts');
    expect(lc).toHaveProperty('auto_heal_exhausted');
  });
});

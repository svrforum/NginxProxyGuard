// E2E verification that ModSec audit JSON survives the full pipeline:
// HTTP request → nginx + ModSec rule match → audit log emission →
// log_collector parser → DB ingestion → /api/v1/logs API.
//
// Companion to the unit-level fixture test in
// api/internal/service/log_collector_parser_test.go (TestModSecParser_FixtureSchema)
// which uses captured JSON. This spec proves the runtime path actually
// produces parseable audit JSON in a fresh e2e environment — Layer 3 of
// the ModSec capture story (Layer 1 was capture, Layer 2 was fixture parser).
//
// Field shape (verified against api/internal/model/log.go + parser + the
// list-view SELECT in api/internal/repository/log.go ~ line 661):
//   rule_id        (number, JSON-encoded *int64)
//   rule_message   (string)
//   client_ip      (string)
//   request_uri    (string, includes ?query)
//   log_type       ("modsec")
//   host           (vhost from Request.Headers["Host"])
//   status_code    (number)
//   action_taken   ("blocked" for SecRuleEngine=On + 403)
//   block_reason   ("waf" when action_taken="blocked")
//
// NOT asserted here (intentional gap, documented):
//   rule_severity, rule_data, attack_type — the list-view SELECT in log.go
//   omits these to reduce IO ("Select only columns needed for list view to
//   reduce IO (~60% less data)"). The fields ARE stored in the DB (the
//   parser populates them), so the M4.3 fixture-level test confirms parsing;
//   this spec only checks what the list endpoint returns.

import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { pollForLog, triggerRequest } from '../../utils/log-helper';
import { TestDataFactory } from '../../utils/test-data-factory';

// Allow nginx config write → `nginx -t` → reload to settle before we fire the
// probe. 800ms matches the block-reason-regression spec; 2s is overkill but
// safe for paranoia=1 modsec config which adds extra rule files.
async function waitForReload(): Promise<void> {
  await new Promise(res => setTimeout(res, 1500));
}

test.describe('WAF audit pipeline ingestion', () => {
  let api: APIHelper;

  test.beforeEach(async ({ request }) => {
    api = new APIHelper(request);
    await api.login();
  });

  test.afterEach(async () => {
    // cleanupTestHosts only deletes hosts created by this APIHelper instance,
    // so it's safe even if the test failed midway.
    await api.cleanupTestHosts();
  });

  test('SQLi probe lands in DB with parsed audit fields', async () => {
    const domain = TestDataFactory.generateDomain('waf-audit-sqli');
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      // ModSec blocks at the request phase before nginx contacts upstream, so
      // the upstream doesn't need to be reachable. Use 127.0.0.1:1 — the same
      // unreachable target the block-reason regression spec uses. nginx -t
      // accepts a literal IP without DNS resolution (a service name like
      // "whoami" fails the test-build in this host-network setup).
      forward_host: '127.0.0.1',
      forward_port: 1,
      enabled: true,
    });
    await api.enableWAF(host.id, { mode: 'blocking', paranoiaLevel: 1 });
    await waitForReload();

    // Classic SQLi via libinjection — CRS rule 942100 fires at paranoia 1.
    // Path matches the capture fixture used in TestModSecParser_FixtureSchema.
    const probeResp = triggerRequest({
      host: domain,
      path: "/?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
    });
    expect(probeResp.status, 'SQLi probe should be blocked by ModSec').toBe(403);

    const row = await pollForLog(api, {
      host: domain,
      expectedLogType: 'modsec',
      timeoutMs: 15_000,
    });

    // Core access fields: parser populates these from tx.ClientIP + tx.Request.URI.
    expect(row.client_ip, 'client_ip should be populated').toBeTruthy();
    expect(row.request_uri, 'request_uri should be populated').toBeTruthy();
    expect(row.request_uri, 'request_uri should contain query string').toContain('id=');
    expect(row.status_code, 'status_code should be 403').toBe(403);

    // ModSec-specific fields. JSON keys are flat (rule_id / rule_message)
    // per api/internal/model/log.go and the list-view SELECT.
    const ruleID = row.rule_id;
    expect(ruleID, 'rule_id should be a positive integer').toBeTruthy();
    expect(String(ruleID), 'CRS rule_id should be 6 digits').toMatch(/^\d{6}$/);

    expect(row.rule_message, 'rule_message should be populated').toBeTruthy();
    // CRS 942100 message is "SQL Injection Attack Detected via libinjection".
    expect(String(row.rule_message), 'rule_message should describe SQL injection').toMatch(/SQL Injection/i);

    // Action + block_reason for a ModSec-blocked request (SecRuleEngine On).
    expect(row.action_taken, 'action_taken should be "blocked"').toBe('blocked');
    expect(row.block_reason, 'block_reason should be "waf"').toBe('waf');
  });

  test('XSS probe also lands with parsed audit fields', async () => {
    const domain = TestDataFactory.generateDomain('waf-audit-xss');
    const host = await api.createProxyHost({
      domain_names: [domain],
      forward_scheme: 'http',
      forward_host: '127.0.0.1',
      forward_port: 1,
      enabled: true,
    });
    await api.enableWAF(host.id, { mode: 'blocking', paranoiaLevel: 1 });
    await waitForReload();

    // CRS 941100 — XSS via libinjection. Path is URL-encoded so curl passes
    // it through unchanged and ModSec sees the <script>alert(1)</script> body.
    const probeResp = triggerRequest({
      host: domain,
      path: '/?msg=%3Cscript%3Ealert(1)%3C/script%3E',
    });
    expect(probeResp.status, 'XSS probe should be blocked by ModSec').toBe(403);

    const row = await pollForLog(api, {
      host: domain,
      expectedLogType: 'modsec',
      timeoutMs: 15_000,
    });

    expect(row.client_ip, 'client_ip should be populated').toBeTruthy();
    expect(row.request_uri, 'request_uri should contain query string').toContain('msg=');
    expect(row.status_code, 'status_code should be 403').toBe(403);

    const ruleID = row.rule_id;
    expect(String(ruleID), 'CRS rule_id should be 6 digits').toMatch(/^\d{6}$/);
    expect(row.rule_message, 'rule_message should be populated').toBeTruthy();
    expect(row.action_taken, 'action_taken should be "blocked"').toBe('blocked');
    expect(row.block_reason, 'block_reason should be "waf"').toBe('waf');
  });
});

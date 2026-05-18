# Stability Hardening (P0 + P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the HTTP/HTTPS template duplication + 3-way sync manual fragility (structural debt) and add load-bearing E2E regression guards for `block_reason` propagation + ModSec audit JSON schema (silent-failure debt) — all without regressing existing characterization tests or E2E specs.

**Architecture:** 5 milestones executed directly on `main` (project uses direct-to-main workflow). M0 is pre-investigation (memo only). M1 refactors `base.conf.tmpl`/`ssl.conf.tmpl` into 3 shared partials with byte-identical characterization. M2 adds two Go sync tests. M3 adds 18-case unit grep tests + 18-case E2E specs with real nginx + log/DB ingestion verification. M4 adds a capture script + schema lockfile + parser schema test + E2E ingestion spec, plus SOP doc update.

**Tech Stack:** Go 1.26, `text/template`, Echo v4, Playwright (TypeScript), Docker Compose, jq, bash, MaxMind GeoLite2 sample DB.

**Spec:** `docs/superpowers/specs/2026-05-18-stability-hardening-design.md` (commit `27af86d`) — read for full rationale.

---

## Global File Map

| Milestone | File | Action | Responsibility |
|-----------|------|--------|----------------|
| M0 | `docs/superpowers/plans/2026-05-18-stability-hardening-M0-notes.md` | Create | Pre-investigation memo (gitignored) |
| M1 | `api/internal/nginx/testdata/proxy_host_golden/*.conf` | Create | 8 golden render files capturing pre-refactor baseline |
| M1 | `api/internal/nginx/proxy_host_template_characterization_test.go` | Modify | Add 8 golden-file cases |
| M1 | `api/internal/nginx/templates/proxy_host/_common_init.conf.tmpl` | Create | Variable init + search bot + OFC + ACME gate + error pages |
| M1 | `api/internal/nginx/templates/proxy_host/_security.conf.tmpl` | Create | Geo + WAF + AccessList + Exploit + Banned + Cloud + Bot + Filter + Rate + URI |
| M1 | `api/internal/nginx/templates/proxy_host/_challenge_endpoints.conf.tmpl` | Create | Challenge validate + api_fallback + /api/v1/challenge/ |
| M1 | `api/internal/nginx/templates/proxy_host/base.conf.tmpl` | Modify | Slim to HTTP entry + 3 `{{template}}` calls |
| M1 | `api/internal/nginx/templates/proxy_host/ssl.conf.tmpl` | Modify | Slim to HTTPS entry + SSL directives + 3 `{{template}}` calls |
| M1 | `api/internal/nginx/proxy_host_template.go` | Modify | `ParseFiles` add partials; render via `ExecuteTemplate` |
| M2 | `api/internal/database/migration_sync_test.go` | Create | Diff UPGRADE SECTION vs `upgradeSQL` |
| M2 | `api/internal/database/migrations/001_init.sql` | Modify (maybe) | Add UPGRADE SECTION marker if missing |
| M2 | `api/internal/repository/backup_sync_test.go` | Create | Reflect struct `db:` tags vs export/import SQL |
| M2 | `api/internal/model/backup.go` | Modify (maybe) | Add `db:` tags if M0 finds gaps |
| M3 | `api/internal/nginx/block_reason_regression_test.go` | Create | 18 unit grep cases |
| M3 | `test/e2e/fixtures/geoip-test.mmdb` | Create | MaxMind GeoLite2 sample (vendored) |
| M3 | `test/e2e/fixtures/geoip-test.LICENSE.md` | Create | MaxMind license attribution |
| M3 | `test/e2e/utils/log-helper.ts` | Create | `triggerRequest` + `pollForLog` |
| M3 | `test/e2e/utils/api-helper.ts` | Modify | Add `setGeoRestriction`/`setAccessList`/`setBannedIPs`/`setBotFilter`/etc. |
| M3 | `test/e2e/global-setup.ts` | Create | Pre-flight 18080 port + geoip fixture check |
| M3 | `test/e2e/playwright.config.ts` | Modify | Wire `globalSetup` |
| M3 | `docker-compose.e2e-test.yml` | Modify | Mount geoip-test.mmdb into npg-test-proxy |
| M3 | `test/e2e/specs/security/block-reason-regression.spec.ts` | Create | 18 E2E cases (parallel describe) |
| M4 | `scripts/extract-schema.jq` | Create | Recursive key+type schema extraction |
| M4 | `scripts/capture-modsec-audit.sh` | Create | E2E-based audit JSON capture + diff |
| M4 | `api/internal/service/testdata/modsec_audit_v3.0.15.json` | Create | Captured fixture |
| M4 | `api/internal/service/testdata/modsec_audit_schema.json` | Create | Schema lockfile |
| M4 | `api/internal/service/log_collector_parser_test.go` | Modify | Add `TestModSecParser_FixtureSchema` |
| M4 | `test/e2e/specs/security/waf-audit-format.spec.ts` | Create | DB ingestion verification |
| M4 | `nginx/CLAUDE.md` | Modify | Update ModSec version bump checklist |

---

## Pre-flight (run once at the start of every session)

- [ ] **Step 1: Verify clean working tree**

```bash
cd /opt/stacks/nginxproxyguard
git status
```

Expected: clean (only `docs/superpowers/plans/2026-05-16-phase-2-optimization.md` untracked is OK; ignore `.playwright-mcp/`, `test-results/`).

- [ ] **Step 2: Verify spec exists**

```bash
git log --oneline -1 docs/superpowers/specs/2026-05-18-stability-hardening-design.md
```

Expected: `27af86d docs(spec): add stability hardening design (P0+P1)`.

---

## Milestone M0 — Pre-Investigation (no code changes)

**Risk:** 🟢 None — observation only.

### Task M0.1: Inspect 001_init.sql UPGRADE SECTION format

**Files:**
- Read: `api/internal/database/migrations/001_init.sql`

- [ ] **Step 1: Locate UPGRADE SECTION**

```bash
grep -nE "UPGRADE SECTION|upgrade section" api/internal/database/migrations/001_init.sql | head -5
```

Expected: One or more matches near file end. If zero matches, the section uses a different marker — search for `-- ALTER TABLE` near file end and document the actual marker pattern.

- [ ] **Step 2: Capture the marker convention**

```bash
tail -200 api/internal/database/migrations/001_init.sql > /tmp/m0_upgrade_section.txt
wc -l /tmp/m0_upgrade_section.txt
```

Read `/tmp/m0_upgrade_section.txt` and identify:
- Start marker (e.g., `-- =========== UPGRADE SECTION ===========`)
- Per-statement comment prefix (likely `-- ALTER TABLE ...`)
- End marker (or just EOF)

- [ ] **Step 3: Record findings**

Create `docs/superpowers/plans/2026-05-18-stability-hardening-M0-notes.md`:

```markdown
# M0 Pre-investigation Notes

## M0.1 — 001_init.sql UPGRADE SECTION format

- Start marker: `<exact line found>`
- End marker: `<exact line or EOF>`
- Per-statement prefix: `<e.g., "-- " prefix on every line>`
- Multi-line statement handling: `<e.g., terminated by ";">`

Example excerpt:
```sql
-- =========== UPGRADE SECTION (documentation only) ===========
-- ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS waf_paranoia_level INT DEFAULT 1;
-- ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS waf_anomaly_threshold INT DEFAULT 5;
```

If marker missing or inconsistent: note here, M2.B.1 will add a normalized marker.
```

- [ ] **Step 4: Do NOT commit this file** (gitignored or work memo)

```bash
echo "docs/superpowers/plans/2026-05-18-stability-hardening-M0-notes.md" >> .gitignore
```

Skip if `.gitignore` already covers it; verify with `git check-ignore docs/superpowers/plans/2026-05-18-stability-hardening-M0-notes.md`.

### Task M0.2: Inspect backup struct `db:` tag coverage

**Files:**
- Read: `api/internal/model/backup.go`
- Read: `api/internal/repository/backup_export.go`
- Read: `api/internal/repository/backup_import.go`

- [ ] **Step 1: List backup struct types**

```bash
grep -nE "^type Backup[A-Z][A-Za-z]+ struct" api/internal/model/backup.go
```

Expected: multiple `type BackupProxyHost struct`, `type BackupCertificate struct`, etc. List them in the M0 notes.

- [ ] **Step 2: Check db tag coverage per struct**

```bash
awk '/^type Backup.*struct/,/^}/' api/internal/model/backup.go | grep -cE "db:\""
awk '/^type Backup.*struct/,/^}/' api/internal/model/backup.go | grep -cE "^\s+[A-Z][a-zA-Z0-9]+\s+\*?[a-zA-Z]"
```

Compare counts. If equal, all fields have `db:` tags. If `db:` count is lower, list which structs are missing.

- [ ] **Step 3: Identify the export/import function names per table**

```bash
grep -nE "^func.*export[A-Z]" api/internal/repository/backup_export.go | head -20
grep -nE "^func.*import[A-Z]" api/internal/repository/backup_import.go | head -20
```

Record the per-table function name mapping in the M0 notes (e.g., `BackupProxyHost ↔ exportProxyHosts / importProxyHosts`).

- [ ] **Step 4: Append findings to `M0-notes.md`**

```markdown
## M0.2 — Backup struct db: tag coverage

| Struct | File:Line | db: tags present? | Export func | Import func |
|--------|-----------|-------------------|-------------|-------------|
| BackupProxyHost | model/backup.go:NN | yes/no (count) | exportProxyHosts | importProxyHosts |
| BackupRedirectHost | ... | ... | ... | ... |
| BackupCertificate | ... | ... | ... | ... |
| (others) | ... | ... | ... | ... |
```

### Task M0.3: Verify MaxMind GeoLite2 test sample availability

- [ ] **Step 1: Locate vendored test mmdb candidates**

```bash
ls -la test/e2e/fixtures/ 2>/dev/null
```

If `geoip-test.mmdb` already exists, M3.C.2 fixture step becomes a no-op.

- [ ] **Step 2: Document source URL**

Append to `M0-notes.md`:

```markdown
## M0.3 — GeoLite2 test sample

Source: https://github.com/maxmind/MaxMind-DB/tree/main/test-data
Specifically: `GeoLite2-Country-Test.mmdb` (Apache 2.0 license).

If not vendored yet, M3.C.2 downloads:
  curl -L -o test/e2e/fixtures/geoip-test.mmdb \
    https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-Country-Test.mmdb

License: Apache 2.0 — record full text in test/e2e/fixtures/geoip-test.LICENSE.md.
```

### Task M0.4: Verify SeaweedFS port 18080 status

- [ ] **Step 1: Check port occupancy**

```bash
ss -ltnp 2>/dev/null | grep ":18080 " || echo "port 18080 free"
```

If `port 18080 free` → great, e2e can start cleanly. If occupied → record process name + PID in M0 notes; M3.C.2 globalSetup will gate on this.

- [ ] **Step 2: Append to M0 notes**

```markdown
## M0.4 — Port 18080 status

Status: <free | occupied by SeaweedFS PID NNNN | other>
Action: <none | document workaround>
```

**Milestone M0 complete.** No commits — memo file is local-only.

---

## Milestone M1 — Template Partial Split (A항목)

**Risk:** 🟡 Medium — refactor touches template loader and 2 large templates. Characterization tests are mandatory safety net.

### Task M1.1: Identify the template loader entry point

**Files:**
- Read: `api/internal/nginx/proxy_host_template.go`
- Read: `api/internal/nginx/manager.go` (where `GenerateConfigFull` calls render)

- [ ] **Step 1: Find current ParseFiles**

```bash
grep -nE "ParseFiles|template\.New|ExecuteTemplate|template\.Must" api/internal/nginx/proxy_host_template.go
```

Record: which function loads templates, and the file paths it reads. This is the function M1.4 will modify.

- [ ] **Step 2: Find current render calls**

```bash
grep -nE "Execute\(|ExecuteTemplate\(" api/internal/nginx/proxy_host_template.go api/internal/nginx/manager.go
```

If `tmpl.Execute(buf, data)` is used (no template name), M1.4 must switch to `tmpl.ExecuteTemplate(buf, "base.conf.tmpl", data)` and `..., "ssl.conf.tmpl", data)`.

### Task M1.2: Add 8 characterization golden files (pre-refactor baseline)

**Files:**
- Create: `api/internal/nginx/testdata/proxy_host_golden/minimal_enabled.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/ssl_force_https.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/all_security_on.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/http3_quic.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/no_ipv6.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/geo_challenge.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/exploit_userAgent.conf`
- Create: `api/internal/nginx/testdata/proxy_host_golden/uri_block_with_exception.conf`
- Modify: `api/internal/nginx/proxy_host_template_characterization_test.go`

- [ ] **Step 1: Write test cases that render and write golden files when `-update` flag is set**

Add to `proxy_host_template_characterization_test.go`:

```go
package nginx

import (
    "flag"
    "os"
    "path/filepath"
    "testing"

    "github.com/lib/pq"
    "nginx-proxy-guard/internal/model"
)

var updateGolden = flag.Bool("update", false, "update golden files instead of comparing")

type goldenCase struct {
    name string
    data ProxyHostConfigData
}

func goldenCases() []goldenCase {
    enabled := func() *model.ProxyHost {
        return &model.ProxyHost{
            ID:            "test-host-id",
            DomainNames:   pq.StringArray{"example.com"},
            ForwardScheme: "http",
            ForwardHost:   "127.0.0.1",
            ForwardPort:   8080,
            Enabled:       true,
        }
    }

    sslEnabled := func() *model.ProxyHost {
        h := enabled()
        certID := "test-cert-id"
        h.SSLEnabled = true
        h.CertificateID = &certID
        h.SSLForceHTTPS = true
        return h
    }

    return []goldenCase{
        {
            name: "minimal_enabled",
            data: ProxyHostConfigData{Host: enabled(), HTTPPort: "80", HTTPSPort: "443"},
        },
        {
            name: "ssl_force_https",
            data: ProxyHostConfigData{Host: sslEnabled(), HTTPPort: "80", HTTPSPort: "443"},
        },
        {
            name: "all_security_on",
            data: ProxyHostConfigData{
                Host: func() *model.ProxyHost {
                    h := enabled()
                    h.WAFEnabled = true
                    h.WAFMode = "blocking"
                    h.WAFParanoiaLevel = 1
                    h.BlockExploits = true
                    return h
                }(),
                HTTPPort:  "80",
                HTTPSPort: "443",
                GeoRestriction: &model.GeoRestriction{
                    Enabled:   true,
                    Mode:      "blacklist",
                    Countries: []string{"CN", "RU"},
                },
                BannedIPs: []string{"1.2.3.4"},
            },
        },
        {
            name: "http3_quic",
            data: ProxyHostConfigData{
                Host: func() *model.ProxyHost {
                    h := sslEnabled()
                    h.SSLHTTP3 = true
                    h.SSLHTTP2 = true
                    return h
                }(),
                HTTPPort:  "80",
                HTTPSPort: "443",
            },
        },
        {
            name: "no_ipv6",
            data: ProxyHostConfigData{Host: enabled(), HTTPPort: "80", HTTPSPort: "443"},
            // EnableIPv6 default false in struct; explicitly set false in Manager
        },
        {
            name: "geo_challenge",
            data: ProxyHostConfigData{
                Host:     enabled(),
                HTTPPort: "80", HTTPSPort: "443",
                GeoRestriction: &model.GeoRestriction{
                    Enabled: true, Mode: "blacklist", Countries: []string{"CN"},
                    ChallengeMode: true,
                },
            },
        },
        {
            name: "exploit_userAgent",
            data: ProxyHostConfigData{
                Host: func() *model.ProxyHost {
                    h := enabled()
                    h.BlockExploits = true
                    return h
                }(),
                HTTPPort: "80", HTTPSPort: "443",
                ExploitBlockRules: []model.ExploitBlockRule{
                    {
                        ID: "USER-AGENT-001", IDSanitized: "USER_AGENT_001",
                        Name: "Scanner UA", Category: "scanner",
                        PatternType: "user_agent", Pattern: "sqlmap",
                    },
                },
            },
        },
        {
            name: "uri_block_with_exception",
            data: ProxyHostConfigData{
                Host:     enabled(),
                HTTPPort: "80", HTTPSPort: "443",
                URIBlock: &model.URIBlock{
                    Enabled: true,
                    Rules: []model.URIBlockRule{
                        {Enabled: true, MatchType: "prefix", Pattern: "/admin", Description: "block admin"},
                    },
                    ExceptionIPs:    []string{"10.0.0.1"},
                    AllowPrivateIPs: false,
                },
            },
        },
    }
}

func TestProxyHostTemplateGolden(t *testing.T) {
    m := newTestManager(t)
    goldenDir := filepath.Join("testdata", "proxy_host_golden")
    if *updateGolden {
        if err := os.MkdirAll(goldenDir, 0755); err != nil {
            t.Fatal(err)
        }
    }

    for _, tc := range goldenCases() {
        t.Run(tc.name, func(t *testing.T) {
            ctx := t.Context()
            if err := m.GenerateConfigFull(ctx, tc.data); err != nil {
                t.Fatalf("GenerateConfigFull: %v", err)
            }
            rendered, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(tc.data.Host)))
            if err != nil {
                t.Fatalf("read rendered: %v", err)
            }
            goldenPath := filepath.Join(goldenDir, tc.name+".conf")
            if *updateGolden {
                if err := os.WriteFile(goldenPath, rendered, 0644); err != nil {
                    t.Fatalf("write golden: %v", err)
                }
                t.Logf("updated %s", goldenPath)
                return
            }
            want, err := os.ReadFile(goldenPath)
            if err != nil {
                t.Fatalf("read golden %s: %v (run with -update to create)", goldenPath, err)
            }
            if string(rendered) != string(want) {
                t.Errorf("rendered output differs from %s\n--- got\n%s\n--- want\n%s",
                    goldenPath, string(rendered), string(want))
            }
        })
    }
}
```

Note: if `newTestManager`/`ProxyHostConfigData` field names differ in current code, adapt minimally. Inspect `proxy_host_template_characterization_test.go` for the existing helper before pasting.

- [ ] **Step 2: Generate baseline goldens against current (un-refactored) templates**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/nginx/... -run TestProxyHostTemplateGolden -update -v
```

Expected: 8 golden files created in `api/internal/nginx/testdata/proxy_host_golden/`.

- [ ] **Step 3: Re-run without `-update` to confirm passing baseline**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/nginx/... -run TestProxyHostTemplateGolden -v
```

Expected: 8 PASS.

- [ ] **Step 4: Sanity check golden content**

```bash
wc -l api/internal/nginx/testdata/proxy_host_golden/*.conf
head -30 api/internal/nginx/testdata/proxy_host_golden/minimal_enabled.conf
```

Expected: each file is non-empty (hundreds of lines for security-on cases). Spot-check that `server { listen 80; ... }` block is present.

- [ ] **Step 5: Commit baseline**

```bash
git add api/internal/nginx/testdata/proxy_host_golden/ \
        api/internal/nginx/proxy_host_template_characterization_test.go
git commit -m "test(nginx): add golden-file baseline before template partial split"
```

### Task M1.3: Create `_common_init.conf.tmpl`

**Files:**
- Create: `api/internal/nginx/templates/proxy_host/_common_init.conf.tmpl`
- Read: `api/internal/nginx/templates/proxy_host/base.conf.tmpl:7-68`

- [ ] **Step 1: Extract lines 7–68 of `base.conf.tmpl` into a new partial**

The content from `base.conf.tmpl` lines 7–68 (variable initialization, search bot detection, open_file_cache, ACME/challenge bypass gate, custom error pages) verbatim, wrapped in `{{define "_common_init"}} ... {{end}}`.

```gotmpl
{{define "_common_init"}}
    # Initialize tracking variables
    set $block_reason_var "-";
    set $bot_category_var "-";
    set $geo_blocked 0;
    set $is_search_bot 0;

    # NPM-compatible variables for custom config
    set $forward_scheme {{.Host.ForwardScheme}};
    set $server "{{.Host.ForwardHost}}";
    set $port {{.Host.ForwardPort}};

    # Resolver for dynamic proxy_pass with variables
    resolver {{dnsResolver}} valid=30s;

{{if .SearchEnginesList}}
    # Search bot detection (set once, used by GeoIP, CloudProvider, BotFilter)
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_search_bot 1;
    }
{{end}}

    {{if .GlobalSettings}}{{if .GlobalSettings.OpenFileCacheEnabled}}
    # Open File Cache (from Global Settings)
    open_file_cache max={{if .GlobalSettings.OpenFileCacheMax}}{{.GlobalSettings.OpenFileCacheMax}}{{else}}10000{{end}} inactive={{if .GlobalSettings.OpenFileCacheInactive}}{{.GlobalSettings.OpenFileCacheInactive}}{{else}}60s{{end}};
    open_file_cache_valid {{if .GlobalSettings.OpenFileCacheValid}}{{.GlobalSettings.OpenFileCacheValid}}{{else}}30s{{end}};
    open_file_cache_min_uses {{if .GlobalSettings.OpenFileCacheMinUses}}{{.GlobalSettings.OpenFileCacheMinUses}}{{else}}2{{end}};
    open_file_cache_errors {{if .GlobalSettings.OpenFileCacheErrors}}on{{else}}off{{end}};
    {{end}}{{end}}

    # Skip security checks for ACME HTTP-01 Challenge
    set $skip_security_for_acme 0;
    if ($request_uri ~ "^/.well-known/acme-challenge/") {
        set $skip_security_for_acme 1;
    }
    # Also skip for challenge page to prevent redirect loops
    if ($request_uri ~ "^/api/v1/challenge/") {
        set $skip_security_for_acme 1;
    }

    # ACME HTTP-01 Challenge support (bypass all security checks)
    location /.well-known/acme-challenge/ {
        # Allow all access for certificate validation
        allow all;
        root /etc/nginx/acme-challenge;
        try_files $uri =404;
    }

    # Custom error pages for upstream errors
    error_page 502 /error_502.html;
    error_page 503 /error_503.html;
    error_page 504 /error_504.html;
    location = /error_502.html { internal; root /etc/nginx/html; try_files /502.html =502; }
    location = /error_503.html { internal; root /etc/nginx/html; try_files /503.html =503; }
    location = /error_504.html { internal; root /etc/nginx/html; try_files /504.html =504; }

    # Custom error page for security blocks (WAF, block_exploits, geo restriction, bot filter, etc.)
    error_page 403 @blocked;
    location @blocked {
        root /etc/nginx/html;
        default_type text/html;
        try_files /403.html =403;
    }
{{end}}
```

**Verification:** the partial's content (between `{{define}}` and `{{end}}`) MUST match `base.conf.tmpl:7-68` byte-for-byte except for the addition of the `{{define}}/{{end}}` wrapper. Use diff to confirm.

```bash
# After saving the partial:
sed -n '7,68p' api/internal/nginx/templates/proxy_host/base.conf.tmpl > /tmp/base_slice.txt
# Strip the define/end wrapper from the partial:
sed -n '2,$p' api/internal/nginx/templates/proxy_host/_common_init.conf.tmpl | sed '$d' > /tmp/partial_body.txt
diff /tmp/base_slice.txt /tmp/partial_body.txt
```

Expected: empty diff (or whitespace-only).

### Task M1.4: Create `_security.conf.tmpl`

**Files:**
- Create: `api/internal/nginx/templates/proxy_host/_security.conf.tmpl`
- Read: `api/internal/nginx/templates/proxy_host/base.conf.tmpl:70-648`

- [ ] **Step 1: Extract lines 70–648 verbatim, wrapped in `{{define "_security"}}/{{end}}`**

This is the largest chunk (~580 lines): GeoRestriction Direct Block + WAF + Geo Challenge Mode + AccessList + BlockExploits (4 types) + Banned IPs + Cloud IPs + BotFilter + Filter Subscription + Rate Limit + URI Block.

```gotmpl
{{define "_security"}}
<paste lines 70..648 of base.conf.tmpl verbatim>
{{end}}
```

**Verification:**

```bash
sed -n '70,648p' api/internal/nginx/templates/proxy_host/base.conf.tmpl > /tmp/base_slice.txt
sed -n '2,$p' api/internal/nginx/templates/proxy_host/_security.conf.tmpl | sed '$d' > /tmp/partial_body.txt
diff /tmp/base_slice.txt /tmp/partial_body.txt
```

Expected: empty diff.

### Task M1.5: Create `_challenge_endpoints.conf.tmpl`

**Files:**
- Create: `api/internal/nginx/templates/proxy_host/_challenge_endpoints.conf.tmpl`
- Read: `api/internal/nginx/templates/proxy_host/base.conf.tmpl:650-689`

- [ ] **Step 1: Extract lines 650–689 verbatim, wrapped in `{{define "_challenge_endpoints"}}/{{end}}`**

```gotmpl
{{define "_challenge_endpoints"}}
{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
    # Challenge validation endpoint (internal)
    location = /_challenge/validate {
        internal;
        proxy_pass http://{{apiHost}}/api/v1/challenge/validate;
        ...
    }

    location @api_fallback { ... }
    location /api/v1/challenge/ { ... }
{{end}}{{end}}
{{end}}
```

(Use exact lines 650–689 of `base.conf.tmpl` between the `{{define}}` and `{{end}}` wrapper.)

**Verification:**

```bash
sed -n '650,689p' api/internal/nginx/templates/proxy_host/base.conf.tmpl > /tmp/base_slice.txt
sed -n '2,$p' api/internal/nginx/templates/proxy_host/_challenge_endpoints.conf.tmpl | sed '$d' > /tmp/partial_body.txt
diff /tmp/base_slice.txt /tmp/partial_body.txt
```

Expected: empty diff.

### Task M1.6: Update `proxy_host_template.go` to load partials

**Files:**
- Modify: `api/internal/nginx/proxy_host_template.go`

- [ ] **Step 1: Update ParseFiles call**

Locate the template parsing block (from M1.1 Step 1). Modify `ParseFiles` to include the 3 new partials BEFORE `base.conf.tmpl` and `ssl.conf.tmpl`:

```go
// Before:
tmpl, err := template.New("base.conf.tmpl").Funcs(funcMap).ParseFiles(
    filepath.Join(templatesDir, "base.conf.tmpl"),
)

// After:
tmpl, err := template.New("proxy_host").Funcs(funcMap).ParseFiles(
    filepath.Join(templatesDir, "_common_init.conf.tmpl"),
    filepath.Join(templatesDir, "_security.conf.tmpl"),
    filepath.Join(templatesDir, "_challenge_endpoints.conf.tmpl"),
    filepath.Join(templatesDir, "base.conf.tmpl"),
    filepath.Join(templatesDir, "ssl.conf.tmpl"),
)
```

- [ ] **Step 2: Update render call to use ExecuteTemplate**

If the current code uses `tmpl.Execute(buf, data)`, change it to `tmpl.ExecuteTemplate(buf, "base.conf.tmpl", data)`. If there's a similar call for ssl, mirror it.

Locate via:

```bash
grep -nE "tmpl\.Execute|template\.Execute" api/internal/nginx/proxy_host_template.go
```

Example diff:

```go
// Before:
if err := tmpl.Execute(&buf, data); err != nil { ... }

// After:
if err := tmpl.ExecuteTemplate(&buf, "base.conf.tmpl", data); err != nil { ... }
```

If two separate templates (base and ssl) are rendered sequentially, ensure each call names the appropriate top-level template.

### Task M1.7: Slim `base.conf.tmpl` to use partials

**Files:**
- Modify: `api/internal/nginx/templates/proxy_host/base.conf.tmpl`

- [ ] **Step 1: Replace body**

Replace the entire body between `server {` (line 2) and `}` (file end before final `{{end}}`) so it becomes:

```gotmpl
{{if .Host.Enabled}}
server {
    listen {{.HTTPPort}};
{{if .EnableIPv6}}    listen [::]:{{.HTTPPort}};
{{end}}    server_name {{join .Host.DomainNames " "}};

    {{template "_common_init" .}}
    {{template "_security" .}}
    {{template "_challenge_endpoints" .}}

    # ============================================================
    # Custom config (advanced + access list + cache + headers etc.)
    # — keep any tail content that was AFTER line 689 in original
    # ============================================================
<paste original lines 690 onwards if any>
}
{{end}}
```

**Note:** `base.conf.tmpl` ends at line 691 in current code (`{{end}}` after `server {`). If lines 690-691 just contain the closing `}` and `{{end}}`, the replacement above is complete. If there's additional content (e.g., proxy_pass directives) between line 689 and 691, preserve it.

Verify:

```bash
wc -l api/internal/nginx/templates/proxy_host/base.conf.tmpl
```

Expected: significantly reduced (likely 15-25 lines).

### Task M1.8: Slim `ssl.conf.tmpl` to use partials

**Files:**
- Modify: `api/internal/nginx/templates/proxy_host/ssl.conf.tmpl`

- [ ] **Step 1: Find the corresponding sections in ssl.conf.tmpl**

```bash
grep -nE "Initialize tracking variables|Geo Restriction|WAF \(ModSecurity\)|Block common exploits|Banned IPs check|Bot Filter|Rate Limiting|URI Path Blocking|Challenge validation endpoint" api/internal/nginx/templates/proxy_host/ssl.conf.tmpl
```

This identifies the line ranges in ssl.conf.tmpl that mirror base.conf.tmpl's shared blocks.

- [ ] **Step 2: Replace body**

Keep:
- Lines 1–14 (file open, listen, http2/http3 listen, server_name) — unchanged
- SSL-specific block (ssl_certificate, ssl_protocols, ssl_ciphers, ssl_ecdh_curve, HTTP/3 ssl_early_data) — unchanged
- Variable initialization through error pages (`_common_init` equivalent in ssl) — REPLACE with `{{template "_common_init" .}}`
- All security blocks (Geo, WAF, AccessList, Exploits, Banned, Cloud, Bot, Filter, Rate, URI) — REPLACE with `{{template "_security" .}}`
- Challenge endpoints — REPLACE with `{{template "_challenge_endpoints" .}}`
- Any SSL-only tail content + `}` + `{{end}}` — unchanged

Resulting structure:

```gotmpl
{{if .Host.SSLEnabled}}
server {
    listen {{.HTTPSPort}} ssl;
{{if .EnableIPv6}}    listen [::]:{{.HTTPSPort}} ssl;
{{end}}{{if .Host.SSLHTTP2}}    http2 on;
{{end}}{{if .Host.SSLHTTP3}}    listen {{.HTTPSPort}} quic;
{{if .EnableIPv6}}    listen [::]:{{.HTTPSPort}} quic;
{{end}}    ssl_early_data on;
{{end}}    server_name {{join .Host.DomainNames " "}};

    # SSL configuration
    ssl_certificate /etc/nginx/certs/{{certPath .Host}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{certPath .Host}}/privkey.pem;
    ssl_protocols {{...}};
    ssl_prefer_server_ciphers {{...}};
    ssl_ciphers {{...}};
    ssl_ecdh_curve {{...}};

    {{template "_common_init" .}}
    {{template "_security" .}}
    {{template "_challenge_endpoints" .}}

    # ... SSL-only tail (proxy_pass with HTTPS upstream etc) ...
}
{{end}}
```

Use the original `ssl.conf.tmpl:55-65` SSL directive block verbatim (don't paraphrase — copy exactly to preserve any GlobalSettings fallback chains).

### Task M1.9: Run characterization tests against refactored templates

- [ ] **Step 1: Build api**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: success. If template parse fails (e.g., partial name typo), build will succeed but `go test` fails at template.New step.

- [ ] **Step 2: Run characterization tests**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/nginx/... -run TestProxyHostTemplateGolden -v
```

Expected: all 8 PASS. If any fail, the rendered output differs from the pre-refactor golden — inspect the diff:

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/nginx/... -run TestProxyHostTemplateGolden -v 2>&1 | tee /tmp/golden_diff.txt
less /tmp/golden_diff.txt
```

Common causes of diff:
- Whitespace at partial boundaries — adjust newlines in partial body
- Indentation drift — partials should not add/remove leading whitespace

**Do not update goldens** (`-update` flag) without confirming refactor was the cause; doing so masks regressions.

- [ ] **Step 3: Run full nginx package tests**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/nginx/... -v
```

Expected: all PASS (characterization, reload, health probe, etc.).

### Task M1.10: Verify real nginx still parses generated config

- [ ] **Step 1: Bring up dev compose**

```bash
docker compose -f docker-compose.dev.yml build api nginx
docker compose -f docker-compose.dev.yml up -d
```

- [ ] **Step 2: Run nginx -t**

```bash
docker exec npg-proxy nginx -t
```

Expected: `nginx: configuration file /etc/nginx/nginx.conf test is successful`.

If there are existing proxy hosts in the dev DB, this validates the full pipeline. If empty, manually create one through the UI or API to exercise the partial-based rendering:

```bash
# Login first to get token, then:
curl -sX POST http://localhost:8080/api/v1/proxy-hosts \
  -H "Authorization: Bearer $DEV_TOKEN" -H "Content-Type: application/json" \
  -d '{"domain_names":["smoke.test.local"],"forward_host":"whoami","forward_port":80,"forward_scheme":"http","enabled":true}'
docker exec npg-proxy nginx -t
```

### Task M1.11: Commit M1

- [ ] **Step 1: Stage and commit**

```bash
git add api/internal/nginx/templates/proxy_host/_common_init.conf.tmpl \
        api/internal/nginx/templates/proxy_host/_security.conf.tmpl \
        api/internal/nginx/templates/proxy_host/_challenge_endpoints.conf.tmpl \
        api/internal/nginx/templates/proxy_host/base.conf.tmpl \
        api/internal/nginx/templates/proxy_host/ssl.conf.tmpl \
        api/internal/nginx/proxy_host_template.go
git commit -m "refactor(nginx): extract shared security partial from base/ssl templates

base.conf.tmpl and ssl.conf.tmpl shared ~650 lines of security logic
(GeoIP, WAF, AccessList, exploit block, banned IPs, cloud blocking,
bot filter, filter subscription, rate limit, URI block, challenge
endpoints). Splitting into _common_init / _security / _challenge_endpoints
partials and including them via {{template}} eliminates the regression
vector that produced #137 and #129."
```

**Milestone M1 complete.**

---

## Milestone M2 — 3-way Sync Tests (B항목)

**Risk:** 🟢 Low — additive tests, no production code changes (except possibly adding `db:` tags or UPGRADE SECTION marker).

### Task M2.1: Normalize UPGRADE SECTION marker (if M0 found inconsistency)

**Files:**
- Modify (conditionally): `api/internal/database/migrations/001_init.sql`

- [ ] **Step 1: If M0.1 noted missing or inconsistent marker**

Add normalized marker if needed. Append at end of file (or before existing upgrade content):

```sql
-- =============================================================
-- UPGRADE SECTION (documentation only - not executed)
-- All statements below MUST also exist in migration.go upgradeSQL
-- =============================================================
-- ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS waf_paranoia_level INT DEFAULT 1;
-- (... existing upgrade statements ...)
-- =============================================================
-- END UPGRADE SECTION
-- =============================================================
```

If M0.1 found the marker is already present and consistent, skip this task entirely.

### Task M2.2: Write migration sync test (failing first if gap exists)

**Files:**
- Create: `api/internal/database/migration_sync_test.go`

- [ ] **Step 1: Write the test + parser**

```go
// api/internal/database/migration_sync_test.go
package database

import (
    "os"
    "path/filepath"
    "regexp"
    "sort"
    "strings"
    "testing"
)

func TestMigrationUpgradeSync(t *testing.T) {
    sqlPath := filepath.Join("migrations", "001_init.sql")
    sqlBytes, err := os.ReadFile(sqlPath)
    if err != nil {
        t.Fatalf("read %s: %v", sqlPath, err)
    }
    fromSQL, err := extractUpgradeSection(string(sqlBytes))
    if err != nil {
        t.Fatalf("parse UPGRADE SECTION: %v", err)
    }
    fromGo := normalizeAll(upgradeSQL)

    sort.Strings(fromSQL)
    sort.Strings(fromGo)

    sqlSet := toSet(fromSQL)
    goSet := toSet(fromGo)

    var missingFromGo, missingFromSQL []string
    for s := range sqlSet {
        if !goSet[s] {
            missingFromGo = append(missingFromGo, s)
        }
    }
    for s := range goSet {
        if !sqlSet[s] {
            missingFromSQL = append(missingFromSQL, s)
        }
    }

    if len(missingFromGo) > 0 {
        sort.Strings(missingFromGo)
        t.Errorf("Statements in 001_init.sql UPGRADE SECTION but not in upgradeSQL:\n  %s",
            strings.Join(missingFromGo, "\n  ---\n  "))
    }
    if len(missingFromSQL) > 0 {
        sort.Strings(missingFromSQL)
        t.Errorf("Statements in upgradeSQL but not documented in 001_init.sql UPGRADE SECTION:\n  %s",
            strings.Join(missingFromSQL, "\n  ---\n  "))
    }
}

var (
    startMarker = regexp.MustCompile(`(?i)^--\s*=+\s*UPGRADE SECTION`)
    endMarker   = regexp.MustCompile(`(?i)^--\s*=+\s*END UPGRADE SECTION`)
    commentSQL  = regexp.MustCompile(`^--\s*(ALTER TABLE|CREATE INDEX|CREATE OR REPLACE|DROP|UPDATE|INSERT|DO)\b`)
)

func extractUpgradeSection(content string) ([]string, error) {
    lines := strings.Split(content, "\n")
    inSection := false
    var buf []string
    for _, line := range lines {
        if !inSection {
            if startMarker.MatchString(line) {
                inSection = true
            }
            continue
        }
        if endMarker.MatchString(line) {
            break
        }
        if commentSQL.MatchString(line) {
            // strip leading "-- "
            stmt := strings.TrimPrefix(strings.TrimSpace(line), "--")
            stmt = strings.TrimSpace(stmt)
            buf = append(buf, stmt)
        } else if len(buf) > 0 && strings.HasPrefix(strings.TrimSpace(line), "--") && !strings.Contains(line, "=") {
            // continuation of previous statement (also comment-prefixed)
            cont := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "--"))
            if cont != "" {
                buf[len(buf)-1] += " " + cont
            }
        }
    }
    if !inSection {
        return nil, errStartMarkerNotFound
    }
    out := make([]string, 0, len(buf))
    for _, s := range buf {
        out = append(out, normalize(s))
    }
    return out, nil
}

var errStartMarkerNotFound = fmt.Errorf("UPGRADE SECTION start marker not found")

func normalize(s string) string {
    s = strings.TrimRight(s, ";")
    s = strings.TrimSpace(s)
    // Collapse multi-space
    s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
    // Upper-case SQL keywords (lightweight)
    keywords := []string{"alter table", "add column", "if not exists", "create index", "create or replace", "drop", "update", "insert", "do"}
    for _, kw := range keywords {
        s = strings.ReplaceAll(s, kw, strings.ToUpper(kw))
        s = strings.ReplaceAll(s, strings.Title(kw), strings.ToUpper(kw))
    }
    return s
}

func normalizeAll(ss []string) []string {
    out := make([]string, 0, len(ss))
    for _, s := range ss {
        out = append(out, normalize(s))
    }
    return out
}

func toSet(ss []string) map[string]bool {
    out := make(map[string]bool, len(ss))
    for _, s := range ss {
        out[s] = true
    }
    return out
}
```

Note: this references `upgradeSQL` from the same package (`database`). If the variable lives in `migration.go` it's accessible directly.

Also needed: import `"fmt"` for `errStartMarkerNotFound`.

- [ ] **Step 2: Run the test**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/database/... -run TestMigrationUpgradeSync -v
```

Expected outcomes:
- **PASS** if current code is already in sync (best case)
- **FAIL** with explicit list of missing statements — these are real sync gaps to fix in Task M2.3

- [ ] **Step 3: If FAIL — fix the sync gap**

For each statement listed, decide:
- "Missing from upgradeSQL" → add the statement to `migration.go`'s `upgradeSQL` array
- "Missing from 001_init.sql UPGRADE SECTION" → add the comment line to `001_init.sql`

Re-run until PASS.

- [ ] **Step 4: Commit**

```bash
git add api/internal/database/migration_sync_test.go
# Plus any 001_init.sql or migration.go fixes:
git add api/internal/database/migrations/001_init.sql api/internal/database/migration.go
git commit -m "test(migration): add upgradeSQL <-> 001_init.sql UPGRADE SECTION sync guard"
```

### Task M2.3: Write backup sync test

**Files:**
- Create: `api/internal/repository/backup_sync_test.go`
- Modify (conditionally): `api/internal/model/backup.go` (add `db:` tags if M0 found gaps)

- [ ] **Step 1: If M0.2 found db: tag gaps — add them**

For each Backup* struct field missing a `db:` tag, add the column name matching the SQL:

```go
type BackupProxyHost struct {
    ID            string         `db:"id"`
    DomainNames   pq.StringArray `db:"domain_names"`
    ForwardScheme string         `db:"forward_scheme"`
    // ... (one tag per field; consult backup_export.go SELECT for column names)
}
```

Run `go build ./...` to confirm no syntax errors.

- [ ] **Step 2: Write the test**

```go
// api/internal/repository/backup_sync_test.go
package repository

import (
    "go/ast"
    "go/parser"
    "go/token"
    "os"
    "path/filepath"
    "reflect"
    "regexp"
    "strings"
    "testing"

    "nginx-proxy-guard/internal/model"
)

type syncTarget struct {
    name        string
    structValue any
    exportFunc  string
    importFunc  string
}

var syncTargets = []syncTarget{
    {"ProxyHost", model.BackupProxyHost{}, "exportProxyHosts", "importProxyHosts"},
    {"RedirectHost", model.BackupRedirectHost{}, "exportRedirectHosts", "importRedirectHosts"},
    // Add more from M0.2 findings:
    // {"Certificate", model.BackupCertificate{}, "exportCertificates", "importCertificates"},
    // {"AccessList", model.BackupAccessList{}, "exportAccessLists", "importAccessLists"},
    // ...
}

func TestBackupExportImportSync(t *testing.T) {
    for _, tc := range syncTargets {
        t.Run(tc.name, func(t *testing.T) {
            fields := dbTagFields(tc.structValue)
            if len(fields) == 0 {
                t.Fatalf("no db: tags on %T — fix struct first", tc.structValue)
            }
            exportSQL := extractFuncBody(t, "backup_export.go", tc.exportFunc)
            importSQL := extractFuncBody(t, "backup_import.go", tc.importFunc)

            for _, col := range fields {
                if !containsColumn(exportSQL, col) {
                    t.Errorf("[%s] column %q in struct but missing from backup_export.go:%s",
                        tc.name, col, tc.exportFunc)
                }
                if !containsColumn(importSQL, col) {
                    t.Errorf("[%s] column %q in struct but missing from backup_import.go:%s",
                        tc.name, col, tc.importFunc)
                }
            }
        })
    }
}

func dbTagFields(v any) []string {
    t := reflect.TypeOf(v)
    var out []string
    for i := 0; i < t.NumField(); i++ {
        tag := t.Field(i).Tag.Get("db")
        if tag == "" || tag == "-" {
            continue
        }
        out = append(out, tag)
    }
    return out
}

// extractFuncBody parses the given Go file and returns the source text of
// the named function's body. Used to grep for column names within a specific
// function's SQL string literals.
func extractFuncBody(t *testing.T, fileName, funcName string) string {
    t.Helper()
    path := filepath.Join(".", fileName)
    src, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("read %s: %v", path, err)
    }
    fset := token.NewFileSet()
    f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
    if err != nil {
        t.Fatalf("parse %s: %v", path, err)
    }
    for _, decl := range f.Decls {
        fn, ok := decl.(*ast.FuncDecl)
        if !ok || fn.Name.Name != funcName {
            continue
        }
        if fn.Body == nil {
            continue
        }
        start := fset.Position(fn.Body.Pos()).Offset
        end := fset.Position(fn.Body.End()).Offset
        return string(src[start:end])
    }
    t.Fatalf("function %s not found in %s", funcName, path)
    return ""
}

func containsColumn(haystack, col string) bool {
    // Match column name as a word — guards against substring false positives
    // (e.g., "id" matching "host_id"). Surround with non-word boundary check.
    re := regexp.MustCompile(`\b` + regexp.QuoteMeta(col) + `\b`)
    return re.MatchString(strings.ToLower(haystack))
}
```

- [ ] **Step 3: Run the test**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/repository/... -run TestBackupExportImportSync -v
```

Expected:
- **PASS** if struct fields and SQL are in sync
- **FAIL** with explicit list of missing column names — fix by adding the column to the corresponding SELECT/INSERT SQL

- [ ] **Step 4: If FAIL, fix the actual gap**

For each missing column, locate the export/import function and add the column to the SQL literal. Re-run until PASS.

- [ ] **Step 5: Commit**

```bash
git add api/internal/repository/backup_sync_test.go
# Plus any model/backup.go or backup_export.go / backup_import.go fixes:
git add api/internal/model/backup.go \
        api/internal/repository/backup_export.go \
        api/internal/repository/backup_import.go
git commit -m "test(backup): add struct <-> export/import SQL sync guard"
```

**Milestone M2 complete.**

---

## Milestone M3 — Block Reason Regression Guards (C항목)

**Risk:** 🟡 Medium — adds new test infrastructure (Playwright global-setup, geoip fixture, log-helper). Bugs here only affect tests, not production.

### Task M3.1: Write unit grep test infrastructure

**Files:**
- Create: `api/internal/nginx/block_reason_regression_test.go`

- [ ] **Step 1: Write helpers + minimalEnabledHost + 18 test cases**

```go
// api/internal/nginx/block_reason_regression_test.go
package nginx

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/lib/pq"
    "nginx-proxy-guard/internal/model"
)

func minimalEnabledHost() ProxyHostConfigData {
    return ProxyHostConfigData{
        Host: &model.ProxyHost{
            ID:            "blockreason-test",
            DomainNames:   pq.StringArray{"example.com"},
            ForwardScheme: "http",
            ForwardHost:   "127.0.0.1",
            ForwardPort:   8080,
            Enabled:       true,
        },
        HTTPPort:  "80",
        HTTPSPort: "443",
    }
}

func renderProxyHost(t *testing.T, data ProxyHostConfigData) string {
    t.Helper()
    m := newTestManager(t)
    if err := m.GenerateConfigFull(t.Context(), data); err != nil {
        t.Fatalf("GenerateConfigFull: %v", err)
    }
    rendered, err := os.ReadFile(filepath.Join(m.configPath, GetConfigFilename(data.Host)))
    if err != nil {
        t.Fatalf("read rendered: %v", err)
    }
    return string(rendered)
}

func assertBlockReason(t *testing.T, output, reason string) {
    t.Helper()
    needle := fmt.Sprintf(`set $block_reason_var "%s"`, reason)
    if !strings.Contains(output, needle) {
        t.Errorf("expected %q in rendered config, but missing", needle)
    }
}

func assertReturnStatus(t *testing.T, output string, status int) {
    t.Helper()
    needle := fmt.Sprintf("return %d", status)
    if !strings.Contains(output, needle) {
        t.Errorf("expected %q in rendered config, but missing", needle)
    }
}

// --- Data builders (composable) ---

type mutate func(d ProxyHostConfigData) ProxyHostConfigData

func compose(ms ...mutate) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        for _, m := range ms {
            d = m(d)
        }
        return d
    }
}

func withGeoBlock(mode, country string) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.GeoRestriction = &model.GeoRestriction{
            Enabled: true, Mode: mode, Countries: []string{country},
        }
        return d
    }
}

func withGeoChallenge(country string) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.GeoRestriction = &model.GeoRestriction{
            Enabled: true, Mode: "blacklist", Countries: []string{country},
            ChallengeMode: true,
        }
        return d
    }
}

func withAccessListDeny(ip string) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.AccessList = &model.AccessList{
            Name: "test-list",
            Items: []model.AccessListItem{
                {Directive: "deny", Address: ip},
            },
        }
        return d
    }
}

func withExploit(patternType, pattern string) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.Host.BlockExploits = true
        sanitized := strings.NewReplacer("-", "_", ".", "_").Replace(patternType + "_" + pattern)
        d.ExploitBlockRules = append(d.ExploitBlockRules, model.ExploitBlockRule{
            ID:          strings.ToUpper(patternType) + "-001",
            IDSanitized: sanitized,
            Name:        patternType + " rule",
            Category:    "test",
            PatternType: patternType,
            Pattern:     pattern,
        })
        return d
    }
}

func withBannedIP(ip string) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.BannedIPs = append(d.BannedIPs, ip)
        return d
    }
}

func withFilterSubscription() mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.UseFilterSubscription = true
        return d
    }
}

func withCloudProviderBlock() mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.BlockedCloudIPRanges = []string{"104.16.0.0/13"} // CF sample
        return d
    }
}

func withCloudProviderChallenge() mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.BlockedCloudIPRanges = []string{"104.16.0.0/13"}
        d.CloudProviderChallengeMode = true
        return d
    }
}

func withBotFilter(opts model.BotFilter) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        opts.Enabled = true
        d.BotFilter = &opts
        // Provide lists so the template emits regex branches
        if opts.BlockBadBots {
            d.BadBotsList = []string{"AhrefsBot", "SemrushBot"}
        }
        if opts.BlockAIBots {
            d.AIBotsList = []string{"GPTBot", "Claude-Web"}
        }
        if opts.BlockSuspiciousClients {
            d.SuspiciousClientsList = []string{"curl", "wget"}
        }
        return d
    }
}

func withURIBlock(prefix string) mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.URIBlock = &model.URIBlock{
            Enabled: true,
            Rules: []model.URIBlockRule{
                {Enabled: true, MatchType: "prefix", Pattern: prefix, Description: "test"},
            },
        }
        return d
    }
}

func withRateLimit() mutate {
    return func(d ProxyHostConfigData) ProxyHostConfigData {
        d.RateLimit = &model.RateLimit{Enabled: true, BurstSize: 1, LimitResponse: 429}
        return d
    }
}

// --- 18 cases ---

func TestBlockReasonRegression(t *testing.T) {
    cases := []struct {
        name   string
        apply  mutate
        reason string
        status int
        extra  []string
    }{
        {"geo_block_blacklist", withGeoBlock("blacklist", "CN"), "geo_block", 403, nil},
        {"geo_block_whitelist", withGeoBlock("whitelist", "KR"), "geo_block", 403, nil},
        {"geo_challenge", withGeoChallenge("CN"), "geo_block", 0, nil},
        {"access_denied", withAccessListDeny("1.2.3.4"), "access_denied", 0, nil},
        {"exploit_query_string", withExploit("query_string", "union.*select"), "exploit_block", 403, nil},
        {"exploit_request_uri", withExploit("request_uri", "/etc/passwd"), "exploit_block", 403, nil},
        {"exploit_user_agent_scanner", withExploit("user_agent", "sqlmap"), "exploit_block", 403,
            []string{`set $bot_category_var "scanner"`}},
        {"exploit_request_method", withExploit("request_method", "TRACE"), "exploit_block", 405, nil},
        {"banned_ip_manual", withBannedIP("1.2.3.4"), "banned_ip", 403, nil},
        {"banned_ip_filter_subscription",
            compose(withBannedIP("1.2.3.4"), withFilterSubscription()),
            "filter_subscription", 403, nil},
        {"cloud_provider_block", withCloudProviderBlock(), "cloud_provider_block", 403, nil},
        {"cloud_provider_challenge", withCloudProviderChallenge(), "cloud_provider_challenge", 418, nil},
        {"bot_filter_bad_bot",
            withBotFilter(model.BotFilter{BlockBadBots: true}),
            "bot_filter", 403, []string{`set $bot_category_var "bad_bot"`}},
        {"bot_filter_ai_bot",
            withBotFilter(model.BotFilter{BlockAIBots: true}),
            "bot_filter", 403, []string{`set $bot_category_var "ai_bot"`}},
        {"bot_filter_suspicious",
            withBotFilter(model.BotFilter{BlockSuspiciousClients: true}),
            "bot_filter", 403, []string{`set $bot_category_var "suspicious"`}},
        {"bot_filter_custom",
            withBotFilter(model.BotFilter{CustomBlockedAgents: "MyBot"}),
            "bot_filter", 403, []string{`set $bot_category_var "custom"`}},
        {"filter_subscription_ua",
            withFilterSubscription(),
            "filter_subscription", 403, nil},
        {"uri_block_prefix", withURIBlock("/admin"), "uri_block", 403, nil},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            data := tc.apply(minimalEnabledHost())
            out := renderProxyHost(t, data)
            assertBlockReason(t, out, tc.reason)
            if tc.status != 0 {
                assertReturnStatus(t, out, tc.status)
            }
            for _, needle := range tc.extra {
                if !strings.Contains(out, needle) {
                    t.Errorf("expected %q in rendered config, but missing", needle)
                }
            }
        })
    }
}
```

Note: field names like `BannedIPs`, `BlockedCloudIPRanges`, `UseFilterSubscription`, `BadBotsList`, etc. must match `ProxyHostConfigData` and `model.BotFilter` actual field names. Inspect via:

```bash
grep -nE "^type ProxyHostConfigData struct" -A 50 api/internal/nginx/*.go
grep -nE "^type BotFilter struct" -A 30 api/internal/model/*.go
```

Adjust the builders to match. Also confirm `model.URIBlockRule`, `model.AccessListItem`, `model.ExploitBlockRule` field names.

- [ ] **Step 2: Run the test**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/nginx/... -run TestBlockReasonRegression -v
```

Expected: 18 PASS. If any FAIL with `expected ... missing`, the underlying template may have a genuine block_reason gap — investigate and fix in the template before claiming the test correct.

- [ ] **Step 3: Commit**

```bash
git add api/internal/nginx/block_reason_regression_test.go
git commit -m "test(nginx): add block_reason variable unit-level regression guard

Covers 18 security layer activation paths and asserts the rendered
template emits the expected set \$block_reason_var, return status,
and bot_category variable. Fast feedback for refactors of the
shared _security partial."
```

### Task M3.2: Vendor MaxMind GeoLite2 test sample

**Files:**
- Create: `test/e2e/fixtures/geoip-test.mmdb`
- Create: `test/e2e/fixtures/geoip-test.LICENSE.md`

- [ ] **Step 1: Skip if M0.3 confirmed already vendored**

```bash
test -f test/e2e/fixtures/geoip-test.mmdb && echo "already vendored" || echo "need to fetch"
```

- [ ] **Step 2: Download the test sample**

```bash
mkdir -p test/e2e/fixtures
curl -fL -o test/e2e/fixtures/geoip-test.mmdb \
  https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-Country-Test.mmdb
file test/e2e/fixtures/geoip-test.mmdb
ls -la test/e2e/fixtures/geoip-test.mmdb
```

Expected: file is `data` (mmdb is binary), several hundred KB.

- [ ] **Step 3: Add license**

Create `test/e2e/fixtures/geoip-test.LICENSE.md`:

```markdown
# GeoLite2-Country-Test.mmdb License

Source: https://github.com/maxmind/MaxMind-DB/tree/main/test-data
License: Apache License 2.0

This is a synthetic test database used solely for E2E test validation.
It is NOT the production GeoLite2 database. For production, use the
official MaxMind distribution at https://www.maxmind.com.

Copyright (c) MaxMind, Inc. — see full Apache 2.0 license at
https://github.com/maxmind/MaxMind-DB/blob/main/LICENSE
```

- [ ] **Step 4: Commit**

```bash
git add test/e2e/fixtures/geoip-test.mmdb test/e2e/fixtures/geoip-test.LICENSE.md
git commit -m "test(e2e): vendor MaxMind GeoLite2 test database for block_reason E2E

Synthetic sample DB (Apache 2.0) used by block-reason-regression spec
to evaluate geo restriction layers without depending on the host's
MaxMind subscription."
```

### Task M3.3: Mount geoip fixture into npg-test-proxy

**Files:**
- Modify: `docker-compose.e2e-test.yml`

- [ ] **Step 1: Find the nginx service definition**

```bash
grep -nE "^  nginx:|GeoIP|geoip" docker-compose.e2e-test.yml
```

- [ ] **Step 2: Add volume mount under nginx service**

Locate the `nginx:` (likely `npg-test-proxy`) service block and add to its `volumes:` list:

```yaml
    volumes:
      # ... existing mounts ...
      - ./test/e2e/fixtures/geoip-test.mmdb:/etc/nginx/geoip/GeoLite2-Country.mmdb:ro
      - ./test/e2e/fixtures/geoip-test.mmdb:/etc/nginx/geoip/GeoLite2-ASN.mmdb:ro
```

The mmdb path `/etc/nginx/geoip/GeoLite2-Country.mmdb` must match what `geoip-update.sh` or `geoip.conf` expects. Inspect:

```bash
grep -nE "geoip2|GeoLite2" nginx/conf.d/geoip.conf nginx/conf.d/geoip-disabled.conf nginx/scripts/geoip-update.sh 2>/dev/null
```

Adjust the target paths to match nginx's expected location (likely `/etc/nginx/geoip/`).

- [ ] **Step 3: Restart e2e environment and verify GeoIP is active**

```bash
sudo docker compose -f docker-compose.e2e-test.yml down -v
sudo docker compose -f docker-compose.e2e-test.yml up -d --build
sleep 10
docker exec npg-test-proxy ls -la /etc/nginx/geoip/
```

Expected: `GeoLite2-Country.mmdb` present, non-zero size.

- [ ] **Step 4: Verify nginx parses GeoIP module**

```bash
docker exec npg-test-proxy nginx -T 2>&1 | grep -i geoip2 | head -5
```

Expected: `geoip2 /etc/nginx/geoip/GeoLite2-Country.mmdb` directive present.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.e2e-test.yml
git commit -m "test(e2e): mount GeoLite2 test mmdb into npg-test-proxy

Enables geo restriction E2E cases by satisfying the geoip2 module's
mmdb requirement in the e2e environment."
```

### Task M3.4: Add Playwright global setup with 18080 port guard

**Files:**
- Create: `test/e2e/global-setup.ts`
- Modify: `test/e2e/playwright.config.ts`

- [ ] **Step 1: Write global-setup.ts**

```ts
// test/e2e/global-setup.ts
import { exec } from 'child_process';
import { existsSync } from 'fs';
import { promisify } from 'util';
import { resolve } from 'path';

const execAsync = promisify(exec);

async function checkPortFree(port: number): Promise<boolean> {
  try {
    const { stdout } = await execAsync(`ss -ltn 'sport = :${port}'`);
    return !stdout.includes(`:${port} `);
  } catch {
    return true; // ss command failed; assume free
  }
}

async function globalSetup() {
  // Guard 1: required port for npg-test-proxy
  const PROXY_PORT = 18080;
  const free = await checkPortFree(PROXY_PORT);
  if (!free) {
    throw new Error(
      `Port ${PROXY_PORT} is occupied — e2e cannot start.\n` +
      `Most commonly SeaweedFS. Workaround:\n` +
      `  - sudo systemctl stop seaweedfs   (or whatever holds it)\n` +
      `  - or edit docker-compose.e2e-test.yml to use a different port.`
    );
  }

  // Guard 2: GeoLite2 test fixture must be vendored
  const geoipFixture = resolve(__dirname, 'fixtures', 'geoip-test.mmdb');
  if (!existsSync(geoipFixture)) {
    throw new Error(
      `Missing fixture: ${geoipFixture}\n` +
      `Run M3.2 of the stability hardening plan to vendor it.`
    );
  }

  // eslint-disable-next-line no-console
  console.log('✓ Pre-flight: port 18080 free, geoip-test.mmdb present');
}

export default globalSetup;
```

- [ ] **Step 2: Wire into playwright.config.ts**

```bash
grep -nE "globalSetup|export default" test/e2e/playwright.config.ts
```

Add to the config object:

```ts
export default defineConfig({
  // ... existing config ...
  globalSetup: require.resolve('./global-setup.ts'),
  // ... rest ...
});
```

- [ ] **Step 3: Run a smoke test to verify globalSetup runs**

```bash
cd test/e2e
npx playwright test specs/auth/ --reporter=line | head -20
```

Expected: "✓ Pre-flight: port 18080 free, geoip-test.mmdb present" appears once, before any specs run. If port is occupied or fixture missing, you'll get the explicit error message.

- [ ] **Step 4: Commit**

```bash
cd /opt/stacks/nginxproxyguard
git add test/e2e/global-setup.ts test/e2e/playwright.config.ts
git commit -m "test(e2e): add global-setup with port 18080 + geoip fixture guard"
```

### Task M3.5: Write `log-helper.ts` (triggerRequest + pollForLog)

**Files:**
- Create: `test/e2e/utils/log-helper.ts`

- [ ] **Step 1: Write helpers**

```ts
// test/e2e/utils/log-helper.ts
import { APIHelper } from './api-helper';

const PROXY_PORT_DEFAULT = 18080;

export interface TriggerOptions {
  host: string;
  path?: string;
  method?: string;
  ua?: string;
  spoofIP?: string;        // X-Forwarded-For; nginx's set_real_ip_from trusts private ranges
  proxyPort?: number;
  extraHeaders?: Record<string, string>;
}

export interface TriggerResponse {
  status: number;
  body: string;
  headers: Record<string, string>;
}

export async function triggerRequest(opts: TriggerOptions): Promise<TriggerResponse> {
  const port = opts.proxyPort ?? PROXY_PORT_DEFAULT;
  const url = `http://127.0.0.1:${port}${opts.path ?? '/'}`;
  const headers: Record<string, string> = {
    'Host': opts.host,
    ...opts.extraHeaders,
  };
  if (opts.spoofIP) headers['X-Forwarded-For'] = opts.spoofIP;
  if (opts.ua) headers['User-Agent'] = opts.ua;

  const resp = await fetch(url, {
    method: opts.method ?? 'GET',
    headers,
    redirect: 'manual',
  });
  const body = await resp.text();
  const hdrs: Record<string, string> = {};
  resp.headers.forEach((v, k) => { hdrs[k] = v; });
  return { status: resp.status, body, headers: hdrs };
}

export interface LogRow {
  id: string;
  host_id: string;
  status: number;
  block_reason: string | null;
  bot_category: string | null;
  exploit_rule: string | null;
  log_type: string;
  geo_country: string | null;
  client_ip: string;
  uri: string;
  rule_id?: string | null;
  severity?: string | null;
  message?: string | null;
  matched_data?: string | null;
}

export interface PollCriteria {
  host_id: string;
  expected_block_reason?: string;
  expected_status?: number;
  expected_log_type?: string;
  timeoutMs?: number;
  intervalMs?: number;
}

export async function pollForLog(api: APIHelper, criteria: PollCriteria): Promise<LogRow> {
  const timeout = criteria.timeoutMs ?? 10_000;
  const interval = criteria.intervalMs ?? 250;
  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    const logs: LogRow[] = await api.getLogs({
      host_id: criteria.host_id,
      limit: 50,
    });
    const match = logs.find(l =>
      (!criteria.expected_block_reason || l.block_reason === criteria.expected_block_reason) &&
      (!criteria.expected_status || l.status === criteria.expected_status) &&
      (!criteria.expected_log_type || l.log_type === criteria.expected_log_type)
    );
    if (match) return match;
    await new Promise(r => setTimeout(r, interval));
  }
  throw new Error(`pollForLog timeout (${timeout}ms): criteria=${JSON.stringify(criteria)}`);
}
```

- [ ] **Step 2: Commit (api-helper additions in next task)**

Don't commit yet — `api-helper.ts` doesn't have `getLogs` yet. Continue to M3.6.

### Task M3.6: Extend `api-helper.ts` with security setting helpers + getLogs

**Files:**
- Modify: `test/e2e/utils/api-helper.ts`

- [ ] **Step 1: Inspect current api-helper.ts structure**

```bash
grep -nE "^\s+async [a-zA-Z]+\(" test/e2e/utils/api-helper.ts | head -20
```

Identify the method format (likely `async createProxyHost(...)`, `async deleteProxyHost(...)`, etc.).

- [ ] **Step 2: Add helper methods**

Append to the `APIHelper` class (inside the class body, alongside existing methods):

```ts
  async getLogs(params: { host_id?: string; limit?: number }): Promise<any[]> {
    return this.withRetry(async () => {
      const search = new URLSearchParams();
      if (params.host_id) search.set('host_id', params.host_id);
      if (params.limit) search.set('limit', String(params.limit));
      const resp = await this.request.get(`/api/v1/logs?${search.toString()}`, {
        headers: this.getHeaders(),
      });
      if (!resp.ok()) throw new Error(`getLogs ${resp.status()}: ${await resp.text()}`);
      const body = await resp.json();
      return body.data ?? body.logs ?? body;  // adapt to actual response shape
    }, 'getLogs');
  }

  async setGeoRestriction(hostId: string, geo: {
    enabled: boolean;
    mode: 'whitelist' | 'blacklist';
    countries: string[];
    allow_private_ips?: boolean;
    allow_search_bots?: boolean;
    challenge_mode?: boolean;
    allowed_ips?: string[];
  }): Promise<void> {
    await this.withRetry(async () => {
      const resp = await this.request.put(`/api/v1/proxy-hosts/${hostId}/geo-restriction`, {
        headers: this.getHeaders(),
        data: geo,
      });
      if (!resp.ok()) throw new Error(`setGeoRestriction ${resp.status()}: ${await resp.text()}`);
    }, 'setGeoRestriction');
  }

  async setAccessList(hostId: string, items: Array<{ directive: 'allow' | 'deny'; address: string }>): Promise<void> {
    await this.withRetry(async () => {
      // Create access list, then attach
      const create = await this.request.post('/api/v1/access-lists', {
        headers: this.getHeaders(),
        data: { name: `e2e-${hostId.slice(0, 8)}`, satisfy_any: false, items },
      });
      if (!create.ok()) throw new Error(`createAccessList ${create.status()}: ${await create.text()}`);
      const al = await create.json();
      this.createdAccessListIds.push(al.id);

      const attach = await this.request.put(`/api/v1/proxy-hosts/${hostId}`, {
        headers: this.getHeaders(),
        data: { access_list_id: al.id },
      });
      if (!attach.ok()) throw new Error(`attachAccessList ${attach.status()}: ${await attach.text()}`);
    }, 'setAccessList');
  }

  async setBannedIPs(hostId: string, ips: string[]): Promise<void> {
    await this.withRetry(async () => {
      for (const ip of ips) {
        const resp = await this.request.post('/api/v1/banned-ips', {
          headers: this.getHeaders(),
          data: { ip_address: ip, proxy_host_id: hostId, reason: 'e2e' },
        });
        if (!resp.ok() && resp.status() !== 409) {
          throw new Error(`banIP ${resp.status()}: ${await resp.text()}`);
        }
      }
    }, 'setBannedIPs');
  }

  async setExploitRule(hostId: string, rule: {
    pattern_type: 'query_string' | 'request_uri' | 'user_agent' | 'request_method';
    pattern: string;
    category: string;
    name: string;
  }): Promise<void> {
    await this.withRetry(async () => {
      // Enable block_exploits on host
      const upd = await this.request.put(`/api/v1/proxy-hosts/${hostId}`, {
        headers: this.getHeaders(),
        data: { block_exploits: true },
      });
      if (!upd.ok()) throw new Error(`enableBlockExploits ${upd.status()}`);

      // Create exploit rule
      const create = await this.request.post('/api/v1/exploit-rules', {
        headers: this.getHeaders(),
        data: { ...rule, enabled: true, proxy_host_id: hostId },
      });
      if (!create.ok()) throw new Error(`createExploitRule ${create.status()}: ${await create.text()}`);
    }, 'setExploitRule');
  }

  async setBotFilter(hostId: string, opts: {
    block_bad_bots?: boolean;
    block_ai_bots?: boolean;
    block_suspicious_clients?: boolean;
    custom_blocked_agents?: string;
  }): Promise<void> {
    await this.withRetry(async () => {
      const resp = await this.request.put(`/api/v1/proxy-hosts/${hostId}/bot-filter`, {
        headers: this.getHeaders(),
        data: { enabled: true, ...opts },
      });
      if (!resp.ok()) throw new Error(`setBotFilter ${resp.status()}: ${await resp.text()}`);
    }, 'setBotFilter');
  }

  async setURIBlock(hostId: string, prefix: string): Promise<void> {
    await this.withRetry(async () => {
      const resp = await this.request.put(`/api/v1/proxy-hosts/${hostId}/uri-block`, {
        headers: this.getHeaders(),
        data: {
          enabled: true,
          rules: [{ enabled: true, match_type: 'prefix', pattern: prefix, description: 'e2e' }],
        },
      });
      if (!resp.ok()) throw new Error(`setURIBlock ${resp.status()}: ${await resp.text()}`);
    }, 'setURIBlock');
  }

  async setRateLimit(hostId: string, rps: number, burst: number): Promise<void> {
    await this.withRetry(async () => {
      const resp = await this.request.put(`/api/v1/proxy-hosts/${hostId}/rate-limit`, {
        headers: this.getHeaders(),
        data: { enabled: true, requests_per_second: rps, burst_size: burst, limit_response: 429 },
      });
      if (!resp.ok()) throw new Error(`setRateLimit ${resp.status()}: ${await resp.text()}`);
    }, 'setRateLimit');
  }

  async enableWAF(hostId: string, opts?: { mode?: 'blocking' | 'detection'; paranoia?: 1 | 2 | 3 | 4 }): Promise<void> {
    await this.withRetry(async () => {
      const resp = await this.request.put(`/api/v1/proxy-hosts/${hostId}`, {
        headers: this.getHeaders(),
        data: {
          waf_enabled: true,
          waf_mode: opts?.mode ?? 'blocking',
          waf_paranoia_level: opts?.paranoia ?? 1,
        },
      });
      if (!resp.ok()) throw new Error(`enableWAF ${resp.status()}: ${await resp.text()}`);
    }, 'enableWAF');
  }
```

**Important:** the exact endpoint paths above (`/geo-restriction`, `/bot-filter`, `/uri-block`, `/rate-limit`) MUST match the routes registered in `api/internal/bootstrap/routes.go`. Verify:

```bash
grep -nE "/geo-restriction|/bot-filter|/uri-block|/rate-limit|/exploit-rules|/banned-ips|/access-lists" api/internal/bootstrap/routes.go
```

Adjust the path strings to match actual routes.

- [ ] **Step 3: Don't commit yet — combine with M3.7**

### Task M3.7: Write `block-reason-regression.spec.ts` (18 E2E cases)

**Files:**
- Create: `test/e2e/specs/security/block-reason-regression.spec.ts`

- [ ] **Step 1: Write the spec**

```ts
// test/e2e/specs/security/block-reason-regression.spec.ts
import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { triggerRequest, pollForLog } from '../../utils/log-helper';

const PROXY_PORT = 18080;

function randomDomain(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}.test.local`;
}

test.describe.parallel('block_reason regression', () => {

  test('geo_block: blacklist mode emits block_reason=geo_block', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('geo-bl')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setGeoRestriction(host.id, { enabled: true, mode: 'blacklist', countries: ['KR'] });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT,
      spoofIP: '203.243.0.1',
    });
    expect(resp.status).toBe(403);

    const log = await pollForLog(api, {
      host_id: host.id, expected_block_reason: 'geo_block', expected_status: 403, timeoutMs: 10_000,
    });
    expect(log.block_reason).toBe('geo_block');
    expect(log.geo_country).toMatch(/KR/);

    await api.deleteProxyHost(host.id);
  });

  test('geo_block: whitelist mode blocks non-US', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('geo-wl')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setGeoRestriction(host.id, { enabled: true, mode: 'whitelist', countries: ['US'] });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, spoofIP: '203.243.0.1',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'geo_block', timeoutMs: 10_000 });
    expect(log.block_reason).toBe('geo_block');

    await api.deleteProxyHost(host.id);
  });

  test('geo_block: challenge mode returns challenge page (not 403)', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('geo-ch')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setGeoRestriction(host.id, {
      enabled: true, mode: 'blacklist', countries: ['KR'], challenge_mode: true,
    });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, spoofIP: '203.243.0.1',
    });
    // Challenge mode redirects to /api/v1/challenge/page or similar — not a 403
    expect([200, 302, 307]).toContain(resp.status);

    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'geo_block', timeoutMs: 10_000 });
    expect(log.block_reason).toBe('geo_block');

    await api.deleteProxyHost(host.id);
  });

  test('access_denied: explicit deny in access list', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('acl')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setAccessList(host.id, [{ directive: 'deny', address: '10.255.255.42' }]);

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, spoofIP: '10.255.255.42',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'access_denied', timeoutMs: 10_000 });
    expect(log.block_reason).toBe('access_denied');

    await api.deleteProxyHost(host.id);
  });

  test('exploit_block: query_string SQLi pattern', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('exploit-qs')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setExploitRule(host.id, {
      pattern_type: 'query_string', pattern: 'union.*select',
      category: 'sqli', name: 'e2e sqli',
    });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT,
      path: "/?q=1'+UNION+SELECT+1--",
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'exploit_block', timeoutMs: 10_000 });
    expect(log.exploit_rule).toBeTruthy();

    await api.deleteProxyHost(host.id);
  });

  test('exploit_block: request_uri LFI pattern', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('exploit-uri')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setExploitRule(host.id, {
      pattern_type: 'request_uri', pattern: '/etc/passwd',
      category: 'lfi', name: 'e2e lfi',
    });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT,
      path: '/something/etc/passwd',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'exploit_block', timeoutMs: 10_000 });
    expect(log.block_reason).toBe('exploit_block');

    await api.deleteProxyHost(host.id);
  });

  test('exploit_block: user_agent scanner sets bot_category=scanner', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('exploit-ua')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setExploitRule(host.id, {
      pattern_type: 'user_agent', pattern: 'sqlmap', category: 'scanner', name: 'e2e scanner',
    });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, ua: 'sqlmap/1.0',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'exploit_block', timeoutMs: 10_000 });
    expect(log.bot_category).toBe('scanner');

    await api.deleteProxyHost(host.id);
  });

  test('exploit_block: request_method TRACE returns 405', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('exploit-method')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setExploitRule(host.id, {
      pattern_type: 'request_method', pattern: 'TRACE', category: 'method', name: 'e2e method',
    });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, method: 'TRACE',
    });
    expect(resp.status).toBe(405);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'exploit_block', expected_status: 405, timeoutMs: 10_000 });
    expect(log.block_reason).toBe('exploit_block');

    await api.deleteProxyHost(host.id);
  });

  test('banned_ip: manual ban records block_reason=banned_ip', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('banned')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setBannedIPs(host.id, ['10.255.255.99']);

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, spoofIP: '10.255.255.99',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'banned_ip', timeoutMs: 10_000 });
    expect(log.block_reason).toBe('banned_ip');

    await api.deleteProxyHost(host.id);
  });

  test('uri_block: prefix /admin returns 403', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('uri')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setURIBlock(host.id, '/admin');

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, path: '/admin/dashboard',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'uri_block', timeoutMs: 10_000 });
    expect(log.block_reason).toBe('uri_block');

    await api.deleteProxyHost(host.id);
  });

  test('bot_filter: bad_bot UA sets bot_category=bad_bot', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('bot-bad')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setBotFilter(host.id, { block_bad_bots: true });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, ua: 'AhrefsBot/7.0',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'bot_filter', timeoutMs: 10_000 });
    expect(log.bot_category).toBe('bad_bot');

    await api.deleteProxyHost(host.id);
  });

  test('bot_filter: ai_bot GPTBot sets bot_category=ai_bot', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('bot-ai')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setBotFilter(host.id, { block_ai_bots: true });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, ua: 'GPTBot/1.0',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'bot_filter', timeoutMs: 10_000 });
    expect(log.bot_category).toBe('ai_bot');

    await api.deleteProxyHost(host.id);
  });

  test('bot_filter: suspicious curl UA sets bot_category=suspicious', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('bot-susp')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setBotFilter(host.id, { block_suspicious_clients: true });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, ua: 'curl/7.88.0',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'bot_filter', timeoutMs: 10_000 });
    expect(log.bot_category).toBe('suspicious');

    await api.deleteProxyHost(host.id);
  });

  test('bot_filter: custom blocked agent sets bot_category=custom', async ({ request }) => {
    const api = new APIHelper(request);
    await api.login();
    const host = await api.createProxyHost({
      domain_names: [randomDomain('bot-custom')],
      forward_host: 'whoami', forward_port: 80, forward_scheme: 'http', enabled: true,
    });
    await api.setBotFilter(host.id, { custom_blocked_agents: 'MyEvilBot' });

    const resp = await triggerRequest({
      host: host.domain_names[0], proxyPort: PROXY_PORT, ua: 'MyEvilBot/2.0',
    });
    expect(resp.status).toBe(403);
    const log = await pollForLog(api, { host_id: host.id, expected_block_reason: 'bot_filter', timeoutMs: 10_000 });
    expect(log.bot_category).toBe('custom');

    await api.deleteProxyHost(host.id);
  });

  // The following 4 cases depend on external IP datasets being seeded by api setup.
  // If the dataset is empty in test DB, mark them as test.skip().

  test.skip('cloud_provider_block: Cloudflare IP blocked', async ({ request }) => {
    // Requires cloud_providers.cidrs to be seeded — implement when cloud provider seed is wired.
  });

  test.skip('cloud_provider_challenge: redirects to challenge page', async ({ request }) => {
    // Same as above.
  });

  test.skip('filter_subscription: IP from subscribed list blocked', async ({ request }) => {
    // Requires filter subscription to be active.
  });

  test.skip('rate_limit: exceeds rps emits 429', async ({ request }) => {
    // Rate limit doesn't set block_reason — verify status only.
    // Implement after confirming whether rate_limit hits affect access log block column.
  });
});
```

**Note:** the 4 `test.skip()` cases require external dataset seeding. Leave them as skip-with-note initially; they can be wired in a follow-up if/when the seeding infrastructure exists. The committed plan covers 14 active cases — that's still a major improvement over the current state (0 cases verified end-to-end).

- [ ] **Step 2: Run the spec**

```bash
sudo docker compose -f docker-compose.e2e-test.yml up -d --build
sleep 15
cd test/e2e
npx playwright test specs/security/block-reason-regression.spec.ts --reporter=line
```

Expected: 14 PASS, 4 SKIP.

If a case fails, the diagnostic output will indicate which step (config creation, request, log polling) failed. Common issues:
- API helper endpoint path mismatch → fix `api-helper.ts` URL
- block_reason in log doesn't match → real template bug, debug via `docker exec npg-test-proxy cat /var/log/nginx/access.log | tail -5`

- [ ] **Step 3: Commit (combined with M3.5 and M3.6)**

```bash
cd /opt/stacks/nginxproxyguard
git add test/e2e/utils/log-helper.ts \
        test/e2e/utils/api-helper.ts \
        test/e2e/specs/security/block-reason-regression.spec.ts
git commit -m "test(e2e): add end-to-end block_reason ingestion spec for security layers

Covers 14 security-layer activation paths and asserts (a) the request
is blocked with expected status and (b) the resulting log row carries
the correct block_reason / bot_category / exploit_rule fields. New
log-helper.ts provides trigger + poll utilities; api-helper.ts gains
per-feature setup helpers. Cloud provider, filter subscription, and
rate limit cases are skipped pending seed/spec follow-up."
```

**Milestone M3 complete.**

---

## Milestone M4 — ModSec Audit Fixture Automation (D항목)

**Risk:** 🟡 Medium — adds shell scripting + fixture vendoring + parser tightening.

### Task M4.1: Write `extract-schema.jq`

**Files:**
- Create: `scripts/extract-schema.jq`

- [ ] **Step 1: Write the schema extraction filter**

```jq
# scripts/extract-schema.jq
# Input: array of audit JSON objects (one entry = one ModSec transaction)
# Output: schema object — each leaf value replaced by its type name
#
# Usage: jq -f scripts/extract-schema.jq < audit.json

def schema_of:
  if type == "object" then
    to_entries | map({key, value: (.value | schema_of)}) | from_entries
  elif type == "array" then
    if length > 0 then [.[0] | schema_of] else ["empty"] end
  else
    type   # "string" | "number" | "boolean" | "null"
  end;

# Extract schema from the first entry (assume all entries share the same shape).
# If the input has 0 entries, return an error string.
if length == 0 then
  "no audit entries"
else
  .[0] | schema_of
end
```

- [ ] **Step 2: Smoke test**

```bash
echo '[{"transaction":{"client_ip":"1.2.3.4","client_port":54321}}]' | jq -f scripts/extract-schema.jq
```

Expected output:

```json
{
  "transaction": {
    "client_ip": "string",
    "client_port": "number"
  }
}
```

### Task M4.2: Write `capture-modsec-audit.sh`

**Files:**
- Create: `scripts/capture-modsec-audit.sh`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# scripts/capture-modsec-audit.sh
# Capture ModSecurity audit JSON in the e2e environment, extract a schema
# lockfile, and surface any drift against the committed schema.
#
# Usage:
#   scripts/capture-modsec-audit.sh [VERSION]
#
# VERSION defaults to the MODSECURITY_VERSION pinned in nginx/Dockerfile.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION="${1:-$(grep -oP 'MODSECURITY_VERSION=\K[\d.]+' nginx/Dockerfile)}"
[ -n "$VERSION" ] || { echo "ERROR: could not determine ModSec version"; exit 1; }

FIXTURE_DIR="api/internal/service/testdata"
SAMPLE_FILE="${FIXTURE_DIR}/modsec_audit_v${VERSION}.json"
SCHEMA_FILE="${FIXTURE_DIR}/modsec_audit_schema.json"
TEMP_FIXTURE=$(mktemp)
TEMP_SCHEMA=$(mktemp)
trap 'rm -f "$TEMP_FIXTURE" "$TEMP_SCHEMA"' EXIT

echo "==> ModSec version: $VERSION"
mkdir -p "$FIXTURE_DIR"

# 1. e2e env up
echo "==> [1/5] Ensuring e2e environment is running..."
if ! docker compose -f docker-compose.e2e-test.yml ps --status running --services 2>/dev/null | grep -q nginx; then
    sudo docker compose -f docker-compose.e2e-test.yml up -d --wait
    sleep 5
fi

# 2. Get admin token from a fresh login (uses default test admin creds)
echo "==> [2/5] Authenticating..."
TEST_USER="${TEST_USER:-testadmin}"
TEST_PASS="${TEST_PASS:-Testadmin123!}"
TOKEN=$(curl -sf -X POST http://localhost:19080/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}" \
    | jq -r '.token')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || { echo "ERROR: login failed"; exit 1; }

# 3. Create WAF-enabled probe host
echo "==> [3/5] Creating probe host..."
HOST_DOMAIN="modsec-capture-$(date +%s).test.local"
HOST_ID=$(curl -sf -X POST http://localhost:19080/api/v1/proxy-hosts \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"domain_names\":[\"$HOST_DOMAIN\"],\"forward_host\":\"whoami\",
         \"forward_port\":80,\"forward_scheme\":\"http\",\"enabled\":true,
         \"waf_enabled\":true,\"waf_mode\":\"blocking\",\"waf_paranoia_level\":1}" \
    | jq -r '.id')
[ -n "$HOST_ID" ] && [ "$HOST_ID" != "null" ] || { echo "ERROR: host creation failed"; exit 1; }
echo "    host_id=$HOST_ID"

cleanup_host() {
    curl -sf -X DELETE "http://localhost:19080/api/v1/proxy-hosts/$HOST_ID" \
        -H "Authorization: Bearer $TOKEN" >/dev/null 2>&1 || true
}
trap "cleanup_host; rm -f $TEMP_FIXTURE $TEMP_SCHEMA" EXIT

# 4. Fire probes (covers SQLi, XSS, LFI, RFI, scanner UA)
echo "==> [4/5] Firing probes..."
PROBES=(
    "/?q=1'%20OR%201=1--"
    "/?q=%3Cscript%3Ealert(1)%3C/script%3E"
    "/?file=../../../etc/passwd"
    "/?include=http://example.com/x"
)
for path in "${PROBES[@]}"; do
    curl -s -o /dev/null -H "Host: $HOST_DOMAIN" "http://localhost:18080$path" || true
done
curl -s -o /dev/null -H "Host: $HOST_DOMAIN" -A 'sqlmap/1.0' http://localhost:18080/ || true
sleep 2  # allow audit log flush

# 5. Collect audit log + extract schema
echo "==> [5/5] Collecting audit log..."
docker exec npg-test-proxy cat /var/log/nginx/modsec_audit.log \
    | grep -E '^\{"transaction' \
    | jq -s '.' > "$TEMP_FIXTURE"

ENTRIES=$(jq 'length' "$TEMP_FIXTURE")
if [ "$ENTRIES" = "0" ]; then
    echo "ERROR: no audit log entries captured. ModSec may not be triggering, or audit log path differs."
    echo "       inspect: docker exec npg-test-proxy ls -la /var/log/nginx/"
    exit 1
fi
echo "    captured $ENTRIES entries"

jq -f "$ROOT/scripts/extract-schema.jq" < "$TEMP_FIXTURE" > "$TEMP_SCHEMA"

# Diff against locked schema
if [ -f "$SCHEMA_FILE" ]; then
    if diff -u "$SCHEMA_FILE" "$TEMP_SCHEMA"; then
        echo ""
        echo "✓ Schema unchanged. Fixture is still in sync."
        echo "  (Sample file regenerated but not committed unless you mv it manually:"
        echo "   mv $TEMP_FIXTURE $SAMPLE_FILE)"
        exit 0
    else
        echo ""
        echo "⚠️  Schema CHANGED. Review the diff above."
        echo ""
        echo "If intentional (ModSec version bump):"
        echo "  mv $TEMP_SCHEMA  $SCHEMA_FILE"
        echo "  mv $TEMP_FIXTURE $SAMPLE_FILE"
        echo "  vim api/internal/service/log_collector_parser.go    # adjust types"
        echo "  go test ./internal/service/... -run ModSec"
        echo "  git add $SCHEMA_FILE $SAMPLE_FILE api/internal/service/log_collector_parser.go"
        echo "  git commit -m 'fix(modsec): align audit parser with vX.Y.Z schema'"
        exit 1
    fi
else
    echo ""
    echo "✓ Initial schema created (no prior lockfile)."
    mv "$TEMP_SCHEMA" "$SCHEMA_FILE"
    mv "$TEMP_FIXTURE" "$SAMPLE_FILE"
    echo "  $SCHEMA_FILE"
    echo "  $SAMPLE_FILE"
fi
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/capture-modsec-audit.sh scripts/extract-schema.jq
```

- [ ] **Step 3: Run it to generate initial fixture + lockfile**

```bash
sudo docker compose -f docker-compose.e2e-test.yml up -d --build
sleep 15
./scripts/capture-modsec-audit.sh
ls -la api/internal/service/testdata/
```

Expected: `modsec_audit_v3.0.15.json` (or current version) + `modsec_audit_schema.json` created.

If the script fails (e.g., audit log empty), investigate:
- `docker exec npg-test-proxy ls -la /var/log/nginx/` — confirm `modsec_audit.log` exists
- ModSec audit setup in `nginx/modsec/modsec-base.conf` — should have `SecAuditEngine On`, `SecAuditLogType Serial`, `SecAuditLogFormat JSON`
- Trigger probes manually: `curl -H "Host: <host>" "http://localhost:18080/?q=1'+OR+1=1--"` then check log

- [ ] **Step 4: Commit script + initial fixture**

```bash
git add scripts/capture-modsec-audit.sh scripts/extract-schema.jq \
        api/internal/service/testdata/modsec_audit_v3.0.15.json \
        api/internal/service/testdata/modsec_audit_schema.json
git commit -m "feat(modsec): add audit JSON capture script and schema lockfile

scripts/capture-modsec-audit.sh runs probes against the e2e
environment, captures the resulting audit log, extracts a key+type
schema, and diffs it against the committed lockfile. New ModSec
versions that alter the audit payload now fail this script
(loud and explicit) instead of silently breaking the parser."
```

### Task M4.3: Add parser schema test

**Files:**
- Modify: `api/internal/service/log_collector_parser_test.go`

- [ ] **Step 1: Inspect existing parser test structure**

```bash
grep -nE "^func Test|^var modsec" api/internal/service/log_collector_parser_test.go | head -10
```

Confirm the parser entry point name (likely `parseModSecAudit` or similar — adjust below if different).

- [ ] **Step 2: Add schema validation test**

Append to `log_collector_parser_test.go`:

```go
import (
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestModSecParser_FixtureSchema(t *testing.T) {
    versions := []string{"3.0.15"}  // add new versions on bump
    for _, v := range versions {
        t.Run("v"+v, func(t *testing.T) {
            fixturePath := filepath.Join("testdata", fmt.Sprintf("modsec_audit_v%s.json", v))
            schemaPath := filepath.Join("testdata", "modsec_audit_schema.json")

            fixtureBytes, err := os.ReadFile(fixturePath)
            require.NoError(t, err, "read fixture %s", fixturePath)

            var entries []map[string]any
            require.NoError(t, json.Unmarshal(fixtureBytes, &entries))
            require.NotEmpty(t, entries, "fixture has no entries")

            // 1) Every fixture entry parses cleanly
            for i, raw := range entries {
                rawBytes, _ := json.Marshal(raw)
                parsed, err := parseModSecAudit(rawBytes)
                require.NoError(t, err, "entry %d", i)
                assert.NotEmpty(t, parsed.Transaction.UniqueID, "entry %d UniqueID", i)
                assert.NotEmpty(t, parsed.Transaction.Request.URI, "entry %d Request.URI", i)
            }

            // 2) Fixture schema matches the committed lockfile
            extracted := extractSchemaFromObject(entries[0])
            schemaBytes, err := os.ReadFile(schemaPath)
            require.NoError(t, err, "read schema lockfile %s", schemaPath)
            var locked any
            require.NoError(t, json.Unmarshal(schemaBytes, &locked))
            extractedJSON, _ := json.MarshalIndent(extracted, "", "  ")
            lockedJSON, _ := json.MarshalIndent(locked, "", "  ")
            assert.Equal(t, string(lockedJSON), string(extractedJSON),
                "Fixture schema diverged from %s.\n"+
                "Run scripts/capture-modsec-audit.sh, review the diff, and commit updates.",
                schemaPath)
        })
    }
}

// extractSchemaFromObject mirrors scripts/extract-schema.jq: replaces every
// leaf with its JSON type name ("string"/"number"/"boolean"/"null"). Arrays
// are summarised by their first element (or ["empty"]).
func extractSchemaFromObject(v any) any {
    switch x := v.(type) {
    case map[string]any:
        out := make(map[string]any, len(x))
        for k, val := range x {
            out[k] = extractSchemaFromObject(val)
        }
        return out
    case []any:
        if len(x) == 0 {
            return []any{"empty"}
        }
        return []any{extractSchemaFromObject(x[0])}
    case string:
        return "string"
    case float64, int, int64:
        return "number"
    case bool:
        return "boolean"
    case nil:
        return "null"
    default:
        return fmt.Sprintf("unknown:%T", v)
    }
}
```

If `parseModSecAudit` is unexported, ensure the test is in the same package (`package service`).

- [ ] **Step 3: Run the test**

```bash
docker compose -f docker-compose.dev.yml run --rm api \
  go test ./internal/service/... -run ModSec -v
```

Expected: PASS. If schema mismatch, the diff in the test output will show which field changed — usually means the lockfile was committed from a state where the parser couldn't handle that field. Investigate.

- [ ] **Step 4: Commit**

```bash
git add api/internal/service/log_collector_parser_test.go
git commit -m "test(modsec): assert fixture schema matches lockfile

Locks in the ModSecurity audit JSON shape per version. Any new field,
missing field, or type change against testdata/modsec_audit_schema.json
fails the build, forcing a parser review."
```

### Task M4.4: Write `waf-audit-format.spec.ts` (E2E ingestion)

**Files:**
- Create: `test/e2e/specs/security/waf-audit-format.spec.ts`

- [ ] **Step 1: Write the spec**

```ts
// test/e2e/specs/security/waf-audit-format.spec.ts
import { test, expect } from '@playwright/test';
import { APIHelper } from '../../utils/api-helper';
import { triggerRequest, pollForLog } from '../../utils/log-helper';

const PROXY_PORT = 18080;

function randomDomain(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}.test.local`;
}

test('modsec audit ingestion: SQLi probe lands in DB with parsed fields', async ({ request }) => {
  const api = new APIHelper(request);
  await api.login();

  const host = await api.createProxyHost({
    domain_names: [randomDomain('waf-audit')],
    forward_host: 'whoami', forward_port: 80, forward_scheme: 'http',
    enabled: true,
  });
  await api.enableWAF(host.id, { mode: 'blocking', paranoia: 1 });

  // Allow nginx reload to settle
  await new Promise(r => setTimeout(r, 2000));

  const resp = await triggerRequest({
    host: host.domain_names[0],
    proxyPort: PROXY_PORT,
    path: "/?q=1'+OR+1=1--",
  });
  expect(resp.status).toBe(403);

  const log = await pollForLog(api, {
    host_id: host.id,
    expected_log_type: 'modsec',
    timeoutMs: 15_000,
  });

  expect(log.rule_id, 'rule_id should be a CRS rule ID').toBeTruthy();
  expect(log.severity, 'severity should be set').toMatch(/CRITICAL|WARNING|NOTICE|ERROR|ALERT/);
  expect(log.message, 'message should be populated').toBeTruthy();
  expect(log.uri, 'uri should contain query').toContain('q=');
  expect(log.client_ip, 'client_ip should be set').toBeTruthy();

  await api.deleteProxyHost(host.id);
});
```

Note: depending on the actual log API response shape, `log.rule_id` etc. may live under `log.modsec_data` or similar nested field. Adjust assertions to match the API's JSON.

- [ ] **Step 2: Run the spec**

```bash
sudo docker compose -f docker-compose.e2e-test.yml up -d --build
sleep 15
cd test/e2e
npx playwright test specs/security/waf-audit-format.spec.ts --reporter=line
```

Expected: PASS. If FAIL with "no log row matching", the audit log path may not be ingested by `log_collector.go` — confirm `log_collector` is reading the right file inside the container.

- [ ] **Step 3: Commit**

```bash
cd /opt/stacks/nginxproxyguard
git add test/e2e/specs/security/waf-audit-format.spec.ts
git commit -m "test(e2e): add ModSec audit pipeline ingestion spec

Verifies the full WAF audit path: nginx ModSec rule match -> audit
log emission -> log_collector parse -> DB ingestion -> API surface.
The committed fixture in api/internal/service/testdata covers the
parser unit layer; this spec covers the runtime pipeline."
```

### Task M4.5: Update nginx/CLAUDE.md ModSec checklist

**Files:**
- Modify: `nginx/CLAUDE.md`

- [ ] **Step 1: Locate existing ModSec version bump section**

```bash
grep -nE "ModSecurity / CRS 버전 범프 체크리스트|버전 범프" nginx/CLAUDE.md
```

- [ ] **Step 2: Insert capture script step**

Update the checklist to add a step right after build verification:

```markdown
| # | 검증 | 명령 |
|---|------|------|
| 1 | 빌드 성공 + `nginx -t` 통과 | `docker compose build nginx && docker exec npg-proxy nginx -t` |
| 2 | 룰 매칭 (403 응답) | SQLi/XSS 프로브 |
| 3 | **audit JSON schema 검증** | `./scripts/capture-modsec-audit.sh` — 변화 있으면 스크립트가 실패하며 diff 표시 |
| 4 | API 파서 단위 테스트 | `docker run ... go test ./internal/service/... -run ModSec -v` |
| 5 | DB ingestion 검증 | `cd test/e2e && npx playwright test specs/security/waf-audit-format.spec.ts` |
| 6 | UI 표시 | `로그 → WAF 이벤트` 탭에 신규 행 표시 |
```

The existing table likely has 6 rows already with similar content; replace the existing audit JSON capture row with the new one, and update the API parser / DB ingestion rows to reference the test files added in M4.3 and M4.4.

- [ ] **Step 3: Commit**

```bash
git add nginx/CLAUDE.md
git commit -m "docs(nginx): add capture-modsec-audit.sh to version bump checklist"
```

**Milestone M4 complete.**

---

## Milestone DoD — Definition of Done verification

### Task DoD.1: Full Go test suite

- [ ] **Step 1: Run full go test**

```bash
docker compose -f docker-compose.dev.yml run --rm api go test ./...
```

Expected: all PASS.

### Task DoD.2: Full E2E suite

- [ ] **Step 1: Ensure clean e2e env**

```bash
sudo docker compose -f docker-compose.e2e-test.yml down -v
sudo docker compose -f docker-compose.e2e-test.yml up -d --build
sleep 20
```

- [ ] **Step 2: Run E2E security specs**

```bash
cd test/e2e
npx playwright test specs/security/ specs/proxy-host/ --reporter=line
```

Expected: all PASS (existing specs unchanged + new block-reason-regression and waf-audit-format).

- [ ] **Step 3: Run E2E logs specs**

```bash
npx playwright test specs/logs/ --reporter=line
```

Expected: all PASS.

### Task DoD.3: nginx -t in real container

- [ ] **Step 1: Bring up dev compose with all hosts**

```bash
cd /opt/stacks/nginxproxyguard
sudo docker compose -f docker-compose.dev.yml up -d --build
sleep 10
docker exec npg-proxy nginx -t
```

Expected: `configuration file ... test is successful`.

### Task DoD.4: capture-modsec-audit re-verification

- [ ] **Step 1: Re-run capture**

```bash
./scripts/capture-modsec-audit.sh
```

Expected: `✓ Schema unchanged. Fixture is still in sync.`

### Task DoD.5: Architecture doc refresh

- [ ] **Step 1: Update ARCHITECTURE.md if it references template structure**

```bash
grep -nE "base\.conf\.tmpl|ssl\.conf\.tmpl|template structure|template partial" ARCHITECTURE.md | head -10
```

If matches exist, update to reference the new `_common_init`, `_security`, `_challenge_endpoints` partials.

- [ ] **Step 2: Commit any architecture doc update**

```bash
git add ARCHITECTURE.md
git commit -m "docs(architecture): note template partial structure"
```

(Skip commit if no changes.)

### Task DoD.6: Release approval gate

- [ ] **Step 1: Ask the user**

Do NOT run `/release` or version bump without explicit approval. Per project memory: "Release flow needs approval — walk through release steps and wait for explicit OK before doing any of them."

Provide the user with a summary of what would be in the release:

```
Stability hardening (P0+P1) is complete. Proposed release: v2.14.0.

Changes since v2.13.19:
- refactor(nginx): extract shared security partial from base/ssl templates
- test(migration): add upgradeSQL <-> 001_init.sql UPGRADE SECTION sync guard
- test(backup): add struct <-> export/import SQL sync guard
- test(nginx): add block_reason variable unit-level regression guard
- test(e2e): vendor MaxMind GeoLite2 test database
- test(e2e): mount GeoLite2 test mmdb into npg-test-proxy
- test(e2e): add global-setup with port + geoip guard
- test(e2e): add end-to-end block_reason ingestion spec
- feat(modsec): add audit JSON capture script and schema lockfile
- test(modsec): assert fixture schema matches lockfile
- test(e2e): add ModSec audit pipeline ingestion spec
- docs(nginx): add capture-modsec-audit.sh to version bump checklist

Ready to bump api/internal/config/constants.go AppVersion and ui/package.json
to 2.14.0 and proceed with the standard release flow?
```

Wait for explicit user OK before bumping version or tagging.

---

## Plan Self-Review

**Coverage check vs spec:**
- §3 (M1 partials) → Tasks M1.1–M1.11 ✓
- §4 (M2 sync tests) → Tasks M2.1–M2.3 ✓
- §5 (M3 block_reason guards) → Tasks M3.1–M3.7 ✓
- §6 (M4 ModSec fixture) → Tasks M4.1–M4.5 ✓
- §7 (implementation order) → Reflected in milestone ordering ✓
- §8 (DoD) → Tasks DoD.1–DoD.6 ✓

**Placeholder scan:** No TBD/TODO. Conditional tasks (M2.1, M3.2) explicitly skip when M0 finding shows them unnecessary.

**Type consistency:** Helper names referenced consistently — `triggerRequest` / `pollForLog` (log-helper.ts), `setGeoRestriction` / `setAccessList` / etc. (api-helper.ts), `extractSchemaFromObject` (parser test mirrors `extract-schema.jq`).

**Ambiguity check:** Endpoint paths in M3.6 flagged as needing route verification — explicit instruction included. Field names in M3.1 builders flagged as needing struct inspection.

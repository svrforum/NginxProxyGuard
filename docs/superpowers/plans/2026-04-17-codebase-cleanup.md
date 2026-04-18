# Codebase Structural Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate accumulated structural debt — doc drift, oversized files, missing tests — across 7 independent PRs landing on `main`.

**Architecture:** Sequential phases in ascending risk order. Phase 2 characterization tests act as safety net for Phases 3-6 refactors. Each phase is an independent PR; a failure in Phase N does not block earlier merges.

**Tech Stack:** Go 1.24 (Echo v4), React 18 + TypeScript 5.6, TimescaleDB 17 + pg17, Docker Compose, Playwright (E2E).

**Spec:** `docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md` — read for full context before starting a phase.

---

## Global File Map

| Phase | File | Action | Responsibility |
|-------|------|--------|----------------|
| 1 | `CLAUDE.md` | Modify | Sync file counts + add `pages/`, `util/` |
| 1 | `ARCHITECTURE.md` | Modify | Sync §2.1, §2.7, §2.11, §3.1 to reality |
| 1 | `nginx/modsec/main.conf` | Delete or annotate | Legacy file — remove if unreferenced |
| 1 | `nginx/modsec/detection-only.conf` | Delete or annotate | Legacy file — remove if unreferenced |
| 2 | `api/internal/nginx/proxy_host_template_characterization_test.go` | Create | 6-case golden-file test |
| 2 | `api/internal/nginx/testdata/golden/proxy_host_*.conf` | Create | 6 golden fixtures |
| 2 | `api/internal/nginx/advanced_config_characterization_test.go` | Create | 20-case directive parser test |
| 2 | `api/internal/service/waf_merge_characterization_test.go` | Create | 4-case WAF merge test |
| 2 | `api/internal/service/sync_auto_recovery_characterization_test.go` | Create | Auto-recovery loop test with fake nginx |
| 3 | `api/internal/bootstrap/` | Create (8 files) | New package encapsulating DI assembly |
| 3 | `api/cmd/server/main.go` | Rewrite | Slim entry point (~170 lines) |
| 4a | `api/internal/nginx/templates/proxy_host/*.tmpl` | Create (9 files) | Split template by section |
| 4a | `api/internal/nginx/proxy_host_template.go` | Rewrite | Load templates via embed.FS |
| 4b | `api/internal/repository/log_*.go` | Create (4 files) | Split oversized log repo |
| 4b | `api/internal/repository/backup_export_*.go` | Create (3 files) | Split export by domain |
| 4b | `api/internal/repository/backup_import_*.go` | Create (3 files) | Split import by domain |
| 4b | `api/internal/repository/proxy_host_*.go` | Create (2 files) | Split proxy_host repo |
| 4b | `api/internal/repository/waf_*.go` | Create (2 files) | Split waf repo |
| 4b | `api/internal/repository/backup_roundtrip_test.go` | Create | Export→import roundtrip test |
| 5 | 10 UI components in `ui/src/components/**` | Split + move | Domain subfolders |
| 6 | `ui/src/components/proxy-host/hooks/*` | Split + replace | 5 new modules + thin container |

---

## Phase 1: Docs Sync + Legacy Cleanup

**Branch:** `phase1/docs-sync`
**PR title:** `chore: sync architecture docs and prune legacy`
**Risk:** 🟢 Very low — docs edits + possibly delete 2 unreferenced files.

### Task 1.1: Create branch and baseline

**Files:** none yet

- [ ] **Step 1: Ensure clean working tree on main**

```bash
cd /opt/stacks/nginxproxyguard
git status
git checkout main
git pull --ff-only origin main
```

Expected: clean tree, up to date with remote.

- [ ] **Step 2: Create phase1 branch**

```bash
git checkout -b phase1/docs-sync
```

### Task 1.2: Collect actual project metrics

**Files:** none (temporary notes)

- [ ] **Step 1: Record current backend file counts**

```bash
cd /opt/stacks/nginxproxyguard
for d in handler service repository model middleware nginx scheduler util config database; do
  count=$(find api/internal/$d -name '*.go' -not -name '*_test.go' 2>/dev/null | wc -l)
  echo "$d: $count"
done
```

Write output to a scratch note (terminal paste is fine). Expected output:
```
handler: 37
service: 29
repository: 30
model: 25
middleware: 3
nginx: 10
scheduler: 5
util: 1
config: 2
database: 2
```

- [ ] **Step 2: Confirm AppVersion in code**

```bash
grep -n "AppVersion" api/internal/config/constants.go
```

Expected: `const AppVersion = "..."` with current release version (verify it matches `git describe --tags --abbrev=0`).

- [ ] **Step 3: Confirm UI directory presence**

```bash
ls ui/src/pages/
ls ui/src/hooks/
```

### Task 1.3: Update CLAUDE.md — Backend directory counts

**Files:**
- Modify: `CLAUDE.md` (section "Backend (Go) Architecture" → "Directory Structure")

- [ ] **Step 1: Update file counts in the backend directory tree**

In `CLAUDE.md`, find the block starting with `api/` under "Backend (Go) Architecture → Directory Structure" and update the file-count comments:

Replace the `handler/`, `model/`, `nginx/`, `repository/`, `service/` comments with the actual counts measured in Task 1.2:

```
├── handler/                # HTTP 핸들러 (37개 파일)
├── middleware/             # 인증, API 토큰, 레이트리밋 (3개 파일)
├── model/                  # 데이터 구조체 (25개 파일)
├── nginx/                  # Nginx 설정 생성 엔진 (10개 파일)
├── repository/             # DB 접근 계층 (30개 파일)
├── scheduler/              # 백그라운드 작업 (5개 파일)
├── service/                # 비즈니스 로직 (29개 파일)
└── util/                   # SQL 유틸리티 (query.go)
```

### Task 1.4: Update CLAUDE.md — Frontend directory structure

**Files:**
- Modify: `CLAUDE.md` (section "Frontend (React) Architecture" → "Directory Structure")

- [ ] **Step 1: Add `pages/` directory to the ui/src tree**

In the `ui/src/` block under Frontend Architecture, insert after `components/` block:

```
├── pages/                      # 라우트 단위 탭 호스트 컨테이너
│   ├── CertificatesPage.tsx    # /certificates/* 라우트 그룹
│   ├── LogsPage.tsx            # /logs/* 라우트 그룹
│   ├── SettingsPage.tsx        # /settings/* 라우트 그룹
│   └── WAFPage.tsx             # /waf/* 라우트 그룹
```

### Task 1.5: Update ARCHITECTURE.md — §2.1 directory tree

**Files:**
- Modify: `ARCHITECTURE.md` §2.1 "Directory Structure"

- [ ] **Step 1: Update §2.1 file-count comments to actual values**

Replace the existing counts:
- `handler/ # 26 핸들러 파일` → `handler/ # 37 핸들러 파일`
- `model/ # 23 모델 파일` → `model/ # 25 모델 파일`
- `nginx/ # 7 파일` → `nginx/ # 10 파일`
- `repository/ # 30 레포지토리 파일` → keep 30 (correct)
- `service/ # 20 서비스 파일` → `service/ # 29 서비스 파일`

### Task 1.6: Update ARCHITECTURE.md — §2.7 repository inventory

**Files:**
- Modify: `ARCHITECTURE.md` §2.7 "Repository Inventory"

- [ ] **Step 1: List all current repository files**

```bash
ls api/internal/repository/*.go | grep -v _test.go | sort
```

- [ ] **Step 2: Compare against the table in §2.7 and add missing rows, remove stale rows**

Cross-reference each `.go` file against the inventory table. For files NOT in the table, add a row capturing the Repository type name + key methods. For table rows with no corresponding file, delete them.

### Task 1.7: Update ARCHITECTURE.md — §2.11 AppVersion

**Files:**
- Modify: `ARCHITECTURE.md` §2.11 "Key Constants"

- [ ] **Step 1: Replace stale AppVersion literal**

Find:
```go
const AppVersion = "2.7.4"
```

Replace with current version from `constants.go` (verified in Task 1.2):
```go
const AppVersion = "2.9.1"  // See api/internal/config/constants.go — single source of truth
```

Also, in the header of `ARCHITECTURE.md` (lines 1-6), change:
```
> **Version**: 2.7.6 | **Last Updated**: 2026-04-06
```
to:
```
> **Version**: See `api/internal/config/constants.go` `AppVersion` (single source of truth)
> **Last Updated**: 2026-04-17
```

### Task 1.8: Update ARCHITECTURE.md — §3.1 frontend structure

**Files:**
- Modify: `ARCHITECTURE.md` §3.1

- [ ] **Step 1: Add `pages/` to frontend directory tree**

Insert the same `pages/` block described in Task 1.4 into the §3.1 directory tree.

- [ ] **Step 2: Add separator note between pages/ and components/**

Add below the `components/` description:

```
> **pages/ vs components/ 경계:** `pages/`는 라우트별 탭 호스트 컨테이너 (`CertificatesPage`, `LogsPage`, `SettingsPage`, `WAFPage`). 재사용 단위는 `components/`에 위치.
```

### Task 1.9: Audit legacy nginx config files

**Files:** read-only

- [ ] **Step 1: Check if legacy files are referenced anywhere**

```bash
cd /opt/stacks/nginxproxyguard
grep -rn "main\.conf\|detection-only\.conf" nginx/ api/ --include="*.go" --include="*.conf" --include="*.sh" --include="Dockerfile*" --include="*.yml" --include="*.yaml" 2>&1 | grep -v "^Binary"
```

- [ ] **Step 2: Classify result**

- If **zero matches** for these two filenames (in include directives or shell scripts), proceed to Task 1.10 (remove).
- If matches exist, skip to Task 1.11 (annotate instead of remove).

### Task 1.10: Remove legacy files (only if Task 1.9 found zero references)

**Files:**
- Delete: `nginx/modsec/main.conf`
- Delete: `nginx/modsec/detection-only.conf`

- [ ] **Step 1: Remove the two files**

```bash
git rm nginx/modsec/main.conf nginx/modsec/detection-only.conf
```

- [ ] **Step 2: Update ARCHITECTURE.md §4.2**

Remove the two lines describing `main.conf` and `detection-only.conf` from the nginx directory tree (their "(레거시)" entries).

### Task 1.11: Annotate legacy files (only if Task 1.9 found matches)

**Files:**
- Modify: `ARCHITECTURE.md` §4.2

- [ ] **Step 1: Add retention note**

In the §4.2 nginx tree, change:
```
│   ├── main.conf               # (레거시) ModSecurity blocking 모드
│   ├── detection-only.conf     # (레거시) ModSecurity detection 모드
```
to:
```
│   ├── main.conf               # (레거시) ModSecurity blocking 모드 — 런타임 참조 존재, 제거 보류
│   ├── detection-only.conf     # (레거시) ModSecurity detection 모드 — 런타임 참조 존재, 제거 보류
```

### Task 1.12: Verify nginx config still tests clean

**Files:** none

- [ ] **Step 1: Start dev nginx container and tail logs**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml up -d nginx
sleep 3
docker compose -f docker-compose.dev.yml logs nginx | tail -30
```

Expected: no `[emerg]` or `nginx -t failed` messages. Banner showing nginx started.

- [ ] **Step 2: Tear down**

```bash
docker compose -f docker-compose.dev.yml down
```

### Task 1.13: Commit, push, open PR

- [ ] **Step 1: Review diff**

```bash
git diff --stat
git diff
```

- [ ] **Step 2: Stage and commit**

```bash
git add CLAUDE.md ARCHITECTURE.md
# Add nginx file deletions if Task 1.10 ran:
git add nginx/modsec/ 2>/dev/null || true
git commit -m "chore: sync architecture docs and prune legacy"
```

- [ ] **Step 3: Push**

```bash
git push -u origin phase1/docs-sync
```

- [ ] **Step 4: Open PR**

```bash
gh pr create --title "chore: sync architecture docs and prune legacy" --body "$(cat <<'EOF'
## Scope
Phase 1 of codebase-cleanup — sync CLAUDE.md and ARCHITECTURE.md with actual project structure, remove unreferenced legacy nginx configs.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §3

## Changes
- CLAUDE.md: update backend file counts (handler 37/service 29/repo 30/model 25/nginx 10/scheduler 5/middleware 3/util 1)
- CLAUDE.md: add `ui/src/pages/` block
- ARCHITECTURE.md §2.1, §2.7, §3.1: sync to reality
- ARCHITECTURE.md §2.11: AppVersion SoT note, drop stale literal
- ARCHITECTURE.md §4.2: (if applicable) legacy modsec files removed or annotated
- nginx/modsec: removed main.conf + detection-only.conf (only if unreferenced)

## Verification
- [x] `docker compose -f docker-compose.dev.yml up -d nginx` starts cleanly

## Out of scope
- Any code changes (docs/deletion only)
EOF
)"
```

Record the PR URL.

---

## Phase 2: Characterization Tests

**Branch:** `phase2/characterization-tests`
**PR title:** `test: add characterization tests for config generation`
**Risk:** 🟢 Low — additive tests only.

**Prerequisite:** Phase 1 PR merged.

### Task 2.1: Create branch

- [ ] **Step 1: Sync main and branch off**

```bash
cd /opt/stacks/nginxproxyguard
git checkout main
git pull --ff-only origin main
git checkout -b phase2/characterization-tests
```

### Task 2.2: Create golden fixture directory structure

**Files:**
- Create: `api/internal/nginx/testdata/golden/` (directory)

- [ ] **Step 1: Create directory**

```bash
mkdir -p api/internal/nginx/testdata/golden
touch api/internal/nginx/testdata/golden/.gitkeep
```

### Task 2.3: Write proxy_host_template characterization test — structure

**Files:**
- Create: `api/internal/nginx/proxy_host_template_characterization_test.go`

- [ ] **Step 1: Create the test file with 6 cases and golden-file helper**

```go
package nginx

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "update golden files")

// characterization cases - capture the rendered output of representative inputs.
// These are BEHAVIORAL snapshots. Any intentional output change requires running
// with -update-golden flag and reviewing the diff before committing.
func TestProxyHostTemplate_Characterization(t *testing.T) {
	cases := []struct {
		name string
		data ProxyHostData
	}{
		{name: "http_only", data: fixtureHTTPOnly()},
		{name: "https_force", data: fixtureHTTPSForce()},
		{name: "waf_blocking", data: fixtureWAFBlocking()},
		{name: "cache_enabled", data: fixtureCacheEnabled()},
		{name: "advanced_config_conflict", data: fixtureAdvancedConfigConflict()},
		{name: "upstream_load_balance", data: fixtureUpstreamLB()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderProxyHostConfig(context.Background(), &buf, tc.data); err != nil {
				t.Fatalf("render failed: %v", err)
			}
			compareGolden(t, "proxy_host_"+tc.name+".conf", buf.Bytes())
		})
	}
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated golden file: %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update-golden to create)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}
```

- [ ] **Step 2: Add fixture helpers in the same file (below the test function)**

The fixture helpers construct representative `ProxyHostData`. The exact shape of `ProxyHostData` must be verified by reading the existing `proxy_host_template.go`:

```bash
grep -n "type ProxyHostData\|type ProxyHost " api/internal/nginx/*.go
```

Write six fixture helpers, one per case. Use UUIDs pinned as constants so output is deterministic. Example for `fixtureHTTPOnly`:

```go
func fixtureHTTPOnly() ProxyHostData {
	return ProxyHostData{
		ID:            "00000000-0000-0000-0000-000000000001",
		DomainNames:   []string{"example.com"},
		ForwardScheme: "http",
		ForwardHost:   "192.168.1.10",
		ForwardPort:   8080,
		SSLEnabled:    false,
		// ...fill in remaining zero-value-safe fields based on struct
	}
}
```

Write the remaining five fixture helpers with the characteristics from the spec §4.1 (HTTPS force + cert + HTTP/2; WAF blocking paranoia 2 threshold 5 with 3 exclusions; cache enabled; advanced_config injecting `proxy_connect_timeout 10s;`; upstream with least_conn and 3 backends).

- [ ] **Step 3: Add a small helper to invoke the actual rendering entry-point**

Look at the actual exported function signature:

```bash
grep -n "func.*GenerateConfig\|func.*renderProxyHost\|func.*Template" api/internal/nginx/proxy_host_template.go | head
```

If the production render function requires a `*Manager` receiver, define `renderProxyHostConfig` as a thin wrapper that invokes the package-level template directly (without file I/O):

```go
// renderProxyHostConfig writes the rendered config to w without filesystem side effects.
// Used by characterization tests.
func renderProxyHostConfig(_ context.Context, w *bytes.Buffer, data ProxyHostData) error {
	return proxyHostTemplate.Execute(w, data)
}
```

(Replace `proxyHostTemplate` with the actual package-level template variable name.)

### Task 2.4: Generate golden files for the first time

- [ ] **Step 1: Run tests with -update-golden to write initial goldens**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./internal/nginx/ -run TestProxyHostTemplate_Characterization -update-golden -v
```

Expected: 6 PASS messages with `updated golden file:` logs. 6 files written under `testdata/golden/`.

- [ ] **Step 2: Inspect each golden to confirm it looks sensible**

```bash
for f in api/internal/nginx/testdata/golden/proxy_host_*.conf; do
  echo "=== $f ==="
  head -40 "$f"
done
```

Each should be a recognizable nginx server block with expected directives for that case (e.g., `http_only` has no `listen 443 ssl`, `waf_blocking` has `modsecurity on;`).

- [ ] **Step 3: Run tests WITHOUT the flag to verify bytewise match**

```bash
go test ./internal/nginx/ -run TestProxyHostTemplate_Characterization -v
```

Expected: 6 PASS messages.

### Task 2.5: Commit goldens + test scaffolding

- [ ] **Step 1: Stage and commit**

```bash
cd /opt/stacks/nginxproxyguard
git add api/internal/nginx/proxy_host_template_characterization_test.go api/internal/nginx/testdata/
git commit -m "test(nginx): add proxy_host_template characterization test with 6 golden fixtures"
```

### Task 2.6: Write WAF merge characterization test

**Files:**
- Create: `api/internal/service/waf_merge_characterization_test.go`

- [ ] **Step 1: Locate the exact function to test**

```bash
grep -n "getMergedWAFExclusions\|MergedWAFExclusions\|MergeWAFExclusions" api/internal/service/*.go
```

Note the receiver type and signature. Typical form:
```go
func (s *ProxyHostService) getMergedWAFExclusions(ctx context.Context, hostID string) ([]model.WAFRuleExclusion, error)
```

Because `getMergedWAFExclusions` calls repositories, we test against in-memory fakes implementing the repo interfaces the function uses.

- [ ] **Step 2: Create the test file with fakes + 4 cases**

```go
package service

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

type fakeWAFRepo struct {
	globalExclusions []model.WAFRuleExclusion
	hostExclusions   map[string][]model.WAFRuleExclusion
}

func (f *fakeWAFRepo) GetGlobalExclusions(ctx context.Context) ([]model.WAFRuleExclusion, error) {
	return f.globalExclusions, nil
}

func (f *fakeWAFRepo) GetHostExclusions(ctx context.Context, hostID string) ([]model.WAFRuleExclusion, error) {
	return f.hostExclusions[hostID], nil
}

// ... implement any other methods the interface demands (return nil, nil)

func TestGetMergedWAFExclusions_Characterization(t *testing.T) {
	cases := []struct {
		name       string
		global     []model.WAFRuleExclusion
		host       []model.WAFRuleExclusion
		wantRuleIDs []int64
	}{
		{
			name:       "global_only",
			global:     []model.WAFRuleExclusion{{RuleID: 942100}, {RuleID: 920300}},
			host:       nil,
			wantRuleIDs: []int64{942100, 920300},
		},
		{
			name:       "host_only",
			global:     nil,
			host:       []model.WAFRuleExclusion{{RuleID: 942200}},
			wantRuleIDs: []int64{942200},
		},
		{
			name:       "merged_with_duplicate_host_wins",
			global:     []model.WAFRuleExclusion{{RuleID: 942100, Scope: "global"}},
			host:       []model.WAFRuleExclusion{{RuleID: 942100, Scope: "host"}, {RuleID: 942300, Scope: "host"}},
			wantRuleIDs: []int64{942100, 942300},
		},
		{
			name:       "both_empty",
			global:     nil,
			host:       nil,
			wantRuleIDs: []int64{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeWAFRepo{
				globalExclusions: tc.global,
				hostExclusions:   map[string][]model.WAFRuleExclusion{"host-1": tc.host},
			}
			svc := &ProxyHostService{wafRepo: repo}

			got, err := svc.getMergedWAFExclusions(context.Background(), "host-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var ruleIDs []int64
			for _, e := range got {
				ruleIDs = append(ruleIDs, e.RuleID)
			}

			if !equalIntSets(ruleIDs, tc.wantRuleIDs) {
				t.Errorf("rule IDs = %v, want (as set) %v", ruleIDs, tc.wantRuleIDs)
			}
		})
	}
}

func equalIntSets(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[int64]int{}
	for _, v := range a {
		m[v]++
	}
	for _, v := range b {
		m[v]--
	}
	for _, c := range m {
		if c != 0 {
			return false
		}
	}
	return true
}
```

> **Note on interface satisfaction:** If the test fails to compile because `ProxyHostService.wafRepo` is a concrete `*repository.WAFRepository` rather than an interface, the test needs the service constructor. Alternative approach: change test to use a real DB via `testcontainers` OR change `wafRepo` field to an interface. The LOWEST-RISK approach is to define a local test-only interface and refactor the service to accept it — BUT that's scope creep. Instead, extract just the merge logic (if possible) into a pure function that takes slices and returns the merged slice, then test that function. Verify this by reading the actual implementation before committing to an approach.

- [ ] **Step 3: Run the test**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./internal/service/ -run TestGetMergedWAFExclusions -v
```

If it fails to compile due to interface issues, refactor as a pure function in a separate file (`waf_merge.go`) that takes `(globalExclusions, hostExclusions []model.WAFRuleExclusion) []model.WAFRuleExclusion`, move the merge body there, and call it from the original method. Re-test.

- [ ] **Step 4: Commit**

```bash
git add api/internal/service/waf_merge_characterization_test.go
# if you created a helper file:
git add api/internal/service/waf_merge.go 2>/dev/null || true
git commit -m "test(service): add WAF merge characterization test with 4 cases"
```

### Task 2.7: Write advanced_config directive-parser test

**Files:**
- Create: `api/internal/nginx/advanced_config_characterization_test.go`

- [ ] **Step 1: Locate the directive parser**

```bash
grep -n "parseAdvancedConfigDirectives\|hasDirective" api/internal/nginx/*.go
```

- [ ] **Step 2: Create test with 20 cases**

```go
package nginx

import (
	"reflect"
	"sort"
	"testing"
)

func TestParseAdvancedConfigDirectives_Characterization(t *testing.T) {
	cases := []struct {
		name     string
		config   string
		wantSet  []string // sorted
	}{
		{"empty", "", nil},
		{"single_directive", "proxy_connect_timeout 10s;", []string{"proxy_connect_timeout"}},
		{"two_directives", "proxy_connect_timeout 10s;\nproxy_read_timeout 60s;", []string{"proxy_connect_timeout", "proxy_read_timeout"}},
		{"with_leading_whitespace", "    proxy_send_timeout 30s;", []string{"proxy_send_timeout"}},
		{"with_tabs", "\tclient_max_body_size 100m;", []string{"client_max_body_size"}},
		{"single_line_comment", "# comment line\nproxy_buffering off;", []string{"proxy_buffering"}},
		{"inline_comment", "proxy_buffering off; # no buffering", []string{"proxy_buffering"}},
		{"blank_lines", "\n\nproxy_buffering off;\n\n", []string{"proxy_buffering"}},
		{"multiline_block_comment_ignored", "# block\n# comment\nclient_body_timeout 30s;", []string{"client_body_timeout"}},
		{"location_block_wrapping_directive", "location /api {\n  proxy_read_timeout 120s;\n}", []string{"proxy_read_timeout"}},
		{"if_block", "if ($host = 'x') {\n  return 301 https://$host$request_uri;\n}", []string{"return"}},
		{"multiple_directives_same_line", "proxy_buffering off; proxy_request_buffering off;", []string{"proxy_buffering", "proxy_request_buffering"}},
		{"duplicate_directive", "proxy_buffering off;\nproxy_buffering on;", []string{"proxy_buffering"}},
		{"with_trailing_semicolon_missing", "proxy_buffering off", []string{"proxy_buffering"}},
		{"case_sensitive", "Proxy_Buffering off;", []string{"Proxy_Buffering"}},
		{"directive_with_complex_value", "add_header X-Frame-Options \"SAMEORIGIN\" always;", []string{"add_header"}},
		{"rewrite_directive", "rewrite ^/old/(.*)$ /new/$1 permanent;", []string{"rewrite"}},
		{"nested_block", "location / {\n  if ($x) {\n    set $y 1;\n  }\n  proxy_pass http://backend;\n}", []string{"set", "proxy_pass"}},
		{"commented_out_directive_not_counted", "# proxy_buffering off;\nreal_directive on;", []string{"real_directive"}},
		{"malformed_line_best_effort", "this is not a valid directive at all\nproxy_buffering off;", []string{"proxy_buffering"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseAdvancedConfigDirectives(tc.config)
			gotSorted := sortedKeys(got)
			wantSorted := append([]string(nil), tc.wantSet...)
			sort.Strings(wantSorted)
			if !reflect.DeepEqual(gotSorted, wantSorted) {
				t.Errorf("got %v, want %v", gotSorted, wantSorted)
			}
		})
	}
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
```

> **Note:** The exact return type of `parseAdvancedConfigDirectives` may be `map[string]struct{}` or `map[string]bool` or `[]string`. Adapt `sortedKeys` to match.

- [ ] **Step 3: Run**

```bash
go test ./internal/nginx/ -run TestParseAdvancedConfigDirectives -v
```

Any failing case reveals current behavior — if it's a bug, open an issue but **leave the test's `wantSet` matching current behavior** (this is a characterization test, not a correctness test). Add a comment noting the discrepancy.

- [ ] **Step 4: Commit**

```bash
git add api/internal/nginx/advanced_config_characterization_test.go
git commit -m "test(nginx): add advanced_config directive-parser characterization test with 20 cases"
```

### Task 2.8: Write sync_auto_recovery characterization test

**Files:**
- Create: `api/internal/service/sync_auto_recovery_characterization_test.go`

- [ ] **Step 1: Locate the function and its dependencies**

```bash
grep -n "func.*SyncAllConfigs" api/internal/service/*.go
grep -n "type NginxManager\|type nginxManager" api/internal/service/*.go
```

Note the service struct's fields (`repo`, `nginx`, etc.) and the `NginxManager` interface if defined.

- [ ] **Step 2: Create fake nginx manager + test**

```go
package service

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

type fakeNginxManager struct {
	writtenConfigs map[string][]byte // host ID -> content
	testAttempts   int
}

func (f *fakeNginxManager) GenerateConfigFull(ctx context.Context, data model.ProxyHostData) error {
	if f.writtenConfigs == nil {
		f.writtenConfigs = map[string][]byte{}
	}
	// simulate per-host config by putting host ID into content
	content := fmt.Sprintf("server { # host=%s content=%s }", data.ID, data.ForwardHost)
	f.writtenConfigs[data.ID] = []byte(content)
	return nil
}

func (f *fakeNginxManager) GenerateHostWAFConfig(ctx context.Context, host model.ProxyHost, exclusions []model.WAFRuleExclusion) error {
	return nil
}

func (f *fakeNginxManager) TestConfig(ctx context.Context) error {
	f.testAttempts++
	for id, content := range f.writtenConfigs {
		if strings.Contains(string(content), "FAIL_MARKER") {
			return fmt.Errorf("nginx: [emerg] error in config for host %s", id)
		}
	}
	return nil
}

func (f *fakeNginxManager) ReloadConfig(ctx context.Context) error { return nil }

func (f *fakeNginxManager) RemoveConfig(ctx context.Context, hostID string) error {
	delete(f.writtenConfigs, hostID)
	return nil
}

// Add any other interface methods with nil-safe no-op implementations.

type fakeProxyHostRepo struct {
	hosts []model.ProxyHost
	statusUpdates map[string]string // hostID -> status
}

func (r *fakeProxyHostRepo) ListEnabled(ctx context.Context) ([]model.ProxyHost, error) {
	return r.hosts, nil
}

func (r *fakeProxyHostRepo) UpdateConfigStatus(ctx context.Context, hostID, status, errMsg string) error {
	if r.statusUpdates == nil {
		r.statusUpdates = map[string]string{}
	}
	r.statusUpdates[hostID] = status
	return nil
}

// Add other methods as no-ops.

func TestSyncAllConfigs_AutoRecovery_Characterization(t *testing.T) {
	// Construct 5 hosts: 2 have a forward host containing "FAIL_MARKER" which the fake nginx will reject.
	hosts := []model.ProxyHost{
		{ID: "host-1", ForwardHost: "good-1.internal"},
		{ID: "host-2", ForwardHost: "FAIL_MARKER-2.internal"},
		{ID: "host-3", ForwardHost: "good-3.internal"},
		{ID: "host-4", ForwardHost: "FAIL_MARKER-4.internal"},
		{ID: "host-5", ForwardHost: "good-5.internal"},
	}

	nginx := &fakeNginxManager{}
	repo := &fakeProxyHostRepo{hosts: hosts}

	svc := &ProxyHostService{
		repo:  repo,
		nginx: nginx,
		// Fill in any other required fields with zero values or fakes.
	}

	err := svc.SyncAllConfigs(context.Background())
	if err != nil {
		t.Fatalf("SyncAllConfigs returned error: %v", err)
	}

	// Bad hosts should have been removed from fake nginx
	for _, badID := range []string{"host-2", "host-4"} {
		if _, stillPresent := nginx.writtenConfigs[badID]; stillPresent {
			t.Errorf("bad host %s config was not removed after failure", badID)
		}
		if status := repo.statusUpdates[badID]; status != "error" {
			t.Errorf("bad host %s status = %q, want \"error\"", badID, status)
		}
	}

	// Good hosts should remain
	for _, goodID := range []string{"host-1", "host-3", "host-5"} {
		if _, ok := nginx.writtenConfigs[goodID]; !ok {
			t.Errorf("good host %s config missing", goodID)
		}
	}

	// Retry budget must not exceed 5 attempts
	if nginx.testAttempts > 5 {
		t.Errorf("testAttempts = %d, want <= 5", nginx.testAttempts)
	}
}
```

> **Note:** The exact field names (`repo`, `nginx`), interfaces, and method signatures must be verified against the current code. If the real `ProxyHostService` struct requires more fields than this fake supplies, add them with zero/fake values. If `SyncAllConfigs` calls methods not on these fakes, add those too.

- [ ] **Step 3: Run**

```bash
go test ./internal/service/ -run TestSyncAllConfigs_AutoRecovery -v
```

If test fails because `SyncAllConfigs` depends on a WAF repo, global settings, etc., augment the fakes (all returning empty slices / zero values is fine).

- [ ] **Step 4: Commit**

```bash
git add api/internal/service/sync_auto_recovery_characterization_test.go
git commit -m "test(service): add SyncAllConfigs auto-recovery characterization test"
```

### Task 2.9: Run entire test suite and push PR

- [ ] **Step 1: Full test run**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./... -v 2>&1 | tail -40
```

Expected: all tests PASS.

- [ ] **Step 2: Push and open PR**

```bash
cd /opt/stacks/nginxproxyguard
git push -u origin phase2/characterization-tests
gh pr create --title "test: add characterization tests for config generation" --body "$(cat <<'EOF'
## Scope
Phase 2 of codebase-cleanup — characterization tests covering the nginx config generation pipeline. These tests freeze current behavior and protect Phase 3-6 refactors from regression.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §4

## Changes
- `proxy_host_template_characterization_test.go` — 6 cases with golden-file fixtures
- `waf_merge_characterization_test.go` — 4 cases (global/host/merge/empty)
- `advanced_config_characterization_test.go` — 20 cases for directive parser
- `sync_auto_recovery_characterization_test.go` — fake-based auto-recovery loop test
- Fixtures: `api/internal/nginx/testdata/golden/proxy_host_*.conf` (6 files)

## Verification
- [x] `go test ./...` green

## Out of scope
- No production code changes (test-only — refactor safety net)
EOF
)"
```

---

## Phase 3: `main.go` → `bootstrap/` package

**Branch:** `phase3/main-bootstrap`
**PR title:** `refactor(api): extract main.go bootstrap into setup functions`
**Risk:** 🟡 Medium — touches DI assembly, must preserve ordering.

**Prerequisites:** Phase 1 and Phase 2 PRs merged.

### Task 3.1: Create branch and snapshot current main.go

- [ ] **Step 1: Branch off main**

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b phase3/main-bootstrap
```

- [ ] **Step 2: Read current main.go once and annotate mentally (or in a scratch file)**

```bash
wc -l api/cmd/server/main.go
```

Expected: ~988 lines. Identify these logical groups in order (they become the bootstrap files):
1. Config load
2. DB init + migrations
3. Redis/Valkey init
4. Nginx manager init
5. Repositories construction (29 repos)
6. Cache injection (4 specific repos)
7. Services construction + cross-service callback wiring
8. Startup (SyncAllConfigs, GenerateDefaultServerConfig, background services)
9. Handlers construction
10. Schedulers start
11. Echo construction + middleware
12. Echo route registration
13. Graceful shutdown goroutine
14. `e.Start(":" + port)`

### Task 3.2: Create `bootstrap/container.go`

**Files:**
- Create: `api/internal/bootstrap/container.go`

- [ ] **Step 1: Write the skeleton**

```go
package bootstrap

import (
	"context"
	"fmt"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/pkg/cache"
)

// Container holds all constructed dependencies for the API server.
// Build with NewContainer, tear down with Close.
type Container struct {
	Config       *config.Config
	DB           *database.DB
	Cache        *cache.RedisClient
	Nginx        *nginx.Manager
	Repositories *Repositories
	Services     *Services
	Handlers     *Handlers
	Schedulers   *Schedulers
}

// NewContainer assembles the full dependency graph.
// Assembly order: DB → Cache → Nginx → Repositories (+ cache injection)
// → Services (+ callbacks) → Handlers → Schedulers.
func NewContainer(cfg *config.Config) (*Container, error) {
	c := &Container{Config: cfg}

	db, err := InitDB(cfg)
	if err != nil {
		return nil, fmt.Errorf("init db: %w", err)
	}
	c.DB = db

	c.Cache = InitCache(cfg) // returns nil on failure (graceful degradation)

	c.Nginx = nginx.NewManager(cfg)

	c.Repositories = InitRepositories(c.DB, c.Cache)

	c.Services = InitServices(c.Config, c.Repositories, c.Nginx)
	wireServiceCallbacks(c.Services)

	c.Handlers = InitHandlers(c.Services)

	c.Schedulers = NewSchedulers(c.Services)

	return c, nil
}

// Close releases all resources. Always safe to call; idempotent per resource.
func (c *Container) Close() error {
	if c.DB != nil {
		if err := c.DB.Close(); err != nil {
			return fmt.Errorf("close db: %w", err)
		}
	}
	if c.Cache != nil {
		c.Cache.Close()
	}
	return nil
}

// Startup performs post-construction startup: config sync, background services.
func (c *Container) Startup(ctx context.Context) error {
	return runStartup(ctx, c)
}

// StartSchedulers boots all schedulers on their goroutines.
func (c *Container) StartSchedulers(ctx context.Context) {
	c.Schedulers.Start(ctx)
}

// StopAll orchestrates graceful shutdown of all background work.
func (c *Container) StopAll() {
	if c.Schedulers != nil {
		c.Schedulers.Stop()
	}
	c.Services.StopBackgroundServices()
}
```

> **Note:** The exact type of `c.Nginx` (`*nginx.Manager` vs an interface) must match what the production code currently uses. Check with `grep -n "nginxManager\|nginx\.Manager\|nginx\.NewManager" api/cmd/server/main.go`.

### Task 3.3: Create `bootstrap/storage.go`

**Files:**
- Create: `api/internal/bootstrap/storage.go`

- [ ] **Step 1: Move DB init + migration logic**

```go
package bootstrap

import (
	"log"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/pkg/cache"
)

// InitDB connects to the database, runs migrations, and returns the pool.
// Logs success/failure; caller should fatal on error.
func InitDB(cfg *config.Config) (*database.DB, error) {
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	log.Println("Connected to database")

	if err := db.RunMigrations(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// InitCache connects to Valkey/Redis. Returns nil on failure — the system
// runs without cache (graceful degradation).
func InitCache(cfg *config.Config) *cache.RedisClient {
	client, err := cache.NewRedisClient(cfg.RedisURL)
	if err != nil {
		log.Printf("Redis cache unavailable: %v (continuing without cache)", err)
		return nil
	}
	log.Println("Connected to Redis/Valkey cache")
	return client
}
```

### Task 3.4: Create `bootstrap/repositories.go`

**Files:**
- Create: `api/internal/bootstrap/repositories.go`

- [ ] **Step 1: Read current main.go to list all 29 repository constructions in order**

```bash
grep -n "repository\\.New\|:= repository\\." api/cmd/server/main.go
```

- [ ] **Step 2: Write Repositories struct with fields matching each NewXxxRepository call**

```go
package bootstrap

import (
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// Repositories bundles all repository instances. Fields mirror the
// construction order found in the previous main.go.
type Repositories struct {
	ProxyHost        *repository.ProxyHostRepository
	Certificate      *repository.CertificateRepository
	WAF              *repository.WAFRepository
	AccessList       *repository.AccessListRepository
	Geo              *repository.GeoRepository
	RateLimit        *repository.RateLimitRepository
	BotFilter        *repository.BotFilterRepository
	SecurityHeaders  *repository.SecurityHeadersRepository
	Upstream         *repository.UpstreamRepository
	Log              *repository.LogRepository
	RedirectHost     *repository.RedirectHostRepository
	DNSProvider      *repository.DNSProviderRepository
	GlobalSettings   *repository.GlobalSettingsRepository
	SystemSettings   *repository.SystemSettingsRepository
	Dashboard        *repository.DashboardRepository
	Auth             *repository.AuthRepository
	APIToken         *repository.APITokenRepository
	AuditLog         *repository.AuditLogRepository
	Challenge        *repository.ChallengeRepository
	CloudProvider    *repository.CloudProviderRepository
	URIBlock         *repository.URIBlockRepository
	ExploitBlockRule *repository.ExploitBlockRuleRepository
	SystemLog        *repository.SystemLogRepository
	Backup           *repository.BackupRepository
	IPBanHistory     *repository.IPBanHistoryRepository
	GeoIPHistory     *repository.GeoIPHistoryRepository
	FilterSub        *repository.FilterSubscriptionRepository
	// Add others if current main.go has more. Cross-check against grep output.
}

// InitRepositories constructs all repos. If cache is non-nil, injects it into
// the four cache-aware repositories exactly as the previous main.go did.
func InitRepositories(db *database.DB, c *cache.RedisClient) *Repositories {
	r := &Repositories{
		ProxyHost:        repository.NewProxyHostRepository(db),
		Certificate:      repository.NewCertificateRepository(db),
		WAF:              repository.NewWAFRepository(db),
		AccessList:       repository.NewAccessListRepository(db),
		Geo:              repository.NewGeoRepository(db),
		RateLimit:        repository.NewRateLimitRepository(db),
		BotFilter:        repository.NewBotFilterRepository(db),
		SecurityHeaders:  repository.NewSecurityHeadersRepository(db),
		Upstream:         repository.NewUpstreamRepository(db),
		Log:              repository.NewLogRepository(db),
		RedirectHost:     repository.NewRedirectHostRepository(db),
		DNSProvider:      repository.NewDNSProviderRepository(db),
		GlobalSettings:   repository.NewGlobalSettingsRepository(db),
		SystemSettings:   repository.NewSystemSettingsRepository(db),
		Dashboard:        repository.NewDashboardRepository(db),
		Auth:             repository.NewAuthRepository(db),
		APIToken:         repository.NewAPITokenRepository(db),
		AuditLog:         repository.NewAuditLogRepository(db),
		Challenge:        repository.NewChallengeRepository(db),
		CloudProvider:    repository.NewCloudProviderRepository(db),
		URIBlock:         repository.NewURIBlockRepository(db),
		ExploitBlockRule: repository.NewExploitBlockRuleRepository(db),
		SystemLog:        repository.NewSystemLogRepository(db),
		Backup:           repository.NewBackupRepository(db),
		IPBanHistory:     repository.NewIPBanHistoryRepository(db),
		GeoIPHistory:     repository.NewGeoIPHistoryRepository(db),
		FilterSub:        repository.NewFilterSubscriptionRepository(db),
	}

	if c != nil {
		r.ProxyHost.SetCache(c)
		r.GlobalSettings.SetCache(c)
		r.SystemSettings.SetCache(c)
		r.ExploitBlockRule.SetCache(c)
	}

	return r
}
```

### Task 3.5: Create `bootstrap/services.go`

**Files:**
- Create: `api/internal/bootstrap/services.go`

- [ ] **Step 1: List service constructions in current main.go**

```bash
grep -n "service\\.New" api/cmd/server/main.go
```

- [ ] **Step 2: Write Services struct + InitServices + wireServiceCallbacks**

Mirror the order and arguments of each `service.NewXxxService(...)` call. For callbacks, replicate the exact wiring from main.go (search for `SetCertificateReadyCallback`, `SetIPRangesUpdatedCallback`, etc.):

```go
package bootstrap

import (
	"context"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/service"
)

type Services struct {
	Auth             *service.AuthService
	ProxyHost        *service.ProxyHostService
	Certificate      *service.CertificateService
	Security         *service.SecurityService
	Audit            *service.AuditService
	Settings         *service.SettingsService
	// ... fill in every service the previous main.go created.

	// Background services with .Stop() methods:
	LogCollector       *service.LogCollector
	DockerLogCollector *service.DockerLogCollector
	StatsCollector     *service.StatsCollector
	WAFAutoBan         *service.WAFAutoBanService
	Fail2ban           *service.Fail2banService
	CloudProvider      *service.CloudProviderService
	GeoIP              *service.GeoIPService
}

func InitServices(cfg *config.Config, r *Repositories, n *nginx.Manager) *Services {
	// Build in the exact order of the previous main.go.
	// Service constructors receive repos and nginx manager — match signatures.
	s := &Services{}
	s.Audit = service.NewAuditService(r.AuditLog)
	s.Auth = service.NewAuthService(r.Auth /* ...other deps */)
	s.Certificate = service.NewCertificateService(r.Certificate, r.DNSProvider /* ... */)
	s.ProxyHost = service.NewProxyHostService(
		r.ProxyHost, r.WAF, r.AccessList, r.Geo, r.RateLimit,
		r.SecurityHeaders, r.BotFilter, r.Upstream, r.SystemSettings,
		r.CloudProvider, r.GlobalSettings, r.URIBlock, r.ExploitBlockRule,
		r.Certificate, n, s.Certificate, /* ... exact args from main.go */
	)
	// ... continue for remaining services.
	return s
}

// wireServiceCallbacks replicates the cross-service callbacks previously
// set up in main.go to avoid circular package imports.
func wireServiceCallbacks(s *Services) {
	s.Certificate.SetCertificateReadyCallback(func(ctx context.Context, certID string) error {
		return s.ProxyHost.RegenerateConfigsForCertificate(ctx, certID)
	})
	// ... replicate every Set*Callback from main.go.
}

// StopBackgroundServices stops long-running services (those with Stop()).
// Called during graceful shutdown.
func (s *Services) StopBackgroundServices() {
	if s.LogCollector != nil { s.LogCollector.Stop() }
	if s.DockerLogCollector != nil { s.DockerLogCollector.Stop() }
	if s.StatsCollector != nil { s.StatsCollector.Stop() }
	// ... replicate every Stop() call from main.go shutdown.
}
```

> **Note:** This file is the most finicky — exact argument order of `NewProxyHostService(...)` must match. If the signature changes between files, the build will fail fast. Copy-paste from main.go verbatim when in doubt.

### Task 3.6: Create `bootstrap/handlers.go`

**Files:**
- Create: `api/internal/bootstrap/handlers.go`

- [ ] **Step 1: List handlers from current main.go**

```bash
grep -n "handler\\.New" api/cmd/server/main.go
```

- [ ] **Step 2: Write Handlers struct + InitHandlers**

```go
package bootstrap

import "nginx-proxy-guard/internal/handler"

type Handlers struct {
	Auth         *handler.AuthHandler
	ProxyHost    *handler.ProxyHostHandler
	Certificate  *handler.CertificateHandler
	Security     *handler.SecurityHandler
	Settings     *handler.SettingsHandler
	Log          *handler.LogHandler
	Dashboard    *handler.DashboardHandler
	// ...add every handler the previous main.go constructed.
}

func InitHandlers(s *Services) *Handlers {
	return &Handlers{
		Auth:        handler.NewAuthHandler(s.Auth, s.Audit),
		ProxyHost:   handler.NewProxyHostHandler(s.ProxyHost, s.Audit),
		Certificate: handler.NewCertificateHandler(s.Certificate, s.Audit),
		// ...continue for all handlers, preserving arg order from main.go.
	}
}
```

### Task 3.7: Create `bootstrap/routes.go`

**Files:**
- Create: `api/internal/bootstrap/routes.go`

- [ ] **Step 1: Copy route registration block from current main.go**

Identify the entire route-registration block (from the first `e.POST(...)` or `v1 := e.Group(...)` until the last `e.GET(...)` of the API). This block moves into `RegisterRoutes(e, c)` verbatim, with `handler.X` references replaced by `c.Handlers.X`.

- [ ] **Step 2: Write routes.go**

```go
package bootstrap

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/time/rate"

	"nginx-proxy-guard/internal/config"
	authMiddleware "nginx-proxy-guard/internal/middleware"
)

// Add "time" import if the CORS MaxAge field in main.go used it — check current code.

// RegisterMiddleware installs global middleware on the Echo instance.
// Order matches the previous main.go exactly.
func RegisterMiddleware(e *echo.Echo, cfg *config.Config) {
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		// ... copy verbatim from main.go
	}))
	e.Use(middleware.Secure())
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(rate.Limit(100))))
}

// RegisterRoutes wires all API endpoints.
func RegisterRoutes(e *echo.Echo, c *Container) {
	// Health
	e.GET("/health", func(ctx echo.Context) error { return ctx.String(200, "OK") })

	// Public routes
	e.POST("/api/v1/auth/login", c.Handlers.Auth.Login)
	// ... continue for all public endpoints.

	// Protected group
	protected := e.Group("/api/v1")
	protected.Use(authMiddleware.APITokenAuth(c.Services.APIToken))
	protected.Use(authMiddleware.AuthMiddleware(c.Services.Auth))

	protected.GET("/proxy-hosts", c.Handlers.ProxyHost.List)
	protected.POST("/proxy-hosts", c.Handlers.ProxyHost.Create)
	// ... continue for all protected endpoints, preserving order from main.go.
}
```

### Task 3.8: Create `bootstrap/schedulers.go`

**Files:**
- Create: `api/internal/bootstrap/schedulers.go`

- [ ] **Step 1: List scheduler constructions from main.go**

```bash
grep -n "scheduler\\.New" api/cmd/server/main.go
```

- [ ] **Step 2: Write Schedulers struct and methods**

```go
package bootstrap

import (
	"context"

	"nginx-proxy-guard/internal/scheduler"
)

type Schedulers struct {
	Renewal        *scheduler.RenewalScheduler
	Partition      *scheduler.PartitionScheduler
	LogRotate      *scheduler.LogRotateScheduler
	Backup         *scheduler.BackupScheduler
	FilterRefresh  *scheduler.FilterRefreshScheduler
}

func NewSchedulers(s *Services) *Schedulers {
	return &Schedulers{
		Renewal:       scheduler.NewRenewalScheduler(s.Certificate),
		Partition:     scheduler.NewPartitionScheduler(/* repo args */),
		LogRotate:     scheduler.NewLogRotateScheduler(/* ... */),
		Backup:        scheduler.NewBackupScheduler(/* ... */),
		FilterRefresh: scheduler.NewFilterRefreshScheduler(/* ... */),
	}
}

func (s *Schedulers) Start(ctx context.Context) {
	s.Renewal.Start(ctx)
	s.Partition.Start(ctx)
	s.LogRotate.Start(ctx)
	s.Backup.Start(ctx)
	s.FilterRefresh.Start(ctx)
}

func (s *Schedulers) Stop() {
	s.Renewal.Stop()
	s.Partition.Stop()
	s.LogRotate.Stop()
	s.Backup.Stop()
	s.FilterRefresh.Stop()
}
```

### Task 3.9: Create `bootstrap/startup.go`

**Files:**
- Create: `api/internal/bootstrap/startup.go`

- [ ] **Step 1: Move startup logic from main.go**

Identify the block in current main.go that:
1. Calls `proxyHostService.SyncAllConfigs(ctx)` (the retry loop)
2. Calls `GenerateDefaultServerConfig` or similar default server config creation
3. Starts background services (`logCollector.Start(ctx)`, `statsCollector.Start(ctx)`, etc.)

Move them into `runStartup`:

```go
package bootstrap

import (
	"context"
	"log"
)

// runStartup performs one-time post-construction startup:
//   1. Sync all proxy host configs (with auto-recovery)
//   2. Generate default server config (catch-all)
//   3. Start long-running background services
func runStartup(ctx context.Context, c *Container) error {
	if err := c.Services.ProxyHost.SyncAllConfigs(ctx); err != nil {
		log.Printf("SyncAllConfigs returned: %v (continuing, per auto-recovery)", err)
	}

	if err := c.Services.ProxyHost.GenerateDefaultServerConfig(ctx); err != nil {
		return err
	}

	// Start background services (non-blocking; they run their own goroutines).
	go c.Services.LogCollector.Start(ctx)
	go c.Services.DockerLogCollector.Start(ctx)
	go c.Services.StatsCollector.Start(ctx)
	go c.Services.WAFAutoBan.Start(ctx)
	go c.Services.Fail2ban.Start(ctx)
	go c.Services.CloudProvider.Start(ctx)
	go c.Services.GeoIP.Start(ctx)

	return nil
}
```

### Task 3.10: Rewrite `main.go`

**Files:**
- Rewrite: `api/cmd/server/main.go`

- [ ] **Step 1: Replace entire file content**

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/bootstrap"
	"nginx-proxy-guard/internal/config"
)

func main() {
	cfg := config.Load()

	c, err := bootstrap.NewContainer(cfg)
	if err != nil {
		log.Fatalf("container init: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())

	if err := c.Startup(ctx); err != nil {
		log.Fatalf("startup: %v", err)
	}

	e := echo.New()
	bootstrap.RegisterMiddleware(e, cfg)
	bootstrap.RegisterRoutes(e, c)

	c.StartSchedulers(ctx)

	go handleShutdown(cancel, c, e)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func handleShutdown(cancel context.CancelFunc, c *bootstrap.Container, e *echo.Echo) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	cancel()
	c.StopAll()
	_ = e.Close()
}
```

- [ ] **Step 2: Verify line count**

```bash
wc -l api/cmd/server/main.go
```

Expected: ≤200 lines.

### Task 3.11: Iterate build until green

- [ ] **Step 1: Attempt to build**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml build api 2>&1 | tail -60
```

First pass will likely reveal mismatched signatures in `services.go`, `handlers.go`, or `routes.go`. Fix each compile error by returning to the faulty file and correcting the arg order, type, or missing field.

- [ ] **Step 2: Iterate until build succeeds**

Expected final output: `npg-api` image built successfully.

### Task 3.12: Run the test suite

- [ ] **Step 1: Phase 2 characterization tests must pass**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./internal/nginx/... ./internal/service/... -v 2>&1 | tail -30
```

All Phase 2 tests PASS. If any fail, investigate wiring (a callback may be missed).

- [ ] **Step 2: Full go test suite**

```bash
go test ./... 2>&1 | tail -20
```

### Task 3.13: Runtime smoke test

- [ ] **Step 1: Bring up dev stack**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml up -d
sleep 10
docker compose -f docker-compose.dev.yml logs api 2>&1 | tail -40
```

Expected: `Connected to database`, `Connected to Redis/Valkey cache`, `Starting server on port 8080`, no panics.

- [ ] **Step 2: Tear down**

```bash
docker compose -f docker-compose.dev.yml down
```

### Task 3.14: E2E test run

- [ ] **Step 1: Build + start E2E environment**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.e2e-test.yml build --no-cache api ui
docker compose -f docker-compose.e2e-test.yml up -d
sleep 20
```

- [ ] **Step 2: Run full E2E suite**

```bash
cd test/e2e
npx playwright test 2>&1 | tail -30
```

Expected: all specs green. If any fail, investigate — the refactor must not change behavior.

- [ ] **Step 3: Tear down**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.e2e-test.yml down -v
```

### Task 3.15: Commit and push PR

- [ ] **Step 1: Stage changes**

```bash
git add api/
git status
git commit -m "refactor(api): extract main.go bootstrap into setup functions"
```

- [ ] **Step 2: Push and open PR**

```bash
git push -u origin phase3/main-bootstrap
gh pr create --title "refactor(api): extract main.go bootstrap into setup functions" --body "$(cat <<'EOF'
## Scope
Phase 3 of codebase-cleanup — extract DI assembly into `internal/bootstrap/` package.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §5

## Changes
- New package `api/internal/bootstrap/` (8 files)
- `main.go` shrunk from ~988 lines to ~170 lines
- DI order preserved: DB → Cache → Nginx → Repos (cache inject 4) → Services (callbacks) → Handlers → Routes → Schedulers

## Verification
- [x] `go test ./...` green (Phase 2 tests pass)
- [x] `docker compose -f docker-compose.dev.yml up -d api` starts cleanly
- [x] Full E2E suite green

## Out of scope
- No behavior changes — pure structural refactor
EOF
)"
```

---

## Phase 4a: `proxy_host_template.go` split via `embed.FS`

**Branch:** `phase4a/template-split`
**PR title:** `refactor(api): split proxy_host_template by section`
**Risk:** 🟡 Medium — protected by Phase 2 golden-file tests (bit-identical output required).

**Prerequisites:** Phase 2 and Phase 3 PRs merged.

### Task 4a.1: Create branch

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b phase4a/template-split
```

### Task 4a.2: Read current template string

- [ ] **Step 1: Find the huge template literal**

```bash
wc -l api/internal/nginx/proxy_host_template.go
grep -n "const.*Template\|var.*Template\|\`" api/internal/nginx/proxy_host_template.go | head -20
```

Identify the package-level constant/variable that holds the nginx server config as a Go raw string literal (backticks).

- [ ] **Step 2: Extract entire template body to a scratch file for section-splitting**

```bash
# Pipe the raw template through:
awk '/^const .*Template.*=/{flag=1; next} flag && /^\`/{flag=0} flag' api/internal/nginx/proxy_host_template.go > /tmp/current_template.txt
wc -l /tmp/current_template.txt
```

(Adjust the awk pattern if the template uses `var` + backticks or a different delimiter.)

### Task 4a.3: Create templates directory

- [ ] **Step 1: Create directory**

```bash
mkdir -p api/internal/nginx/templates/proxy_host
```

### Task 4a.4: Split template into section files

**Files:**
- Create: `api/internal/nginx/templates/proxy_host/base.conf.tmpl`
- Create: 8 additional `.conf.tmpl` files

- [ ] **Step 1: Identify natural section boundaries in the original template**

Read `/tmp/current_template.txt` (or the raw string in source). Find these logical blocks — they become separate template files with `{{define "sectionname"}}...{{end}}`:

| Section | What goes in | Example directives |
|---------|--------------|--------------------|
| `ssl` | HTTPS listener, SSL cert refs, HTTP/2, HTTP/3, force HTTPS | `listen 443 ssl;`, `ssl_certificate`, `ssl_protocols`, `add_header Strict-Transport-Security` |
| `waf` | ModSecurity include | `modsecurity_rules_file host_{{.ID}}.conf;` |
| `cache` | Proxy cache directives | `proxy_cache`, `proxy_cache_valid`, `proxy_cache_key` |
| `upstream` | Upstream block + LB strategy | `upstream {...} { least_conn; server ... }` |
| `security_headers` | HSTS, XFO, CSP, etc. | `add_header X-Frame-Options` |
| `access_list` | Allow/deny list | `allow 10.0.0.0/8;`, `deny all;` |
| `location_defaults` | `block_exploits`, `client_max_body_size`, proxy timeouts — all `hasDirective`-guarded | `{{if not (hasDirective . "client_max_body_size")}}client_max_body_size ...{{end}}` |
| `advanced` | Raw user config | `{{.AdvancedConfig}}` |
| `base` | The server block skeleton that pulls the others in | `server { ... {{template "ssl" .}} ... }` |

- [ ] **Step 2: Write each section file**

For each of the 9 files, write a Go template with a `{{define "sectionname"}}` wrapper and the directives for that section.

Example `api/internal/nginx/templates/proxy_host/ssl.conf.tmpl`:

```
{{define "ssl"}}
{{if .SSLEnabled}}
    listen 443 ssl{{if .SSLHTTP2}} http2{{end}}{{if .SSLHTTP3}} quic{{end}};
    listen [::]:443 ssl{{if .SSLHTTP2}} http2{{end}}{{if .SSLHTTP3}} quic{{end}};

    ssl_certificate /etc/nginx/certs/{{.CertificateID}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{.CertificateID}}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    {{if .SSLForceHTTPS}}
    add_header Strict-Transport-Security "max-age={{/* HSTSMaxAge */}}31536000; includeSubDomains" always;
    {{end}}
{{end}}
{{end}}
```

> **CRITICAL:** The output must be BYTE-IDENTICAL to the existing template for the 6 Phase 2 golden fixtures. Match existing whitespace, including leading spaces, blank lines, and trailing newlines. This is tedious but essential — Phase 2 will catch any deviation.

- [ ] **Step 3: Write base.conf.tmpl**

`api/internal/nginx/templates/proxy_host/base.conf.tmpl`:

```
{{define "base"}}
server {
    set $forward_scheme {{.ForwardScheme}};
    set $server         "{{.ForwardHost}}";
    set $port           {{.ForwardPort}};

    server_name {{range .DomainNames}}{{.}} {{end}};

    {{template "ssl" .}}
    {{template "cache" .}}
    {{template "security_headers" .}}
    {{template "access_list" .}}
    {{template "waf" .}}

    location / {
        {{template "location_defaults" .}}

        proxy_pass $forward_scheme://$server:$port;
        include /etc/nginx/includes/proxy_params.conf;
    }

    {{template "advanced" .}}
}
{{end}}
```

(Exact structure must match the original server block. Copy verbatim from the scratch file, only replacing bodies with `{{template "..." .}}` where appropriate.)

### Task 4a.5: Rewrite `proxy_host_template.go` to use embed.FS

**Files:**
- Rewrite: `api/internal/nginx/proxy_host_template.go`

- [ ] **Step 1: Replace the entire file**

```go
package nginx

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	text_template "text/template"
	// Adjust imports to match what the rest of the package needs.
)

//go:embed templates/proxy_host/*.tmpl
var proxyHostTemplatesFS embed.FS

var proxyHostTemplate = text_template.Must(
	text_template.New("base").
		Funcs(proxyHostFuncMap).
		ParseFS(proxyHostTemplatesFS, "templates/proxy_host/*.tmpl"),
)

// proxyHostFuncMap is the template function registry.
// Preserves pre-refactor helpers: hasDirective, safe, etc.
var proxyHostFuncMap = text_template.FuncMap{
	"hasDirective": hasDirective,
	"safe":         func(s string) template.HTML { return template.HTML(s) },
	// ...add every helper the previous template used.
}

// GenerateConfigFull renders the server block for a single proxy host.
// External API unchanged from the pre-refactor version.
func (m *Manager) GenerateConfigFull(ctx context.Context, data ProxyHostData) error {
	var buf bytes.Buffer
	if err := proxyHostTemplate.ExecuteTemplate(&buf, "base", data); err != nil {
		return fmt.Errorf("render proxy host config: %w", err)
	}
	configPath := m.configPathFor(data)
	return m.writeFileAtomic(configPath, buf.Bytes(), 0644)
}

// Preserve any other exported functions the file previously had (e.g.,
// parseAdvancedConfigDirectives, hasDirective helper) — move them here
// unchanged if they were in this file.
```

> **Note:** If the previous file defined `parseAdvancedConfigDirectives` or similar helpers, keep them in this file — only the template body moves out. The Go function definitions stay.

- [ ] **Step 2: Verify file size**

```bash
wc -l api/internal/nginx/proxy_host_template.go
```

Expected: ≤400 lines (from 1931).

### Task 4a.6: Run Phase 2 golden tests — iterate until byte-identical

- [ ] **Step 1: Run the golden-file tests**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./internal/nginx/ -run TestProxyHostTemplate_Characterization -v 2>&1 | head -80
```

Expected: all 6 cases PASS. Realistically, first pass fails due to whitespace drift.

- [ ] **Step 2: For each failing case, inspect the diff**

The test output will show `--- got ---` vs `--- want ---`. Identify the whitespace or content mismatch and fix the corresponding `.conf.tmpl` file.

- [ ] **Step 3: Repeat until all 6 cases pass WITHOUT using `-update-golden`**

If output is intentionally different (e.g., a newline difference that's semantically equivalent and the current golden is wrong), document the exact change in a commit message and regenerate goldens with `-update-golden`. This should be rare.

### Task 4a.7: Full test suite + E2E

- [ ] **Step 1: Full go test**

```bash
go test ./... 2>&1 | tail -20
```

- [ ] **Step 2: Build and E2E**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.e2e-test.yml build --no-cache api
docker compose -f docker-compose.e2e-test.yml up -d
sleep 20
cd test/e2e
npx playwright test specs/ 2>&1 | tail -20
cd ..
docker compose -f docker-compose.e2e-test.yml down -v
```

Expected: all green, particularly the proxy-host and WAF specs.

### Task 4a.8: Commit and push PR

```bash
cd /opt/stacks/nginxproxyguard
git add api/internal/nginx/
git commit -m "refactor(api): split proxy_host_template by section"
git push -u origin phase4a/template-split
gh pr create --title "refactor(api): split proxy_host_template by section" --body "$(cat <<'EOF'
## Scope
Phase 4a of codebase-cleanup — split 1931-line proxy_host template into 9 section files via embed.FS.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §6

## Changes
- `templates/proxy_host/*.tmpl` (9 new files: base, ssl, waf, cache, upstream, security_headers, access_list, location_defaults, advanced)
- `proxy_host_template.go` rewritten to use `embed.FS` + `ParseFS` (1931 → ~300 lines)
- External API unchanged: `Manager.GenerateConfigFull(ctx, data)` signature identical

## Verification
- [x] Phase 2 golden-file tests byte-identical
- [x] Full go test suite green
- [x] E2E proxy-host + WAF specs green

## Out of scope
- No rendering logic changes — template body identical byte-for-byte vs prior version
EOF
)"
```

---

## Phase 4b: Oversized Repository Split (5 repos)

**Branch:** `phase4b/repo-split`
**PR title:** `refactor(api): split oversized repositories`
**Risk:** 🟡 Medium — same-package, same-struct, same-method signatures; safe mechanical refactor.

**Prerequisites:** Phase 3 PR merged (Phase 2 is strictly speaking the test gatekeeper, but Phase 3 should land first to align with bootstrap/repositories.go references).

### Task 4b.1: Create branch

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b phase4b/repo-split
```

### Task 4b.2: Split `log.go` into 5 files

**Files:**
- Modify: `api/internal/repository/log.go`
- Create: `api/internal/repository/log_queries.go`
- Create: `api/internal/repository/log_stats.go`
- Create: `api/internal/repository/log_settings.go`
- Create: `api/internal/repository/log_cleanup.go`

- [ ] **Step 1: Inventory current methods**

```bash
grep -n "^func (r \*LogRepository)\|^func (r \*LogRepository)" api/internal/repository/log.go
```

- [ ] **Step 2: Classify each method into 5 buckets**

- `log.go` (kept): `NewLogRepository`, `Create`, `CreateBatch`, `GetByID`, `Delete`, core `List` helpers
- `log_queries.go`: `GetDistinctHosts`, `GetDistinctClientIPs`, `GetDistinctUserAgents`, `GetDistinctCountries`, `GetDistinctStatusCodes`, `GetDistinctUpstreamAddrs` (or similar 6)
- `log_stats.go`: `GetStats`, any time-series/aggregate queries
- `log_settings.go`: `GetSettings`, `UpdateSettings`
- `log_cleanup.go`: `Cleanup`, retention helpers, partition-drop calls

Write the classification mapping as comments at the top of each new file.

- [ ] **Step 3: Create `log_queries.go`**

```go
package repository

import (
	"context"
	"database/sql"
)

// Distinct-value lookups used by log filter UI.
// Moved from log.go during Phase 4b repo split.

func (r *LogRepository) GetDistinctHosts(ctx context.Context) ([]string, error) {
	// MOVE body verbatim from log.go
}

func (r *LogRepository) GetDistinctClientIPs(ctx context.Context) ([]string, error) {
	// MOVE body verbatim from log.go
}

// ... continue for all 6 distinct queries.

// Keep this import or strip if unused; re-check after move.
var _ = sql.ErrNoRows
```

Move the actual function bodies verbatim from `log.go`.

- [ ] **Step 4: Create `log_stats.go`, `log_settings.go`, `log_cleanup.go`**

Same pattern: move matching methods verbatim, keep package import block correct.

- [ ] **Step 5: Slim down `log.go`**

In `log.go`, delete the methods that moved. Keep: struct definition, `NewLogRepository`, `SetCache` (if any), core CRUD (`Create`, `CreateBatch`, `GetByID`, `Delete`, base `List`).

- [ ] **Step 6: Verify line counts**

```bash
wc -l api/internal/repository/log*.go
```

Each file ≤500 lines ideally, certainly ≤800.

- [ ] **Step 7: Build**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml build api 2>&1 | tail -30
```

Fix any compile errors (most commonly: method that references a helper still in `log.go` — the helper must either move too or be exported).

### Task 4b.3: Split `backup_export.go`

**Files:**
- Modify: `api/internal/repository/backup_export.go`
- Create: `api/internal/repository/backup_export_proxy.go`
- Create: `api/internal/repository/backup_export_security.go`
- Create: `api/internal/repository/backup_export_settings.go`

- [ ] **Step 1: Inventory ExportAllData's sub-calls**

```bash
grep -n "^func\|exportProxyHost\|exportCertificate\|exportWAF\|exportAccessList\|exportSettings\|exportUser" api/internal/repository/backup_export.go | head -40
```

- [ ] **Step 2: Classify helpers by domain**

- `backup_export.go` (kept): `ExportAllData` orchestrator, pagination/transaction helpers
- `backup_export_proxy.go`: `exportProxyHosts`, `exportRedirectHosts`, `exportCertificates`, `exportDNSProviders`, `exportUpstreams`
- `backup_export_security.go`: `exportAccessLists`, `exportBotFilters`, `exportRateLimits`, `exportWAFRules`, `exportWAFExclusions`, `exportExploitRules`, `exportCloudProviders`, `exportBannedIPs`
- `backup_export_settings.go`: `exportGlobalSettings`, `exportSystemSettings`, `exportUsers`, `exportAPITokens`, `exportFilterSubscriptions`, `exportChallengeConfigs`

- [ ] **Step 3: Move helpers to new files**

For each helper, move verbatim to the appropriate new file. Keep the function visibility (`exportXxx` stays unexported; same-package calls work).

- [ ] **Step 4: Slim backup_export.go**

Keep only `ExportAllData` and any pure orchestration helpers.

- [ ] **Step 5: Verify line counts + build**

```bash
wc -l api/internal/repository/backup_export*.go
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml build api 2>&1 | tail -20
```

### Task 4b.4: Split `backup_import.go`

**Files:**
- Modify: `api/internal/repository/backup_import.go`
- Create: `api/internal/repository/backup_import_proxy.go`
- Create: `api/internal/repository/backup_import_security.go`
- Create: `api/internal/repository/backup_import_settings.go`

- [ ] **Step 1: Apply the same split pattern as Task 4b.3 for import**

- `backup_import.go` (kept): `ImportAllData` orchestrator + transaction management
- `backup_import_proxy.go`: proxy hosts, redirects, certs, DNS, upstreams
- `backup_import_security.go`: access lists, bot filters, rate limits, WAF rules, exploit rules, cloud providers, banned IPs. **CRITICAL:** preserve CHECK-constraint fallback logic (e.g., `if wafParanoiaLevel < 1 { wafParanoiaLevel = 1 }`) in whichever file it lived before — add a comment noting the compliance reason.
- `backup_import_settings.go`: global/system settings, users, API tokens, filter subs, challenge configs

- [ ] **Step 2: Verify CHECK constraint fallback lives in backup_import_security.go**

```bash
grep -n "waf_paranoia_level\|wafParanoiaLevel\|waf_anomaly_threshold\|anomaly_threshold" api/internal/repository/backup_import_security.go
```

Must find the defaulting logic. If not, it got lost in the move — restore.

- [ ] **Step 3: Build**

```bash
docker compose -f docker-compose.dev.yml build api 2>&1 | tail -20
```

### Task 4b.5: Split `proxy_host.go`

**Files:**
- Modify: `api/internal/repository/proxy_host.go`
- Create: `api/internal/repository/proxy_host_queries.go`
- Create: `api/internal/repository/proxy_host_favorites.go`

- [ ] **Step 1: Inventory methods**

```bash
grep -n "^func (r \*ProxyHostRepository)" api/internal/repository/proxy_host.go
```

- [ ] **Step 2: Classify**

- `proxy_host.go` (kept): struct, `NewProxyHostRepository`, `SetCache`, `Create`, `Update`, `Delete`, `GetByID`, `GetByDomain` (core CRUD)
- `proxy_host_queries.go`: `List` (with pagination/sort/search), `GetByCertificateID`, `GetForCloudProvider` (if present), any other list/filter methods
- `proxy_host_favorites.go`: `ToggleFavorite` and any favorite-list helpers

- [ ] **Step 3: Move and verify**

Move verbatim, then:
```bash
wc -l api/internal/repository/proxy_host*.go
docker compose -f docker-compose.dev.yml build api 2>&1 | tail -10
```

### Task 4b.6: Split `waf.go`

**Files:**
- Modify: `api/internal/repository/waf.go`
- Create: `api/internal/repository/waf_exclusions.go`
- Create: `api/internal/repository/waf_snapshots.go`

- [ ] **Step 1: Inventory**

```bash
grep -n "^func (r \*WAFRepository)" api/internal/repository/waf.go
```

- [ ] **Step 2: Classify**

- `waf.go` (kept): struct, constructor, `GetHostConfig` (core read)
- `waf_exclusions.go`: `CreateExclusion`, `DeleteExclusion`, `GetGlobalExclusions`, `GetHostExclusions`, `UpdateExclusion`, all CRUD on `waf_rule_exclusions` + `global_waf_rule_exclusions`
- `waf_snapshots.go`: snapshots + change events — `CreateSnapshot`, `ListSnapshots`, `GetSnapshotDetails`, `LogRuleChangeEvent`

- [ ] **Step 3: Move and verify**

```bash
wc -l api/internal/repository/waf*.go
docker compose -f docker-compose.dev.yml build api 2>&1 | tail -10
```

### Task 4b.7: Add backup roundtrip test

**Files:**
- Create: `api/internal/repository/backup_roundtrip_test.go`

- [ ] **Step 1: Write test using real (or in-memory) database**

```go
package repository

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestBackupRoundtrip verifies that export→import preserves every field.
// Uses the live integration test DB (see api/tests/integration/api_suite_test.go
// for the harness pattern). If that harness is unavailable, skip the test.
func TestBackupRoundtrip(t *testing.T) {
	testdataFile := filepath.Join("testdata", "backup_v2.9.1.json")
	if _, err := os.Stat(testdataFile); os.IsNotExist(err) {
		t.Skip("no backup fixture; create testdata/backup_v2.9.1.json by running full export on a populated dev DB")
	}

	rawBefore, err := os.ReadFile(testdataFile)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Set up a test DB and repo (reuse test harness pattern if available).
	db := setupTestDB(t)
	defer db.Close()

	exportRepo := NewBackupExportRepository(db)
	importRepo := NewBackupImportRepository(db)

	// Import the fixture
	if err := importRepo.ImportAllData(context.Background(), rawBefore); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Re-export
	rawAfter, err := exportRepo.ExportAllData(context.Background())
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Compare (ignore ID regeneration if applicable)
	var before, after map[string]any
	_ = json.Unmarshal(rawBefore, &before)
	_ = json.Unmarshal(rawAfter, &after)

	// Check key table counts match
	for _, table := range []string{"proxy_hosts", "certificates", "access_lists", "waf_rule_exclusions"} {
		b := len(before[table].([]any))
		a := len(after[table].([]any))
		if a != b {
			t.Errorf("%s: before=%d, after=%d", table, b, a)
		}
	}
}

// setupTestDB — fill in based on existing integration harness.
```

> **Note:** If the test harness (`setupTestDB`) is not readily accessible, mark the test `t.Skip("harness pending")` and file a follow-up issue. The test structure is still valuable as a template.

### Task 4b.8: Full test run + E2E

- [ ] **Step 1: go test all**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./... 2>&1 | tail -20
```

- [ ] **Step 2: E2E backup + proxy-host + WAF specs**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.e2e-test.yml build --no-cache api
docker compose -f docker-compose.e2e-test.yml up -d
sleep 20
cd test/e2e
npx playwright test specs/settings/backup.spec.ts specs/proxy-host/ specs/security/ 2>&1 | tail -30
cd ..
docker compose -f docker-compose.e2e-test.yml down -v
```

### Task 4b.9: Commit and PR

```bash
git add api/internal/repository/
git commit -m "refactor(api): split oversized repositories"
git push -u origin phase4b/repo-split
gh pr create --title "refactor(api): split oversized repositories" --body "$(cat <<'EOF'
## Scope
Phase 4b of codebase-cleanup — split 5 repositories >800 LOC into focused files.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §7

## Changes
- `log.go` (1687) → 5 files (log, log_queries, log_stats, log_settings, log_cleanup)
- `backup_export.go` (1115) → 4 files
- `backup_import.go` (961) → 4 files (security file retains CHECK-constraint fallback)
- `proxy_host.go` (1086) → 3 files (proxy_host, _queries, _favorites)
- `waf.go` (944) → 3 files (waf, _exclusions, _snapshots)
- New: `backup_roundtrip_test.go`
- All public method signatures unchanged

## Verification
- [x] Phase 2 characterization tests green
- [x] `go test ./...` green
- [x] E2E backup + proxy-host + WAF specs green

## Out of scope
- No behavior changes — pure file reorganization
EOF
)"
```

---

## Phase 5: UI Component Split (10 files)

**Branch:** `phase5/ui-component-split`
**PR title:** `refactor(ui): split large components below 600 LOC`
**Risk:** 🟡 Medium — protected by existing E2E suite.

**Prerequisites:** Phase 1 PR merged. (Independent of backend phases.)

### Task 5.1: Create branch

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b phase5/ui-component-split
```

### Task 5.2: Split `LogViewer.tsx` (825 → ≤500)

**Files:**
- Modify: `ui/src/components/LogViewer.tsx`
- Create: `ui/src/components/log-viewer/LogTable.tsx`
- Create: `ui/src/components/log-viewer/LogToolbar.tsx`
- Create: `ui/src/components/log-viewer/useLogQuery.ts`

- [ ] **Step 1: Read current LogViewer.tsx to identify responsibilities**

```bash
wc -l ui/src/components/LogViewer.tsx
```

Identify three chunks:
1. Data fetching + query parameters + pagination state → `useLogQuery` hook
2. Table rendering (rows, columns, infinite scroll) → `LogTable`
3. Top toolbar (refresh, export, filter toggle) → `LogToolbar`

- [ ] **Step 2: Create `useLogQuery.ts`**

```tsx
// ui/src/components/log-viewer/useLogQuery.ts
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchLogs } from '@/api/logs';
import type { LogFilters, LogEntry } from '@/types/log';

export function useLogQuery(initialFilters: LogFilters) {
  const [filters, setFilters] = useState<LogFilters>(initialFilters);
  const [page, setPage] = useState(1);

  const query = useQuery({
    queryKey: ['logs', filters, page],
    queryFn: () => fetchLogs(filters, page),
  });

  return {
    logs: query.data?.items ?? [],
    total: query.data?.total ?? 0,
    page, setPage,
    filters, setFilters,
    isLoading: query.isLoading,
    refetch: query.refetch,
  };
}
```

Move the data-fetching state/logic verbatim from LogViewer.tsx.

- [ ] **Step 3: Create `LogTable.tsx`**

```tsx
// ui/src/components/log-viewer/LogTable.tsx
import type { LogEntry } from '@/types/log';

type Props = {
  logs: LogEntry[];
  onRowClick: (log: LogEntry) => void;
};

export function LogTable({ logs, onRowClick }: Props) {
  // Move JSX for table rendering verbatim from LogViewer.tsx
  return (
    <table className="..."> {/* ... */}</table>
  );
}
```

- [ ] **Step 4: Create `LogToolbar.tsx`**

```tsx
// ui/src/components/log-viewer/LogToolbar.tsx
type Props = {
  onRefresh: () => void;
  onExport: () => void;
  onToggleFilters: () => void;
};

export function LogToolbar({ onRefresh, onExport, onToggleFilters }: Props) {
  return (
    <div className="..."> {/* move verbatim from LogViewer */}</div>
  );
}
```

- [ ] **Step 5: Rewrite `LogViewer.tsx` as thin composer**

```tsx
import { useLogQuery } from './log-viewer/useLogQuery';
import { LogTable } from './log-viewer/LogTable';
import { LogToolbar } from './log-viewer/LogToolbar';
// ...existing imports

export function LogViewer() {
  const { logs, filters, setFilters, refetch } = useLogQuery(defaultFilters);
  const [showFilters, setShowFilters] = useState(false);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);

  return (
    <div>
      <LogToolbar
        onRefresh={refetch}
        onExport={() => /* existing export logic */}
        onToggleFilters={() => setShowFilters(s => !s)}
      />
      {showFilters && <LogFilters filters={filters} onChange={setFilters} />}
      <LogTable logs={logs} onRowClick={setSelectedLog} />
      {selectedLog && <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}
```

- [ ] **Step 6: Verify build**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml build ui 2>&1 | tail -15
```

Fix any import errors.

- [ ] **Step 7: Verify line counts**

```bash
wc -l ui/src/components/LogViewer.tsx ui/src/components/log-viewer/LogTable.tsx ui/src/components/log-viewer/LogToolbar.tsx ui/src/components/log-viewer/useLogQuery.ts
```

Expected: all ≤500.

### Task 5.3: Split `ExploitBlockLogs.tsx` (799 → ≤500)

**Files:**
- Modify: `ui/src/components/ExploitBlockLogs.tsx`
- Create: `ui/src/components/exploit-block-logs/ExploitLogTable.tsx`
- Create: `ui/src/components/exploit-block-logs/ExploitLogFilters.tsx`
- Create: `ui/src/components/exploit-block-logs/ExploitLogDetailModal.tsx`

- [ ] **Step 1: Create directory**

```bash
mkdir -p ui/src/components/exploit-block-logs
```

- [ ] **Step 2: Extract the detail modal first (large block)**

Read ExploitBlockLogs.tsx, identify the detail modal JSX + state. Move to `ExploitLogDetailModal.tsx`:

```tsx
import type { ExploitLogEntry } from '@/types/log';
import { useEscapeKey } from '@/hooks/useEscapeKey';

type Props = { log: ExploitLogEntry; onClose: () => void };

export function ExploitLogDetailModal({ log, onClose }: Props) {
  useEscapeKey(onClose);
  return <div className="fixed inset-0 bg-black/50 ...">{/* move JSX */}</div>;
}
```

- [ ] **Step 3: Extract filters**

```tsx
// ExploitLogFilters.tsx
type Props = { filters: ExploitFilters; onChange: (f: ExploitFilters) => void };
export function ExploitLogFilters({ filters, onChange }: Props) {
  return <div>{/* move filter UI */}</div>;
}
```

- [ ] **Step 4: Extract table**

```tsx
// ExploitLogTable.tsx
type Props = { logs: ExploitLogEntry[]; onRowClick: (l: ExploitLogEntry) => void };
export function ExploitLogTable({ logs, onRowClick }: Props) {
  return <table>{/* move table */}</table>;
}
```

- [ ] **Step 5: Rewrite ExploitBlockLogs.tsx as composer**

- [ ] **Step 6: Verify build + line counts**

```bash
docker compose -f docker-compose.dev.yml build ui 2>&1 | tail -10
wc -l ui/src/components/ExploitBlockLogs.tsx ui/src/components/exploit-block-logs/*.tsx
```

### Task 5.4: Split `LogDetailModal.tsx` (709 → ≤500)

**Files:**
- Modify: `ui/src/components/log-viewer/modals/LogDetailModal.tsx`
- Create: `ui/src/components/log-viewer/modals/LogDetailHeader.tsx`
- Create: `ui/src/components/log-viewer/modals/LogDetailBody.tsx`
- Create: `ui/src/components/log-viewer/modals/LogRawBlock.tsx`

- [ ] **Step 1: Extract header (top badge + title + close button)**

```tsx
type Props = { log: LogEntry; onClose: () => void };
export function LogDetailHeader({ log, onClose }: Props) {
  return <div className="flex justify-between ...">{/* move verbatim */}</div>;
}
```

- [ ] **Step 2: Extract raw block (expandable JSON/text viewer)**

```tsx
export function LogRawBlock({ data }: { data: string }) {
  const [expanded, setExpanded] = useState(false);
  return <pre>{/* move */}</pre>;
}
```

- [ ] **Step 3: Extract body (structured field display)**

```tsx
export function LogDetailBody({ log }: { log: LogEntry }) {
  return <div>{/* move */}</div>;
}
```

- [ ] **Step 4: Rewrite LogDetailModal as composer + verify build**

### Task 5.5: Split `BackupManager.tsx` (687 → ≤500)

**Files:**
- Modify: `ui/src/components/BackupManager.tsx`
- Create: `ui/src/components/backup/BackupList.tsx`
- Create: `ui/src/components/backup/BackupActions.tsx`
- Create: `ui/src/components/backup/BackupScheduleCard.tsx`

- [ ] **Step 1: Create directory + subcomponents**

```bash
mkdir -p ui/src/components/backup
```

Three extractions:
- `BackupList` — table of backup files with download/delete buttons
- `BackupActions` — create/restore/upload top bar
- `BackupScheduleCard` — schedule config form (if present)

- [ ] **Step 2: Move + rewrite + verify**

```bash
docker compose -f docker-compose.dev.yml build ui 2>&1 | tail -10
wc -l ui/src/components/BackupManager.tsx ui/src/components/backup/*.tsx
```

### Task 5.6: Split `APITokenManager.tsx` (653 → ≤500)

**Files:**
- Modify: `ui/src/components/APITokenManager.tsx`
- Create: `ui/src/components/api-token/TokenList.tsx`
- Create: `ui/src/components/api-token/TokenCreateModal.tsx`
- Create: `ui/src/components/api-token/TokenUsageModal.tsx`

- [ ] **Step 1: Create directory + 3 subcomponents**

```bash
mkdir -p ui/src/components/api-token
```

Extractions:
- `TokenList` — table of existing tokens with revoke action
- `TokenCreateModal` — create form with permission checkboxes
- `TokenUsageModal` — per-token usage log viewer

- [ ] **Step 2: Move + verify**

### Task 5.7: Split `FilterSubscriptionList.tsx` (640 → ≤500)

**Files:**
- Modify: `ui/src/components/FilterSubscriptionList.tsx`
- Create: `ui/src/components/filter-subscription/SubscriptionTable.tsx`
- Create: `ui/src/components/filter-subscription/SubscriptionForm.tsx`
- Create: `ui/src/components/filter-subscription/SubscriptionActions.tsx`

- [ ] **Step 1: Create directory + subcomponents**

```bash
mkdir -p ui/src/components/filter-subscription
```

Extractions:
- `SubscriptionTable` — list of subscriptions
- `SubscriptionForm` — add/edit modal form
- `SubscriptionActions` — refresh / bulk actions toolbar

### Task 5.8: Split `AccountSettings.tsx` (623 → ≤500)

**Files:**
- Modify: `ui/src/components/AccountSettings.tsx`
- Create: `ui/src/components/account/ProfileTab.tsx`
- Create: `ui/src/components/account/PasswordTab.tsx`
- Create: `ui/src/components/account/TwoFactorTab.tsx`
- Create: `ui/src/components/account/LanguageFontTab.tsx`

- [ ] **Step 1: Create directory**

```bash
mkdir -p ui/src/components/account
```

- [ ] **Step 2: Extract each tab as a separate component**

Identify tab sections in AccountSettings.tsx. Each tab's JSX + state becomes a file.

- [ ] **Step 3: Rewrite AccountSettings.tsx as tab container + verify**

### Task 5.9: Split `LogFilters.tsx` (621 → ≤500)

**Files:**
- Modify: `ui/src/components/log/LogFilters.tsx`
- Create: `ui/src/components/log/BasicFilters.tsx`
- Create: `ui/src/components/log/AdvancedFilters.tsx`
- Create: `ui/src/components/log/FilterActions.tsx`

- [ ] **Step 1: Split by section**

- `BasicFilters` — date range, host, status code
- `AdvancedFilters` — IP, user agent, country, referer
- `FilterActions` — apply/clear/save filter buttons

### Task 5.10: Split `ProxyHostList.tsx` (615 → ≤500)

**Files:**
- Modify: `ui/src/components/ProxyHostList.tsx`
- Create: `ui/src/components/proxy-host-list/ProxyHostRow.tsx`
- Create: `ui/src/components/proxy-host-list/ProxyHostBulkActions.tsx`
- Create: `ui/src/components/proxy-host-list/ProxyHostFilters.tsx`

- [ ] **Step 1: Extract**

- `ProxyHostRow` — single row with status badges, action buttons
- `ProxyHostBulkActions` — multi-select toolbar
- `ProxyHostFilters` — search, status filter, favorite filter

### Task 5.11: Split `TestResultModal.tsx` (614 → ≤500)

**Files:**
- Modify: `ui/src/components/proxy-host-list/TestResultModal.tsx`
- Create: `ui/src/components/proxy-host-list/TestResultSummary.tsx`
- Create: `ui/src/components/proxy-host-list/TestResultDetails.tsx`
- Create: `ui/src/components/proxy-host-list/TestResultLogs.tsx`

- [ ] **Step 1: Extract**

- `TestResultSummary` — top banner with pass/fail count
- `TestResultDetails` — per-test result table
- `TestResultLogs` — expandable log viewer

### Task 5.12: Verify all 10 splits + E2E

- [ ] **Step 1: Confirm all 10 files are ≤600**

```bash
for f in ui/src/components/LogViewer.tsx ui/src/components/ExploitBlockLogs.tsx \
         ui/src/components/log-viewer/modals/LogDetailModal.tsx ui/src/components/BackupManager.tsx \
         ui/src/components/APITokenManager.tsx ui/src/components/FilterSubscriptionList.tsx \
         ui/src/components/AccountSettings.tsx ui/src/components/log/LogFilters.tsx \
         ui/src/components/ProxyHostList.tsx ui/src/components/proxy-host-list/TestResultModal.tsx; do
  wc -l "$f"
done
```

All ≤600 required, ≤500 ideal.

- [ ] **Step 2: Full UI build**

```bash
cd /opt/stacks/nginxproxyguard/ui
rm -rf node_modules/.vite
cd ..
docker compose -f docker-compose.dev.yml build ui 2>&1 | tail -20
```

- [ ] **Step 3: E2E run**

```bash
docker compose -f docker-compose.e2e-test.yml build --no-cache ui
docker compose -f docker-compose.e2e-test.yml up -d
sleep 20
cd test/e2e
npx playwright test 2>&1 | tail -20
cd ..
docker compose -f docker-compose.e2e-test.yml down -v
```

Expected: all green.

### Task 5.13: Manual smoke test

- [ ] **Step 1: Start dev UI + API**

```bash
docker compose -f docker-compose.dev.yml up -d
```

- [ ] **Step 2: Manually verify each refactored screen renders**

Checklist:
- [ ] `/logs/access` — log viewer loads, filter drawer opens
- [ ] `/logs/exploit-blocks` — exploit block logs render, click row for detail modal
- [ ] `/settings/backups` — backup list loads, create/schedule UI visible
- [ ] `/settings/api-tokens` — token list, create modal opens
- [ ] `/settings/filter-subscriptions` — subscription list, add form opens
- [ ] `/settings/account` (or wherever AccountSettings lives) — all tabs switchable
- [ ] `/proxy-hosts` — list loads, bulk actions work, test-result modal opens on test click

- [ ] **Step 3: Tear down**

```bash
docker compose -f docker-compose.dev.yml down
```

### Task 5.14: Commit and PR

```bash
git add ui/
git commit -m "refactor(ui): split large components below 600 LOC"
git push -u origin phase5/ui-component-split
gh pr create --title "refactor(ui): split large components below 600 LOC" --body "$(cat <<'EOF'
## Scope
Phase 5 of codebase-cleanup — split 10 UI components >600 LOC into focused sub-components under domain subfolders.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §8

## Changes
- 10 component files reduced: LogViewer 825→<500, ExploitBlockLogs 799→<500, LogDetailModal 709→<500, BackupManager 687→<500, APITokenManager 653→<500, FilterSubscriptionList 640→<500, AccountSettings 623→<500, LogFilters 621→<500, ProxyHostList 615→<500, TestResultModal 614→<500
- New subfolders: exploit-block-logs, backup, api-token, filter-subscription, account
- Existing subfolders extended: log-viewer, log, proxy-host-list
- Public exports unchanged

## Verification
- [x] `npm run build` succeeds
- [x] Full E2E suite green
- [x] Manual smoke test on each refactored screen

## Out of scope
- No behavior or API changes
EOF
)"
```

---

## Phase 6: `useProxyHostForm` Hook Decomposition

**Branch:** `phase6/proxy-host-form-hooks`
**PR title:** `refactor(ui): decompose useProxyHostForm into domain hooks`
**Risk:** 🔴 High — protected by Phase 2 tests + E2E + manual checklist.

**Prerequisites:** Phase 2 AND Phase 5 PRs merged.

### Task 6.1: Create branch

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
git checkout -b phase6/proxy-host-form-hooks
```

### Task 6.2: Read current useProxyHostForm.ts

- [ ] **Step 1: Snapshot and understand sections**

```bash
wc -l ui/src/components/proxy-host/hooks/useProxyHostForm.ts
cat ui/src/components/proxy-host/hooks/useProxyHostForm.ts | head -100
```

Identify these logical sections in the current file:
1. Initial form state + field setters (state)
2. Validation functions (validateBasic, validateSSL, etc.)
3. Certificate selection/creation flow (cert API calls + polling)
4. Additional settings saves (bot, geo, cloud with `skip_reload=true`)
5. Submit orchestration (the 6-step flow)
6. Return value assembly

### Task 6.3: Create `proxyHostValidation.ts` (pure functions, no `use` prefix)

**Files:**
- Create: `ui/src/components/proxy-host/hooks/proxyHostValidation.ts`

- [ ] **Step 1: Extract validation functions as pure TS**

```typescript
// ui/src/components/proxy-host/hooks/proxyHostValidation.ts
import type { ProxyHostFormData } from '@/types/proxy-host';

export type ValidationErrors = Partial<Record<keyof ProxyHostFormData, string>>;

export function validateBasic(data: ProxyHostFormData): ValidationErrors {
  const errors: ValidationErrors = {};
  if (!data.domainNames || data.domainNames.length === 0) {
    errors.domainNames = 'errors.domainRequired'; // i18n key
  }
  if (!data.forwardHost) {
    errors.forwardHost = 'errors.forwardHostRequired';
  }
  if (data.forwardPort < 1 || data.forwardPort > 65535) {
    errors.forwardPort = 'errors.portInvalid';
  }
  return errors;
}

export function validateSSL(data: ProxyHostFormData): ValidationErrors {
  // Move body verbatim from useProxyHostForm.ts
  return {};
}

export function validateSecurity(data: ProxyHostFormData): ValidationErrors {
  // Move body verbatim from useProxyHostForm.ts
  return {};
}

export function validateAll(data: ProxyHostFormData): ValidationErrors {
  return {
    ...validateBasic(data),
    ...validateSSL(data),
    ...validateSecurity(data),
  };
}
```

Copy each `validateXxx` body verbatim from the existing hook.

### Task 6.4: Create `useProxyHostFormState.ts`

**Files:**
- Create: `ui/src/components/proxy-host/hooks/useProxyHostFormState.ts`

- [ ] **Step 1: Extract state + setters**

```typescript
import { useState, useEffect } from 'react';
import type { ProxyHost, ProxyHostFormData } from '@/types/proxy-host';

function initialFormData(host?: ProxyHost | null): ProxyHostFormData {
  if (!host) {
    return {
      domainNames: [],
      forwardScheme: 'http',
      forwardHost: '',
      forwardPort: 80,
      sslEnabled: false,
      // ...all other fields with sensible defaults
    };
  }
  return {
    domainNames: host.domainNames,
    forwardScheme: host.forwardScheme,
    forwardHost: host.forwardHost,
    // ...map all fields from host to formData
  };
}

export function useProxyHostFormState(host?: ProxyHost | null) {
  const [formData, setFormData] = useState<ProxyHostFormData>(() => initialFormData(host));
  const [activeTab, setActiveTab] = useState<'basic' | 'ssl' | 'security' | 'protection' | 'performance' | 'upstream' | 'advanced'>('basic');

  // Re-initialize when host prop changes (for edit reopen)
  useEffect(() => {
    setFormData(initialFormData(host));
  }, [host]);

  const updateField = <K extends keyof ProxyHostFormData>(key: K, value: ProxyHostFormData[K]) => {
    setFormData(prev => ({ ...prev, [key]: value }));
  };

  return {
    formData, setFormData,
    updateField,
    activeTab, setActiveTab,
  };
}
```

### Task 6.5: Create `useProxyHostCertificate.ts`

**Files:**
- Create: `ui/src/components/proxy-host/hooks/useProxyHostCertificate.ts`

- [ ] **Step 1: Extract cert selection/creation + polling**

```typescript
import { useState } from 'react';
import { createCertificate, fetchCertificate } from '@/api/certificates';
import type { ProxyHostFormData } from '@/types/proxy-host';

const POLL_INTERVAL_MS = 2000;
const POLL_TIMEOUT_MS = 120_000;

type UseCertOpts = {
  formData: ProxyHostFormData;
  updateField: <K extends keyof ProxyHostFormData>(k: K, v: ProxyHostFormData[K]) => void;
};

export function useProxyHostCertificate({ formData, updateField }: UseCertOpts) {
  const [certStatus, setCertStatus] = useState<'idle' | 'creating' | 'polling' | 'ready' | 'failed'>('idle');
  const [certError, setCertError] = useState<string | null>(null);

  /**
   * If formData specifies a NEW cert (sslEnabled && certificateId === 'new'),
   * create it and poll until ready (or timeout). If using an existing cert,
   * no-op. Returns the final certificate ID to attach to the host.
   */
  async function ensureCertificate(): Promise<string | null> {
    if (!formData.sslEnabled) return null;
    if (formData.certificateId && formData.certificateId !== 'new') return formData.certificateId;

    setCertStatus('creating');
    setCertError(null);
    try {
      const cert = await createCertificate({
        domainNames: formData.domainNames,
        provider: 'letsencrypt',
        // ... other fields derived from formData
      });
      setCertStatus('polling');

      const deadline = Date.now() + POLL_TIMEOUT_MS;
      while (Date.now() < deadline) {
        const status = await fetchCertificate(cert.id);
        if (status.status === 'issued') {
          updateField('certificateId', cert.id);
          setCertStatus('ready');
          return cert.id;
        }
        if (status.status === 'error') {
          setCertError(status.errorMessage ?? 'cert issuance failed');
          setCertStatus('failed');
          return null;
        }
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
      }
      setCertError('polling timed out');
      setCertStatus('failed');
      return null;
    } catch (err) {
      setCertError(err instanceof Error ? err.message : String(err));
      setCertStatus('failed');
      return null;
    }
  }

  return { certStatus, certError, ensureCertificate };
}
```

Match the actual API calls (`createCertificate`, `fetchCertificate`) to whatever the previous hook used.

### Task 6.6: Create `useProxyHostExtras.ts`

**Files:**
- Create: `ui/src/components/proxy-host/hooks/useProxyHostExtras.ts`

- [ ] **Step 1: Extract post-create additional-settings saves**

```typescript
import { upsertBotFilter } from '@/api/security';
import { upsertGeoRestriction } from '@/api/access';
import { upsertCloudProviderBlocks } from '@/api/security';
import type { ProxyHostFormData } from '@/types/proxy-host';

export function useProxyHostExtras() {
  /**
   * Saves settings that aren't part of the proxy_host POST payload:
   * bot filter, geo restriction, cloud provider block list.
   * Uses skip_reload=true so nginx doesn't reload between calls.
   */
  async function saveExtras(hostId: string, formData: ProxyHostFormData): Promise<void> {
    if (formData.botFilterEnabled) {
      await upsertBotFilter(hostId, formData.botFilterConfig, { skipReload: true });
    }
    if (formData.geoEnabled) {
      await upsertGeoRestriction(hostId, formData.geoConfig, { skipReload: true });
    }
    if (formData.cloudProvidersBlocked?.length) {
      await upsertCloudProviderBlocks(hostId, formData.cloudProvidersBlocked, { skipReload: true });
    }
  }

  return { saveExtras };
}
```

Match actual API function names used in the current hook.

### Task 6.7: Create `useProxyHostSubmit.ts`

**Files:**
- Create: `ui/src/components/proxy-host/hooks/useProxyHostSubmit.ts`

- [ ] **Step 1: Extract submit orchestrator**

```typescript
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { createProxyHost, updateProxyHost } from '@/api/proxy-hosts';
import { syncAllConfigs } from '@/api/settings';
import { validateAll, type ValidationErrors } from './proxyHostValidation';
import type { ProxyHost, ProxyHostFormData } from '@/types/proxy-host';

type SubmitOpts = {
  host: ProxyHost | null;  // null = create, non-null = edit
  formData: ProxyHostFormData;
  ensureCertificate: () => Promise<string | null>;
  saveExtras: (hostId: string, data: ProxyHostFormData) => Promise<void>;
  onClose: () => void;
};

export type SaveProgress = {
  step: 'idle' | 'validating' | 'certificate' | 'posting' | 'extras' | 'syncing' | 'done';
  message?: string;
};

export function useProxyHostSubmit({ host, formData, ensureCertificate, saveExtras, onClose }: SubmitOpts) {
  const qc = useQueryClient();
  const [errors, setErrors] = useState<ValidationErrors>({});
  const [progress, setProgress] = useState<SaveProgress>({ step: 'idle' });

  async function handleSubmit() {
    setProgress({ step: 'validating' });
    const validationErrors = validateAll(formData);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      setProgress({ step: 'idle' });
      return;
    }
    setErrors({});

    setProgress({ step: 'certificate' });
    const certId = await ensureCertificate();
    if (formData.sslEnabled && !certId) {
      setProgress({ step: 'idle' });
      return;
    }

    setProgress({ step: 'posting' });
    const payload = { ...formData, certificateId: certId ?? formData.certificateId };
    const saved = host
      ? await updateProxyHost(host.id, payload)
      : await createProxyHost(payload);

    setProgress({ step: 'extras' });
    await saveExtras(saved.id, formData);

    setProgress({ step: 'syncing' });
    await syncAllConfigs();

    setProgress({ step: 'done' });
    qc.invalidateQueries({ queryKey: ['proxy-hosts'] });
    setTimeout(onClose, 800);
  }

  return { handleSubmit, errors, progress };
}
```

Match existing API function names and error conventions.

### Task 6.8: Rewrite `useProxyHostForm.ts` as thin container

**Files:**
- Rewrite: `ui/src/components/proxy-host/hooks/useProxyHostForm.ts`

- [ ] **Step 1: Replace entire file**

```typescript
import { useProxyHostFormState } from './useProxyHostFormState';
import { useProxyHostCertificate } from './useProxyHostCertificate';
import { useProxyHostExtras } from './useProxyHostExtras';
import { useProxyHostSubmit } from './useProxyHostSubmit';
import type { ProxyHost } from '@/types/proxy-host';

/**
 * Thin composition root for ProxyHostForm.
 * External shape unchanged from pre-refactor version — consumers don't care.
 */
export function useProxyHostForm(host: ProxyHost | null, onClose: () => void) {
  const state = useProxyHostFormState(host);
  const cert = useProxyHostCertificate({ formData: state.formData, updateField: state.updateField });
  const extras = useProxyHostExtras();
  const submit = useProxyHostSubmit({
    host,
    formData: state.formData,
    ensureCertificate: cert.ensureCertificate,
    saveExtras: extras.saveExtras,
    onClose,
  });

  return {
    // State
    formData: state.formData,
    setFormData: state.setFormData,
    updateField: state.updateField,
    activeTab: state.activeTab,
    setActiveTab: state.setActiveTab,

    // Submit
    handleSubmit: submit.handleSubmit,
    errors: submit.errors,
    saveProgress: submit.progress,

    // Cert
    certStatus: cert.certStatus,
    certError: cert.certError,
  };
}
```

- [ ] **Step 2: Verify line counts**

```bash
wc -l ui/src/components/proxy-host/hooks/*.ts
```

Each file ≤300 lines (hook limit). Main `useProxyHostForm.ts` ≤120.

### Task 6.9: Verify build + types

- [ ] **Step 1: Full UI build**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.dev.yml build ui 2>&1 | tail -30
```

Expected: green. Fix any type mismatches in `ProxyHostForm.tsx` consumers if the return shape shifted.

### Task 6.10: Run Phase 2 characterization tests (backend safety net)

- [ ] **Step 1: Ensure backend is unchanged and passes tests**

```bash
cd /opt/stacks/nginxproxyguard/api
go test ./internal/nginx/... ./internal/service/... -v 2>&1 | tail -20
```

All Phase 2 tests PASS.

### Task 6.11: Full E2E run

- [ ] **Step 1: Build E2E env and run relevant specs**

```bash
cd /opt/stacks/nginxproxyguard
docker compose -f docker-compose.e2e-test.yml build --no-cache ui api
docker compose -f docker-compose.e2e-test.yml up -d
sleep 20
cd test/e2e
npx playwright test specs/proxy-host/ specs/security/ specs/certificates/ 2>&1 | tail -30
cd ..
```

Expected: all green.

### Task 6.12: Manual checklist (from spec §9.3)

- [ ] Create a new HTTP-only proxy host → nginx config generated, accessible
- [ ] Create a new HTTPS proxy host with cert issuance (DNS challenge) → cert issued, proxy reaches backend over HTTPS
- [ ] Edit existing host — Basic tab (change forward port) → change reflected in nginx config
- [ ] Edit existing host — SSL tab (toggle force HTTPS) → `return 301 https://...` appears in config
- [ ] Edit existing host — Security tab (enable WAF, set paranoia 2, add exclusion) → `host_{id}.conf` regenerated with exclusion
- [ ] Edit existing host — Protection tab (enable rate limit 10 r/s) → `limit_req_zone` + `limit_req` in config
- [ ] Edit existing host — Performance tab (enable cache) → `proxy_cache` directives in config
- [ ] Edit existing host — Upstream tab (add 2 backends, least_conn) → `upstream {}` block with correct strategy
- [ ] Edit existing host — Advanced tab (add `proxy_connect_timeout 10s;`) → injected once, no duplicate with auto-generated
- [ ] Validation errors — try submitting with no domain names → error shown, no API call made
- [ ] WAF host config file on disk — after save, `docker compose exec nginx cat /etc/nginx/modsec/host_{id}.conf` matches UI settings
- [ ] SaveProgressModal — each step visible during a full HTTPS create (validating → certificate → posting → extras → syncing → done)

Mark each complete only after verifying in the browser + nginx file inspection.

- [ ] **Step 2: Tear down**

```bash
docker compose -f docker-compose.e2e-test.yml down -v
```

### Task 6.13: Commit and PR

```bash
git add ui/src/components/proxy-host/hooks/
git commit -m "refactor(ui): decompose useProxyHostForm into domain hooks"
git push -u origin phase6/proxy-host-form-hooks
gh pr create --title "refactor(ui): decompose useProxyHostForm into domain hooks" --body "$(cat <<'EOF'
## Scope
Phase 6 of codebase-cleanup — split 677-line useProxyHostForm hook into 5 focused modules.
Spec: docs/superpowers/specs/2026-04-17-codebase-cleanup-design.md §9

## Changes
- `proxyHostValidation.ts` — pure validation functions (no React hook)
- `useProxyHostFormState.ts` — field state + tab state
- `useProxyHostCertificate.ts` — cert selection/creation + 2s polling (120s timeout)
- `useProxyHostExtras.ts` — bot/geo/cloud saves with skip_reload=true
- `useProxyHostSubmit.ts` — 6-step submit orchestrator
- `useProxyHostForm.ts` — thin container (≤120 lines), composition only
- External API unchanged: same `useProxyHostForm(host, onClose)` signature and return shape

## Verification
- [x] `npm run build` succeeds
- [x] Phase 2 backend characterization tests still green
- [x] Full E2E proxy-host + security + certificates specs green
- [x] Manual checklist from spec §9.3 all 12 items passed

## Out of scope
- No backend changes
- No change to form UI / tab content / i18n keys
EOF
)"
```

### Task 6.14: Post-merge tagging

After all 7 PRs are merged to main:

- [ ] **Step 1: Cut release commit**

```bash
cd /opt/stacks/nginxproxyguard
git checkout main && git pull --ff-only origin main
```

- [ ] **Step 2: Bump AppVersion to 2.10.0**

Edit `api/internal/config/constants.go`:
```go
const AppVersion = "2.10.0"
```

Edit `ui/package.json`:
```json
"version": "2.10.0"
```

- [ ] **Step 3: Commit and tag**

```bash
git add api/internal/config/constants.go ui/package.json
git commit -m "release: v2.10.0"
git tag v2.10.0
git push origin main
git push origin v2.10.0
```

CI/CD (per CLAUDE.md §CI/CD) will build and push images automatically.

---

## Phase Completion Checklist

After each Phase PR merges, update the local spec-tracking notes:

- [ ] Phase 1 merged: docs drift resolved ✓
- [ ] Phase 2 merged: 4 characterization tests in place ✓
- [ ] Phase 3 merged: main.go ≤200 lines ✓
- [ ] Phase 4a merged: proxy_host_template.go ≤400 lines ✓
- [ ] Phase 4b merged: all 5 repos ≤800 lines ✓
- [ ] Phase 5 merged: 10 UI components ≤600 lines ✓
- [ ] Phase 6 merged: useProxyHostForm decomposed ✓
- [ ] v2.10.0 tagged and released ✓

---

## Troubleshooting Guide

**If a bootstrap service constructor arg order is wrong:**
Compile error will name the missing or extra argument. Cross-reference against current `main.go` (still on git history of `main`) — the exact arg order is what the constructor expects.

**If a Phase 2 golden test fails after Phase 4a:**
Run `go test ./internal/nginx/ -run TestProxyHostTemplate_Characterization -v` and inspect the `--- got --- / --- want ---` diff. Typically a whitespace issue in one of the section templates. **Do not** run `-update-golden` unless you have verified the change is intentional and reviewed the diff.

**If E2E fails after Phase 3:**
Check `docker compose -f docker-compose.e2e-test.yml logs api` — most likely a callback wasn't wired in `services.go`. Search for `Set*Callback` in the previous main.go and ensure each is replicated in `wireServiceCallbacks`.

**If UI build fails after Phase 5/6:**
- Missing export: ensure new subcomponent files export correctly.
- Circular import: the composer (e.g., LogViewer.tsx) should import from the subfolder, not the other way around.
- Type narrowing broken: if a subcomponent expects a prop that the parent used to derive inline, add that prop to the subcomponent's Props interface.

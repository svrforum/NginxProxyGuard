# NPG Community Filter Subscription System — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a community-driven security filter subscription system that lets NPG users subscribe to curated IP/CIDR/User-Agent blocklists from the `svrforum/npg-filters` GitHub repo (or any URL), with automatic periodic refresh and nginx config integration.

**Architecture:** Two independent subsystems — (1) the `npg-filters` GitHub repo with schema, validation tools, and CI pipelines, and (2) the NPG backend+frontend additions for subscribing, fetching, storing, and applying filter entries. Filter entries are stored in dedicated tables (not mixed into `banned_ips` / `bot_filters`), and merged at nginx config generation time.

**Tech Stack:** Go 1.24 (Echo v4), React 18 + TypeScript + Vite, TimescaleDB 17, GitHub Actions (for npg-filters CI)

**Spec:** `docs/superpowers/specs/2026-03-31-npg-filters-design.md`

---

## File Map

### npg-filters Repo (svrforum/npg-filters)

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `schema.json` | JSON Schema for filter list validation |
| Create | `tools/validate.py` | CI validation: schema, IP/CIDR format, UA regex, duplicates, private IPs, entry limits |
| Create | `tools/build-index.py` | Scan `lists/` → generate `index.json` catalog |
| Create | `.github/workflows/validate.yml` | PR validation workflow |
| Create | `.github/workflows/build-index.yml` | Post-merge index.json generation |
| Create | `.github/PULL_REQUEST_TEMPLATE.md` | PR template for contributors |
| Create | `README.md` | Contribution guide and format docs |
| Create | `lists/ips/web-scanners.json` | Seed: sample IP filter list |
| Create | `lists/cidrs/known-botnets.json` | Seed: sample CIDR filter list |
| Create | `lists/user-agents/malicious-tools.json` | Seed: sample UA filter list |

### NPG Backend (api/)

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `internal/database/migrations/001_init.sql` | Add 3 new tables + indexes |
| Modify | `internal/database/migration.go` | Add upgrade SQL for existing installs |
| Create | `internal/model/filter_subscription.go` | Data structs + request/response types |
| Create | `internal/repository/filter_subscription.go` | DB CRUD for subscriptions, entries, exclusions |
| Create | `internal/service/filter_subscription.go` | Business logic: fetch, parse, format detect, SSRF protection |
| Create | `internal/handler/filter_subscription.go` | HTTP handlers (Echo pattern) |
| Create | `internal/scheduler/filter_refresh.go` | Periodic refresh scheduler |
| Modify | `internal/nginx/proxy_host_template.go` | Add `FilterSubscriptionIPs` and `FilterSubscriptionUAs` to config data |
| Modify | `internal/service/proxy_host_config.go` | Merge filter subscription entries into config data |
| Modify | `internal/config/constants.go` | Add filter subscription constants |
| Modify | `cmd/server/main.go` | Wire DI + register routes + start scheduler |

### NPG Frontend (ui/)

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `src/types/filter-subscription.ts` | TypeScript interfaces |
| Create | `src/api/filter-subscriptions.ts` | API client functions |
| Create | `src/components/FilterSubscriptionList.tsx` | Main page: catalog + subscriptions + modals |
| Create | `src/i18n/locales/ko/filterSubscription.json` | Korean translations |
| Create | `src/i18n/locales/en/filterSubscription.json` | English translations |
| Modify | `src/i18n/index.ts` | Register filterSubscription namespace |
| Modify | `src/App.tsx` | Add route + SettingsPage sub-tab |

---

## Task 1: npg-filters Repo — Schema and Validation Tools

**Files:**
- Create: `schema.json` (in npg-filters repo)
- Create: `tools/validate.py` (in npg-filters repo)
- Create: `tools/build-index.py` (in npg-filters repo)

- [ ] **Step 1: Clone npg-filters repo**

```bash
cd /opt/stacks
git clone https://github.com/svrforum/npg-filters.git
cd npg-filters
```

- [ ] **Step 2: Create JSON Schema (`schema.json`)**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "NPG Filter List",
  "description": "Community-driven security filter list for Nginx Proxy Guard",
  "type": "object",
  "required": ["name", "description", "type", "expires", "entries"],
  "properties": {
    "name": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "description": {
      "type": "string",
      "minLength": 1,
      "maxLength": 500
    },
    "type": {
      "type": "string",
      "enum": ["ip", "cidr", "user_agent"]
    },
    "expires": {
      "type": "string",
      "pattern": "^(6h|12h|24h|48h)$"
    },
    "max_entries": {
      "type": "integer",
      "minimum": 1,
      "maximum": 5000,
      "default": 5000
    },
    "entries": {
      "type": "array",
      "maxItems": 5000,
      "items": {
        "type": "object",
        "required": ["value", "reason", "added", "contributor"],
        "properties": {
          "value": {
            "type": "string",
            "minLength": 1
          },
          "reason": {
            "type": "string",
            "minLength": 1,
            "maxLength": 500
          },
          "added": {
            "type": "string",
            "pattern": "^\\d{4}-\\d{2}-\\d{2}$"
          },
          "contributor": {
            "type": "string",
            "minLength": 1,
            "maxLength": 100
          }
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}
```

- [ ] **Step 3: Create validation tool (`tools/validate.py`)**

```python
#!/usr/bin/env python3
"""Validate NPG filter list JSON files against schema and format rules."""

import json
import sys
import os
import re
import ipaddress
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("ERROR: jsonschema package required. Install: pip install jsonschema")
    sys.exit(1)

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

MAX_ENTRIES_PER_FILE = 5000


def load_schema():
    schema_path = Path(__file__).parent.parent / "schema.json"
    with open(schema_path) as f:
        return json.load(f)


def is_private_ip(addr_str):
    """Check if an IP or CIDR is in a private/reserved range."""
    try:
        if "/" in addr_str:
            net = ipaddress.ip_network(addr_str, strict=False)
            return any(net.overlaps(priv) for priv in PRIVATE_NETWORKS)
        else:
            addr = ipaddress.ip_address(addr_str)
            return any(addr in priv for priv in PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_ip(value):
    """Validate a single IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_cidr(value):
    """Validate a CIDR notation."""
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def validate_user_agent_pattern(value):
    """Validate a regex pattern compiles successfully."""
    try:
        re.compile(value)
        return True
    except re.error:
        return False


def validate_file(filepath, schema):
    """Validate a single filter list file. Returns (errors, warnings, entries)."""
    errors = []
    warnings = []
    entries = []

    try:
        with open(filepath) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON: {e}"], [], []

    # Schema validation
    try:
        jsonschema.validate(data, schema)
    except jsonschema.ValidationError as e:
        errors.append(f"Schema error: {e.message}")
        return errors, warnings, []

    list_type = data["type"]
    file_entries = data.get("entries", [])

    # Entry count check
    max_entries = data.get("max_entries", MAX_ENTRIES_PER_FILE)
    if len(file_entries) > max_entries:
        errors.append(f"Too many entries: {len(file_entries)} > {max_entries}")

    # Validate each entry
    seen_values = set()
    for i, entry in enumerate(file_entries):
        value = entry["value"]

        # Duplicate check within file
        if value in seen_values:
            errors.append(f"Entry {i}: duplicate value '{value}'")
        seen_values.add(value)

        # Type-specific validation
        if list_type == "ip":
            if not validate_ip(value):
                errors.append(f"Entry {i}: invalid IP '{value}'")
            elif is_private_ip(value):
                errors.append(f"Entry {i}: private/reserved IP '{value}' not allowed")
        elif list_type == "cidr":
            if not validate_cidr(value):
                errors.append(f"Entry {i}: invalid CIDR '{value}'")
            elif is_private_ip(value):
                errors.append(f"Entry {i}: private/reserved CIDR '{value}' not allowed")
        elif list_type == "user_agent":
            if not validate_user_agent_pattern(value):
                errors.append(f"Entry {i}: invalid regex pattern '{value}'")

        entries.append(value)

    # Check file is in correct directory
    rel_path = str(filepath)
    expected_dirs = {"ip": "lists/ips/", "cidr": "lists/cidrs/", "user_agent": "lists/user-agents/"}
    expected_dir = expected_dirs.get(list_type, "")
    if expected_dir and expected_dir not in rel_path:
        warnings.append(f"File type '{list_type}' should be in '{expected_dir}' directory")

    return errors, warnings, entries


def check_cross_file_duplicates(all_entries):
    """Check for duplicate values across files of the same type."""
    errors = []
    type_values = {}

    for filepath, list_type, entries in all_entries:
        if list_type not in type_values:
            type_values[list_type] = {}
        for value in entries:
            if value in type_values[list_type]:
                errors.append(
                    f"Cross-file duplicate: '{value}' in both "
                    f"'{type_values[list_type][value]}' and '{filepath}'"
                )
            else:
                type_values[list_type][value] = filepath

    return errors


def main():
    repo_root = Path(__file__).parent.parent
    schema = load_schema()

    # Find all JSON files in lists/
    lists_dir = repo_root / "lists"
    if not lists_dir.exists():
        print("No lists/ directory found")
        sys.exit(0)

    json_files = sorted(lists_dir.rglob("*.json"))
    if not json_files:
        print("No filter list files found")
        sys.exit(0)

    total_errors = []
    total_warnings = []
    all_entries = []

    for filepath in json_files:
        rel_path = filepath.relative_to(repo_root)
        print(f"Validating {rel_path}...")

        errors, warnings, entries = validate_file(filepath, schema)

        for err in errors:
            total_errors.append(f"  {rel_path}: {err}")
            print(f"  ERROR: {err}")

        for warn in warnings:
            total_warnings.append(f"  {rel_path}: {warn}")
            print(f"  WARNING: {warn}")

        if not errors:
            with open(filepath) as f:
                data = json.load(f)
            all_entries.append((str(rel_path), data["type"], entries))
            print(f"  OK ({len(entries)} entries)")

    # Cross-file duplicate check
    cross_errors = check_cross_file_duplicates(all_entries)
    total_errors.extend(cross_errors)
    for err in cross_errors:
        print(f"ERROR: {err}")

    # Summary
    print(f"\n{'='*50}")
    print(f"Files checked: {len(json_files)}")
    print(f"Errors: {len(total_errors)}")
    print(f"Warnings: {len(total_warnings)}")

    if total_errors:
        print("\nValidation FAILED")
        sys.exit(1)
    else:
        print("\nValidation PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Create index builder (`tools/build-index.py`)**

```python
#!/usr/bin/env python3
"""Build index.json from all filter list files in lists/ directory."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def build_index():
    repo_root = Path(__file__).parent.parent
    lists_dir = repo_root / "lists"

    if not lists_dir.exists():
        print("No lists/ directory found")
        return

    catalog = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lists": [],
    }

    json_files = sorted(lists_dir.rglob("*.json"))

    for filepath in json_files:
        try:
            with open(filepath) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"WARNING: Skipping {filepath}: {e}")
            continue

        # Get file modification time
        mtime = os.path.getmtime(filepath)
        updated_at = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        rel_path = str(filepath.relative_to(repo_root))

        entry = {
            "name": data.get("name", filepath.stem),
            "description": data.get("description", ""),
            "type": data.get("type", "ip"),
            "path": rel_path,
            "entry_count": len(data.get("entries", [])),
            "updated_at": updated_at,
        }
        catalog["lists"].append(entry)

    # Write index.json
    index_path = repo_root / "index.json"
    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Generated index.json with {len(catalog['lists'])} lists")


if __name__ == "__main__":
    build_index()
```

- [ ] **Step 5: Commit schema and tools**

```bash
cd /opt/stacks/npg-filters
git add schema.json tools/
git commit -m "feat: add JSON schema and validation/index build tools"
```

---

## Task 2: npg-filters Repo — CI Workflows and Seed Data

**Files:**
- Create: `.github/workflows/validate.yml`
- Create: `.github/workflows/build-index.yml`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Create: `README.md`
- Create: `lists/ips/web-scanners.json`
- Create: `lists/cidrs/known-botnets.json`
- Create: `lists/user-agents/malicious-tools.json`

- [ ] **Step 1: Create PR validation workflow (`.github/workflows/validate.yml`)**

```yaml
name: Validate Filter Lists

on:
  pull_request:
    paths:
      - 'lists/**'
      - 'schema.json'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install jsonschema

      - name: Validate filter lists
        run: python tools/validate.py
```

- [ ] **Step 2: Create index build workflow (`.github/workflows/build-index.yml`)**

```yaml
name: Build Index

on:
  push:
    branches: [main]
    paths:
      - 'lists/**'

jobs:
  build-index:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Build index.json
        run: python tools/build-index.py

      - name: Commit index.json
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add index.json
          if git diff --cached --quiet; then
            echo "No changes to index.json"
          else
            git commit -m "chore: rebuild index.json"
            git push
          fi
```

- [ ] **Step 3: Create PR template (`.github/PULL_REQUEST_TEMPLATE.md`)**

```markdown
## Filter List Contribution

### Type
- [ ] IP
- [ ] CIDR
- [ ] User Agent

### Changes
- [ ] New filter list
- [ ] Update existing filter list

### Checklist
- [ ] Each entry has a `reason` field
- [ ] No private/reserved IP ranges included
- [ ] No duplicate entries (within file or across files)
- [ ] File is in the correct directory (`lists/ips/`, `lists/cidrs/`, or `lists/user-agents/`)
- [ ] Entry count is within limit (max 5,000 per file)
```

- [ ] **Step 4: Create README.md**

```markdown
# NPG Filters

Community-driven security filter lists for [Nginx Proxy Guard](https://github.com/svrforum/nginxproxyguard).

## Filter Types

| Type | Directory | Description |
|------|-----------|-------------|
| IP | `lists/ips/` | Single IP addresses |
| CIDR | `lists/cidrs/` | IP ranges in CIDR notation |
| User Agent | `lists/user-agents/` | Regex patterns for User-Agent strings |

## Format

```json
{
  "name": "List Name",
  "description": "Description of this list",
  "type": "ip",
  "expires": "24h",
  "entries": [
    {
      "value": "1.2.3.4",
      "reason": "Why this entry is blocked",
      "added": "2026-03-31",
      "contributor": "your-github-username"
    }
  ]
}
```

## Contributing

1. Fork this repository
2. Add or update entries in the appropriate directory
3. Submit a Pull Request
4. CI will automatically validate your changes

### Rules

- Each entry must have a `reason`
- Private/reserved IPs are not allowed
- Maximum 5,000 entries per file
- No duplicate values across files of the same type
- User Agent patterns must be valid regex

## Using with NPG

In NPG, go to **Settings → Filter Subscriptions → Catalog** to browse and subscribe to available lists.

You can also subscribe to any list directly via its raw URL:

```
https://raw.githubusercontent.com/svrforum/npg-filters/main/lists/ips/web-scanners.json
```

External plaintext IP/CIDR lists (Spamhaus DROP, FireHOL, etc.) are also supported.
```

- [ ] **Step 5: Create seed filter lists**

**`lists/ips/web-scanners.json`:**
```json
{
  "name": "Web Scanners",
  "description": "Known web vulnerability scanner IPs",
  "type": "ip",
  "expires": "24h",
  "entries": []
}
```

**`lists/cidrs/known-botnets.json`:**
```json
{
  "name": "Known Botnets",
  "description": "Known botnet IP ranges",
  "type": "cidr",
  "expires": "24h",
  "entries": []
}
```

**`lists/user-agents/malicious-tools.json`:**
```json
{
  "name": "Malicious Tools",
  "description": "User-Agent patterns for known attack tools",
  "type": "user_agent",
  "expires": "24h",
  "entries": [
    {
      "value": "sqlmap",
      "reason": "SQL injection tool",
      "added": "2026-03-31",
      "contributor": "svrforum"
    },
    {
      "value": "nikto",
      "reason": "Web vulnerability scanner",
      "added": "2026-03-31",
      "contributor": "svrforum"
    },
    {
      "value": "nmap",
      "reason": "Network scanner",
      "added": "2026-03-31",
      "contributor": "svrforum"
    }
  ]
}
```

- [ ] **Step 6: Run validation locally to verify**

```bash
cd /opt/stacks/npg-filters
pip install jsonschema
python tools/validate.py
```

Expected: `Validation PASSED`

- [ ] **Step 7: Build index locally to verify**

```bash
python tools/build-index.py
cat index.json
```

Expected: JSON with 3 lists

- [ ] **Step 8: Commit and push**

```bash
git add .
git commit -m "feat: add CI workflows, seed data, and README"
git push origin main
```

---

## Task 3: NPG Backend — Database Schema

**Files:**
- Modify: `api/internal/database/migrations/001_init.sql`
- Modify: `api/internal/database/migration.go`

- [ ] **Step 1: Add tables to `001_init.sql` CREATE TABLE section**

Add after the existing tables (before the UPGRADE SECTION):

```sql
-- Filter subscription tables
CREATE TABLE IF NOT EXISTS public.filter_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    name text NOT NULL,
    description text,
    url text NOT NULL UNIQUE,
    format character varying(20) NOT NULL DEFAULT 'npg-json',
    type character varying(20) NOT NULL,
    enabled boolean DEFAULT true,
    refresh_type character varying(20) NOT NULL DEFAULT 'interval',
    refresh_value character varying(50) NOT NULL DEFAULT '24h',
    last_fetched_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_error text,
    entry_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.filter_subscription_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
    value text NOT NULL,
    reason text,
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(subscription_id, value)
);

CREATE INDEX IF NOT EXISTS idx_fse_subscription ON public.filter_subscription_entries(subscription_id);
CREATE INDEX IF NOT EXISTS idx_fse_value ON public.filter_subscription_entries(value);

CREATE TABLE IF NOT EXISTS public.filter_subscription_host_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
    proxy_host_id uuid NOT NULL REFERENCES public.proxy_hosts(id) ON DELETE CASCADE,
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(subscription_id, proxy_host_id)
);
```

- [ ] **Step 2: Add same DDL to UPGRADE SECTION of `001_init.sql`**

Add the same CREATE TABLE/INDEX statements to the upgrade section at the bottom of the file.

- [ ] **Step 3: Add upgrade SQL to `migration.go`**

Add to the `upgradeSQL` variable in `api/internal/database/migration.go`:

```sql
-- Filter subscription tables (v2.7.0+)
CREATE TABLE IF NOT EXISTS public.filter_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    name text NOT NULL,
    description text,
    url text NOT NULL UNIQUE,
    format character varying(20) NOT NULL DEFAULT 'npg-json',
    type character varying(20) NOT NULL,
    enabled boolean DEFAULT true,
    refresh_type character varying(20) NOT NULL DEFAULT 'interval',
    refresh_value character varying(50) NOT NULL DEFAULT '24h',
    last_fetched_at timestamp with time zone,
    last_success_at timestamp with time zone,
    last_error text,
    entry_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.filter_subscription_entries (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
    value text NOT NULL,
    reason text,
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(subscription_id, value)
);

CREATE INDEX IF NOT EXISTS idx_fse_subscription ON public.filter_subscription_entries(subscription_id);
CREATE INDEX IF NOT EXISTS idx_fse_value ON public.filter_subscription_entries(value);

CREATE TABLE IF NOT EXISTS public.filter_subscription_host_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
    proxy_host_id uuid NOT NULL REFERENCES public.proxy_hosts(id) ON DELETE CASCADE,
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(subscription_id, proxy_host_id)
);
```

- [ ] **Step 4: Build API to verify migration compiles**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success

- [ ] **Step 5: Commit**

```bash
git add api/internal/database/
git commit -m "feat: add filter subscription database schema"
```

---

## Task 4: NPG Backend — Model and Constants

**Files:**
- Create: `api/internal/model/filter_subscription.go`
- Modify: `api/internal/config/constants.go`

- [ ] **Step 1: Create model file (`api/internal/model/filter_subscription.go`)**

```go
package model

import "time"

// FilterSubscription represents a subscribed filter list
type FilterSubscription struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Description   string     `json:"description,omitempty"`
	URL           string     `json:"url"`
	Format        string     `json:"format"`
	Type          string     `json:"type"`
	Enabled       bool       `json:"enabled"`
	RefreshType   string     `json:"refresh_type"`
	RefreshValue  string     `json:"refresh_value"`
	LastFetchedAt *time.Time `json:"last_fetched_at,omitempty"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"`
	EntryCount    int        `json:"entry_count"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// FilterSubscriptionEntry represents a single entry in a subscribed filter list
type FilterSubscriptionEntry struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	Value          string    `json:"value"`
	Reason         string    `json:"reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// FilterSubscriptionHostExclusion represents a host excluded from a subscription
type FilterSubscriptionHostExclusion struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	ProxyHostID    string    `json:"proxy_host_id"`
	CreatedAt      time.Time `json:"created_at"`
}

// CreateFilterSubscriptionRequest is the request body for creating a subscription
type CreateFilterSubscriptionRequest struct {
	URL          string `json:"url"`
	Name         string `json:"name,omitempty"`
	Type         string `json:"type,omitempty"`
	RefreshType  string `json:"refresh_type,omitempty"`
	RefreshValue string `json:"refresh_value,omitempty"`
}

// UpdateFilterSubscriptionRequest is the request body for updating a subscription
type UpdateFilterSubscriptionRequest struct {
	Name         *string `json:"name,omitempty"`
	Enabled      *bool   `json:"enabled,omitempty"`
	RefreshType  *string `json:"refresh_type,omitempty"`
	RefreshValue *string `json:"refresh_value,omitempty"`
}

// CatalogSubscribeRequest is the request body for subscribing from catalog
type CatalogSubscribeRequest struct {
	Paths        []string `json:"paths"`
	RefreshType  string   `json:"refresh_type,omitempty"`
	RefreshValue string   `json:"refresh_value,omitempty"`
}

// FilterSubscriptionListResponse is the paginated list response
type FilterSubscriptionListResponse struct {
	Data       []FilterSubscription `json:"data"`
	Total      int                  `json:"total"`
	Page       int                  `json:"page"`
	PerPage    int                  `json:"per_page"`
	TotalPages int                  `json:"total_pages"`
}

// FilterSubscriptionDetail includes entries and exclusions
type FilterSubscriptionDetail struct {
	FilterSubscription
	Entries    []FilterSubscriptionEntry          `json:"entries"`
	Exclusions []FilterSubscriptionHostExclusion  `json:"exclusions"`
}

// FilterCatalog represents the npg-filters index.json
type FilterCatalog struct {
	Version     int                  `json:"version"`
	GeneratedAt string               `json:"generated_at"`
	Lists       []FilterCatalogEntry `json:"lists"`
}

// FilterCatalogEntry represents a single list in the catalog
type FilterCatalogEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Path        string `json:"path"`
	EntryCount  int    `json:"entry_count"`
	UpdatedAt   string `json:"updated_at"`
	Subscribed  bool   `json:"subscribed,omitempty"`
}

// NPGFilterList represents the parsed npg-json format
type NPGFilterList struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"`
	Expires     string              `json:"expires"`
	MaxEntries  int                 `json:"max_entries,omitempty"`
	Entries     []NPGFilterEntry    `json:"entries"`
}

// NPGFilterEntry represents a single entry in npg-json format
type NPGFilterEntry struct {
	Value       string `json:"value"`
	Reason      string `json:"reason"`
	Added       string `json:"added"`
	Contributor string `json:"contributor"`
}
```

- [ ] **Step 2: Add constants to `config/constants.go`**

Add to the end of `api/internal/config/constants.go`:

```go
// Filter subscription constants
const (
	FilterFetchTimeout          = 30 * time.Second
	FilterFetchConnectTimeout   = 5 * time.Second
	FilterMaxResponseSize       = 10 * 1024 * 1024 // 10MB
	FilterMaxTotalEntries       = 50000
	FilterMaxEntriesPerFile     = 5000
	FilterMaxRedirects          = 3
	FilterRefreshCheckInterval  = 10 * time.Minute
	FilterCatalogBaseURL        = "https://raw.githubusercontent.com/svrforum/npg-filters/main/"
	FilterCatalogIndexURL       = "https://raw.githubusercontent.com/svrforum/npg-filters/main/index.json"
)
```

- [ ] **Step 3: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success

- [ ] **Step 4: Commit**

```bash
git add api/internal/model/filter_subscription.go api/internal/config/constants.go
git commit -m "feat: add filter subscription models and constants"
```

---

## Task 5: NPG Backend — Repository

**Files:**
- Create: `api/internal/repository/filter_subscription.go`

- [ ] **Step 1: Create repository file**

```go
package repository

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"nginx-proxy-guard/internal/model"
)

type FilterSubscriptionRepository struct {
	db *sql.DB
}

func NewFilterSubscriptionRepository(db *sql.DB) *FilterSubscriptionRepository {
	return &FilterSubscriptionRepository{db: db}
}

// List returns paginated filter subscriptions
func (r *FilterSubscriptionRepository) List(ctx context.Context, page, perPage int) (*model.FilterSubscriptionListResponse, error) {
	var total int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM filter_subscriptions").Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("failed to count filter subscriptions: %w", err)
	}

	offset := (page - 1) * perPage
	query := `SELECT id, name, COALESCE(description, ''), url, format, type, enabled,
		refresh_type, refresh_value, last_fetched_at, last_success_at, last_error,
		entry_count, created_at, updated_at
		FROM filter_subscriptions ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := r.db.QueryContext(ctx, query, perPage, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list filter subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []model.FilterSubscription
	for rows.Next() {
		var s model.FilterSubscription
		err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.URL, &s.Format, &s.Type,
			&s.Enabled, &s.RefreshType, &s.RefreshValue, &s.LastFetchedAt, &s.LastSuccessAt,
			&s.LastError, &s.EntryCount, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan filter subscription: %w", err)
		}
		subs = append(subs, s)
	}

	if subs == nil {
		subs = []model.FilterSubscription{}
	}

	return &model.FilterSubscriptionListResponse{
		Data:       subs,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: int(math.Ceil(float64(total) / float64(perPage))),
	}, nil
}

// GetByID returns a filter subscription by ID
func (r *FilterSubscriptionRepository) GetByID(ctx context.Context, id string) (*model.FilterSubscription, error) {
	query := `SELECT id, name, COALESCE(description, ''), url, format, type, enabled,
		refresh_type, refresh_value, last_fetched_at, last_success_at, last_error,
		entry_count, created_at, updated_at
		FROM filter_subscriptions WHERE id = $1`

	var s model.FilterSubscription
	err := r.db.QueryRowContext(ctx, query, id).Scan(&s.ID, &s.Name, &s.Description,
		&s.URL, &s.Format, &s.Type, &s.Enabled, &s.RefreshType, &s.RefreshValue,
		&s.LastFetchedAt, &s.LastSuccessAt, &s.LastError, &s.EntryCount,
		&s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("filter subscription not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get filter subscription: %w", err)
	}
	return &s, nil
}

// GetByURL returns a filter subscription by URL
func (r *FilterSubscriptionRepository) GetByURL(ctx context.Context, url string) (*model.FilterSubscription, error) {
	query := `SELECT id, name, COALESCE(description, ''), url, format, type, enabled,
		refresh_type, refresh_value, last_fetched_at, last_success_at, last_error,
		entry_count, created_at, updated_at
		FROM filter_subscriptions WHERE url = $1`

	var s model.FilterSubscription
	err := r.db.QueryRowContext(ctx, query, url).Scan(&s.ID, &s.Name, &s.Description,
		&s.URL, &s.Format, &s.Type, &s.Enabled, &s.RefreshType, &s.RefreshValue,
		&s.LastFetchedAt, &s.LastSuccessAt, &s.LastError, &s.EntryCount,
		&s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get filter subscription by URL: %w", err)
	}
	return &s, nil
}

// Create inserts a new filter subscription
func (r *FilterSubscriptionRepository) Create(ctx context.Context, s *model.FilterSubscription) (*model.FilterSubscription, error) {
	query := `INSERT INTO filter_subscriptions (name, description, url, format, type, enabled, refresh_type, refresh_value)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`

	err := r.db.QueryRowContext(ctx, query, s.Name, s.Description, s.URL, s.Format,
		s.Type, s.Enabled, s.RefreshType, s.RefreshValue).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create filter subscription: %w", err)
	}
	return s, nil
}

// Update modifies a filter subscription
func (r *FilterSubscriptionRepository) Update(ctx context.Context, id string, req *model.UpdateFilterSubscriptionRequest) (*model.FilterSubscription, error) {
	query := `UPDATE filter_subscriptions SET updated_at = now()`
	args := []interface{}{}
	argIdx := 1

	if req.Name != nil {
		query += fmt.Sprintf(", name = $%d", argIdx)
		args = append(args, *req.Name)
		argIdx++
	}
	if req.Enabled != nil {
		query += fmt.Sprintf(", enabled = $%d", argIdx)
		args = append(args, *req.Enabled)
		argIdx++
	}
	if req.RefreshType != nil {
		query += fmt.Sprintf(", refresh_type = $%d", argIdx)
		args = append(args, *req.RefreshType)
		argIdx++
	}
	if req.RefreshValue != nil {
		query += fmt.Sprintf(", refresh_value = $%d", argIdx)
		args = append(args, *req.RefreshValue)
		argIdx++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argIdx)
	args = append(args, id)

	_, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update filter subscription: %w", err)
	}

	return r.GetByID(ctx, id)
}

// Delete removes a filter subscription (CASCADE deletes entries and exclusions)
func (r *FilterSubscriptionRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM filter_subscriptions WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete filter subscription: %w", err)
	}
	return nil
}

// UpdateFetchStatus updates the fetch timestamp and error state
func (r *FilterSubscriptionRepository) UpdateFetchStatus(ctx context.Context, id string, success bool, entryCount int, lastError string) error {
	var query string
	if success {
		query = `UPDATE filter_subscriptions SET last_fetched_at = now(), last_success_at = now(),
			last_error = NULL, entry_count = $2, updated_at = now() WHERE id = $1`
		_, err := r.db.ExecContext(ctx, query, id, entryCount)
		return err
	}
	query = `UPDATE filter_subscriptions SET last_fetched_at = now(), last_error = $2,
		updated_at = now() WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id, lastError)
	return err
}

// ReplaceEntries atomically replaces all entries for a subscription
func (r *FilterSubscriptionRepository) ReplaceEntries(ctx context.Context, subscriptionID string, entries []model.FilterSubscriptionEntry) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete old entries
	_, err = tx.ExecContext(ctx, "DELETE FROM filter_subscription_entries WHERE subscription_id = $1", subscriptionID)
	if err != nil {
		return fmt.Errorf("failed to delete old entries: %w", err)
	}

	// Insert new entries
	for _, entry := range entries {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO filter_subscription_entries (subscription_id, value, reason) VALUES ($1, $2, $3)",
			subscriptionID, entry.Value, entry.Reason)
		if err != nil {
			return fmt.Errorf("failed to insert entry: %w", err)
		}
	}

	return tx.Commit()
}

// GetEntries returns all entries for a subscription
func (r *FilterSubscriptionRepository) GetEntries(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionEntry, error) {
	query := `SELECT id, subscription_id, value, COALESCE(reason, ''), created_at
		FROM filter_subscription_entries WHERE subscription_id = $1 ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries: %w", err)
	}
	defer rows.Close()

	var entries []model.FilterSubscriptionEntry
	for rows.Next() {
		var e model.FilterSubscriptionEntry
		if err := rows.Scan(&e.ID, &e.SubscriptionID, &e.Value, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan entry: %w", err)
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []model.FilterSubscriptionEntry{}
	}
	return entries, nil
}

// GetTotalEntryCount returns the total entry count across all subscriptions
func (r *FilterSubscriptionRepository) GetTotalEntryCount(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM filter_subscription_entries").Scan(&count)
	return count, err
}

// GetEntriesForHost returns all subscription entries applicable to a host
// (entries from enabled subscriptions that the host is NOT excluded from)
func (r *FilterSubscriptionRepository) GetEntriesForHost(ctx context.Context, hostID string, filterType string) ([]model.FilterSubscriptionEntry, error) {
	query := `SELECT e.id, e.subscription_id, e.value, COALESCE(e.reason, ''), e.created_at
		FROM filter_subscription_entries e
		JOIN filter_subscriptions s ON e.subscription_id = s.id
		WHERE s.enabled = true AND s.type = $1
		AND s.id NOT IN (
			SELECT subscription_id FROM filter_subscription_host_exclusions WHERE proxy_host_id = $2
		)
		ORDER BY e.value`

	rows, err := r.db.QueryContext(ctx, query, filterType, hostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get entries for host: %w", err)
	}
	defer rows.Close()

	var entries []model.FilterSubscriptionEntry
	for rows.Next() {
		var e model.FilterSubscriptionEntry
		if err := rows.Scan(&e.ID, &e.SubscriptionID, &e.Value, &e.Reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan entry: %w", err)
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []model.FilterSubscriptionEntry{}
	}
	return entries, nil
}

// ListExclusions returns host exclusions for a subscription
func (r *FilterSubscriptionRepository) ListExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionHostExclusion, error) {
	query := `SELECT id, subscription_id, proxy_host_id, created_at
		FROM filter_subscription_host_exclusions WHERE subscription_id = $1`

	rows, err := r.db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list exclusions: %w", err)
	}
	defer rows.Close()

	var exclusions []model.FilterSubscriptionHostExclusion
	for rows.Next() {
		var ex model.FilterSubscriptionHostExclusion
		if err := rows.Scan(&ex.ID, &ex.SubscriptionID, &ex.ProxyHostID, &ex.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan exclusion: %w", err)
		}
		exclusions = append(exclusions, ex)
	}

	if exclusions == nil {
		exclusions = []model.FilterSubscriptionHostExclusion{}
	}
	return exclusions, nil
}

// AddExclusion adds a host exclusion for a subscription
func (r *FilterSubscriptionRepository) AddExclusion(ctx context.Context, subscriptionID, hostID string) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO filter_subscription_host_exclusions (subscription_id, proxy_host_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		subscriptionID, hostID)
	if err != nil {
		return fmt.Errorf("failed to add exclusion: %w", err)
	}
	return nil
}

// RemoveExclusion removes a host exclusion for a subscription
func (r *FilterSubscriptionRepository) RemoveExclusion(ctx context.Context, subscriptionID, hostID string) error {
	_, err := r.db.ExecContext(ctx,
		"DELETE FROM filter_subscription_host_exclusions WHERE subscription_id = $1 AND proxy_host_id = $2",
		subscriptionID, hostID)
	if err != nil {
		return fmt.Errorf("failed to remove exclusion: %w", err)
	}
	return nil
}

// GetEnabledSubscriptions returns all enabled subscriptions
func (r *FilterSubscriptionRepository) GetEnabledSubscriptions(ctx context.Context) ([]model.FilterSubscription, error) {
	query := `SELECT id, name, COALESCE(description, ''), url, format, type, enabled,
		refresh_type, refresh_value, last_fetched_at, last_success_at, last_error,
		entry_count, created_at, updated_at
		FROM filter_subscriptions WHERE enabled = true`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get enabled subscriptions: %w", err)
	}
	defer rows.Close()

	var subs []model.FilterSubscription
	for rows.Next() {
		var s model.FilterSubscription
		err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.URL, &s.Format, &s.Type,
			&s.Enabled, &s.RefreshType, &s.RefreshValue, &s.LastFetchedAt, &s.LastSuccessAt,
			&s.LastError, &s.EntryCount, &s.CreatedAt, &s.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan subscription: %w", err)
		}
		subs = append(subs, s)
	}

	if subs == nil {
		subs = []model.FilterSubscription{}
	}
	return subs, nil
}

// GetSubscribedURLs returns all subscribed URLs for catalog display
func (r *FilterSubscriptionRepository) GetSubscribedURLs(ctx context.Context) (map[string]bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT url FROM filter_subscriptions")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	urls := make(map[string]bool)
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			return nil, err
		}
		urls[url] = true
	}
	return urls, nil
}
```

- [ ] **Step 2: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success

- [ ] **Step 3: Commit**

```bash
git add api/internal/repository/filter_subscription.go
git commit -m "feat: add filter subscription repository"
```

---

## Task 6: NPG Backend — Service (Fetch, Parse, Format Detection)

**Files:**
- Create: `api/internal/service/filter_subscription.go`

- [ ] **Step 1: Create service file**

```go
package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

type FilterSubscriptionService struct {
	repo             *repository.FilterSubscriptionRepository
	proxyHostService *ProxyHostService
	httpClient       *http.Client
}

func NewFilterSubscriptionService(
	repo *repository.FilterSubscriptionRepository,
	proxyHostService *ProxyHostService,
) *FilterSubscriptionService {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: config.FilterFetchConnectTimeout,
		}).DialContext,
	}

	client := &http.Client{
		Timeout:   config.FilterFetchTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.FilterMaxRedirects {
				return fmt.Errorf("too many redirects (max %d)", config.FilterMaxRedirects)
			}
			// Block redirects to private IPs
			if isPrivateAddr(req.URL.Hostname()) {
				return fmt.Errorf("redirect to private address blocked")
			}
			return nil
		},
	}

	return &FilterSubscriptionService{
		repo:             repo,
		proxyHostService: proxyHostService,
		httpClient:       client,
	}
}

// SetProxyHostService sets the proxy host service (for avoiding circular deps)
func (s *FilterSubscriptionService) SetProxyHostService(phs *ProxyHostService) {
	s.proxyHostService = phs
}

// List returns paginated filter subscriptions
func (s *FilterSubscriptionService) List(ctx context.Context, page, perPage int) (*model.FilterSubscriptionListResponse, error) {
	return s.repo.List(ctx, page, perPage)
}

// GetByID returns a subscription with its entries and exclusions
func (s *FilterSubscriptionService) GetByID(ctx context.Context, id string) (*model.FilterSubscriptionDetail, error) {
	sub, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	entries, err := s.repo.GetEntries(ctx, id)
	if err != nil {
		return nil, err
	}

	exclusions, err := s.repo.ListExclusions(ctx, id)
	if err != nil {
		return nil, err
	}

	return &model.FilterSubscriptionDetail{
		FilterSubscription: *sub,
		Entries:            entries,
		Exclusions:         exclusions,
	}, nil
}

// Create creates a new subscription: fetches URL, detects format, parses, stores entries
func (s *FilterSubscriptionService) Create(ctx context.Context, req *model.CreateFilterSubscriptionRequest) (*model.FilterSubscription, error) {
	// Check URL not already subscribed
	existing, err := s.repo.GetByURL(ctx, req.URL)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("already subscribed to this URL")
	}

	// Check total entry limit before fetching
	totalCount, err := s.repo.GetTotalEntryCount(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to check entry count: %w", err)
	}
	if totalCount >= config.FilterMaxTotalEntries {
		return nil, fmt.Errorf("total entry limit reached (%d)", config.FilterMaxTotalEntries)
	}

	// SSRF protection: block private addresses
	if isPrivateURL(req.URL) {
		return nil, fmt.Errorf("private/reserved addresses are not allowed")
	}

	// Fetch and parse
	body, err := s.fetchURL(ctx, req.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}

	format, filterType, name, description, entries, err := s.parseResponse(body, req)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Enforce per-file limit
	if len(entries) > config.FilterMaxEntriesPerFile {
		entries = entries[:config.FilterMaxEntriesPerFile]
	}

	// Enforce total limit
	if totalCount+len(entries) > config.FilterMaxTotalEntries {
		maxNew := config.FilterMaxTotalEntries - totalCount
		if maxNew <= 0 {
			return nil, fmt.Errorf("total entry limit reached (%d)", config.FilterMaxTotalEntries)
		}
		entries = entries[:maxNew]
	}

	// Set defaults
	refreshType := req.RefreshType
	if refreshType == "" {
		refreshType = "interval"
	}
	refreshValue := req.RefreshValue
	if refreshValue == "" {
		refreshValue = "24h"
	}

	sub := &model.FilterSubscription{
		Name:         name,
		Description:  description,
		URL:          req.URL,
		Format:       format,
		Type:         filterType,
		Enabled:      true,
		RefreshType:  refreshType,
		RefreshValue: refreshValue,
	}

	created, err := s.repo.Create(ctx, sub)
	if err != nil {
		return nil, err
	}

	// Store entries
	if len(entries) > 0 {
		if err := s.repo.ReplaceEntries(ctx, created.ID, entries); err != nil {
			// Rollback: delete the subscription
			s.repo.Delete(ctx, created.ID)
			return nil, fmt.Errorf("failed to store entries: %w", err)
		}
	}

	// Update fetch status
	s.repo.UpdateFetchStatus(ctx, created.ID, true, len(entries), "")

	// Trigger nginx config regeneration
	s.regenerateAllConfigs(ctx)

	return s.repo.GetByID(ctx, created.ID)
}

// Update modifies a subscription's settings
func (s *FilterSubscriptionService) Update(ctx context.Context, id string, req *model.UpdateFilterSubscriptionRequest) (*model.FilterSubscription, error) {
	sub, err := s.repo.Update(ctx, id, req)
	if err != nil {
		return nil, err
	}

	// If enabled state changed, regenerate configs
	if req.Enabled != nil {
		s.regenerateAllConfigs(ctx)
	}

	return sub, nil
}

// Delete removes a subscription and all its entries
func (s *FilterSubscriptionService) Delete(ctx context.Context, id string) error {
	err := s.repo.Delete(ctx, id)
	if err != nil {
		return err
	}

	s.regenerateAllConfigs(ctx)
	return nil
}

// Refresh re-fetches and updates a subscription's entries
func (s *FilterSubscriptionService) Refresh(ctx context.Context, id string) (*model.FilterSubscription, error) {
	sub, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	body, err := s.fetchURL(ctx, sub.URL)
	if err != nil {
		errMsg := err.Error()
		s.repo.UpdateFetchStatus(ctx, id, false, sub.EntryCount, errMsg)
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}

	req := &model.CreateFilterSubscriptionRequest{
		URL:  sub.URL,
		Name: sub.Name,
		Type: sub.Type,
	}
	_, _, _, _, entries, err := s.parseResponse(body, req)
	if err != nil {
		errMsg := err.Error()
		s.repo.UpdateFetchStatus(ctx, id, false, sub.EntryCount, errMsg)
		return nil, fmt.Errorf("failed to parse: %w", err)
	}

	// Empty response protection: keep existing entries
	if len(entries) == 0 {
		log.Printf("[FilterSubscription] Refresh for %s returned 0 entries, keeping existing %d entries", sub.Name, sub.EntryCount)
		s.repo.UpdateFetchStatus(ctx, id, true, sub.EntryCount, "")
		return s.repo.GetByID(ctx, id)
	}

	// Enforce per-file limit
	if len(entries) > config.FilterMaxEntriesPerFile {
		entries = entries[:config.FilterMaxEntriesPerFile]
	}

	if err := s.repo.ReplaceEntries(ctx, id, entries); err != nil {
		errMsg := err.Error()
		s.repo.UpdateFetchStatus(ctx, id, false, sub.EntryCount, errMsg)
		return nil, fmt.Errorf("failed to replace entries: %w", err)
	}

	s.repo.UpdateFetchStatus(ctx, id, true, len(entries), "")
	s.regenerateAllConfigs(ctx)

	return s.repo.GetByID(ctx, id)
}

// GetCatalog fetches the npg-filters index.json and marks subscribed lists
func (s *FilterSubscriptionService) GetCatalog(ctx context.Context) (*model.FilterCatalog, error) {
	body, err := s.fetchURL(ctx, config.FilterCatalogIndexURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch catalog: %w", err)
	}

	var catalog model.FilterCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse catalog: %w", err)
	}

	// Mark subscribed lists
	subscribedURLs, err := s.repo.GetSubscribedURLs(ctx)
	if err != nil {
		return &catalog, nil // Return catalog even if we can't check subscribed status
	}

	for i := range catalog.Lists {
		fullURL := config.FilterCatalogBaseURL + catalog.Lists[i].Path
		catalog.Lists[i].Subscribed = subscribedURLs[fullURL]
	}

	return &catalog, nil
}

// SubscribeFromCatalog subscribes to multiple lists from the catalog
func (s *FilterSubscriptionService) SubscribeFromCatalog(ctx context.Context, req *model.CatalogSubscribeRequest) ([]model.FilterSubscription, error) {
	var results []model.FilterSubscription

	for _, path := range req.Paths {
		fullURL := config.FilterCatalogBaseURL + path

		createReq := &model.CreateFilterSubscriptionRequest{
			URL:          fullURL,
			RefreshType:  req.RefreshType,
			RefreshValue: req.RefreshValue,
		}

		sub, err := s.Create(ctx, createReq)
		if err != nil {
			log.Printf("[FilterSubscription] Failed to subscribe to %s: %v", path, err)
			continue
		}
		results = append(results, *sub)
	}

	return results, nil
}

// AddHostExclusion adds a host exclusion
func (s *FilterSubscriptionService) AddHostExclusion(ctx context.Context, subscriptionID, hostID string) error {
	if err := s.repo.AddExclusion(ctx, subscriptionID, hostID); err != nil {
		return err
	}
	s.regenerateConfigForHost(ctx, hostID)
	return nil
}

// RemoveHostExclusion removes a host exclusion
func (s *FilterSubscriptionService) RemoveHostExclusion(ctx context.Context, subscriptionID, hostID string) error {
	if err := s.repo.RemoveExclusion(ctx, subscriptionID, hostID); err != nil {
		return err
	}
	s.regenerateConfigForHost(ctx, hostID)
	return nil
}

// ListExclusions returns host exclusions for a subscription
func (s *FilterSubscriptionService) ListExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionHostExclusion, error) {
	return s.repo.ListExclusions(ctx, subscriptionID)
}

// GetEntriesForHost returns applicable entries for a host, used by nginx config generation
func (s *FilterSubscriptionService) GetEntriesForHost(ctx context.Context, hostID string, filterType string) ([]model.FilterSubscriptionEntry, error) {
	return s.repo.GetEntriesForHost(ctx, hostID, filterType)
}

// --- Internal methods ---

func (s *FilterSubscriptionService) fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NginxProxyGuard/"+config.AppVersion)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Limit response size
	limited := io.LimitReader(resp.Body, int64(config.FilterMaxResponseSize)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if len(body) > config.FilterMaxResponseSize {
		return nil, fmt.Errorf("response too large (max %d bytes)", config.FilterMaxResponseSize)
	}

	return body, nil
}

func (s *FilterSubscriptionService) parseResponse(body []byte, req *model.CreateFilterSubscriptionRequest) (format, filterType, name, description string, entries []model.FilterSubscriptionEntry, err error) {
	// Try npg-json format first
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var npgList model.NPGFilterList
		if jsonErr := json.Unmarshal(body, &npgList); jsonErr == nil && len(npgList.Entries) > 0 {
			format = "npg-json"
			filterType = npgList.Type
			name = npgList.Name
			description = npgList.Description

			for _, e := range npgList.Entries {
				if !s.validateEntryValue(filterType, e.Value) {
					continue
				}
				entries = append(entries, model.FilterSubscriptionEntry{
					Value:  e.Value,
					Reason: e.Reason,
				})
			}
			return
		}
	}

	// Plaintext format (ip/cidr only)
	format = "plaintext"
	name = req.Name
	if name == "" {
		name = "Custom Filter"
	}
	filterType = req.Type

	scanner := bufio.NewScanner(strings.NewReader(trimmed))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Extract IP/CIDR, ignore trailing comments or metadata
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		value := parts[0]

		// Remove trailing semicolons (Spamhaus format)
		value = strings.TrimRight(value, ";")

		// Auto-detect type from value
		detectedType := ""
		if strings.Contains(value, "/") {
			if isValidCIDR(value) {
				detectedType = "cidr"
			}
		} else if isValidIP(value) {
			detectedType = "ip"
		}

		if detectedType == "" {
			continue
		}

		// Set type from first valid entry if not specified
		if filterType == "" {
			filterType = detectedType
		}

		if isPrivateAddr(value) {
			continue
		}

		entries = append(entries, model.FilterSubscriptionEntry{
			Value:  value,
			Reason: "Imported from external list",
		})
	}

	if filterType == "" {
		filterType = "ip"
	}

	return
}

func (s *FilterSubscriptionService) validateEntryValue(filterType, value string) bool {
	switch filterType {
	case "ip":
		return isValidIP(value) && !isPrivateAddr(value)
	case "cidr":
		return isValidCIDR(value) && !isPrivateAddr(value)
	case "user_agent":
		_, err := regexp.Compile(value)
		return err == nil
	}
	return false
}

func (s *FilterSubscriptionService) regenerateAllConfigs(ctx context.Context) {
	if s.proxyHostService == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[FilterSubscription] panic during config regeneration: %v", r)
			}
		}()
		bgCtx := context.Background()
		if err := s.proxyHostService.RegenerateAllConfigs(bgCtx); err != nil {
			log.Printf("[FilterSubscription] Failed to regenerate configs: %v", err)
		}
	}()
}

func (s *FilterSubscriptionService) regenerateConfigForHost(ctx context.Context, hostID string) {
	if s.proxyHostService == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[FilterSubscription] panic during host config regeneration: %v", r)
			}
		}()
		bgCtx := context.Background()
		if _, err := s.proxyHostService.Update(bgCtx, hostID, &model.UpdateProxyHostRequest{}); err != nil {
			log.Printf("[FilterSubscription] Failed to regenerate config for host %s: %v", hostID, err)
		}
	}()
}

// --- Helper functions ---

func isPrivateURL(rawURL string) bool {
	// Extract hostname from URL
	parts := strings.Split(rawURL, "//")
	if len(parts) < 2 {
		return false
	}
	hostPart := strings.Split(parts[1], "/")[0]
	hostPart = strings.Split(hostPart, ":")[0]
	return isPrivateAddr(hostPart)
}

func isPrivateAddr(addr string) bool {
	// Remove CIDR suffix if present
	host := addr
	if idx := strings.Index(addr, "/"); idx != -1 {
		host = addr[:idx]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// Try resolving hostname
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	privateNets := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	}

	for _, cidr := range privateNets {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isValidIP(value string) bool {
	return net.ParseIP(value) != nil
}

func isValidCIDR(value string) bool {
	_, _, err := net.ParseCIDR(value)
	return err == nil
}
```

- [ ] **Step 2: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success (may have unused import warnings if `RegenerateAllConfigs` doesn't exist yet — that's fine, it will be wired in Task 9)

- [ ] **Step 3: Commit**

```bash
git add api/internal/service/filter_subscription.go
git commit -m "feat: add filter subscription service with fetch, parse, and format detection"
```

---

## Task 7: NPG Backend — Handler

**Files:**
- Create: `api/internal/handler/filter_subscription.go`

- [ ] **Step 1: Create handler file**

```go
package handler

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type FilterSubscriptionHandler struct {
	service *service.FilterSubscriptionService
	audit   *service.AuditService
}

func NewFilterSubscriptionHandler(
	svc *service.FilterSubscriptionService,
	audit *service.AuditService,
) *FilterSubscriptionHandler {
	return &FilterSubscriptionHandler{
		service: svc,
		audit:   audit,
	}
}

func (h *FilterSubscriptionHandler) List(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	result, err := h.service.List(c.Request().Context(), page, perPage)
	if err != nil {
		return databaseError(c, "list filter subscriptions", err)
	}
	return c.JSON(http.StatusOK, result)
}

func (h *FilterSubscriptionHandler) GetByID(c echo.Context) error {
	id := c.Param("id")
	detail, err := h.service.GetByID(c.Request().Context(), id)
	if err != nil {
		return classifyError(c, "get filter subscription", err)
	}
	return c.JSON(http.StatusOK, detail)
}

func (h *FilterSubscriptionHandler) Create(c echo.Context) error {
	var req model.CreateFilterSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if req.URL == "" {
		return badRequestError(c, "url is required")
	}

	sub, err := h.service.Create(c.Request().Context(), &req)
	if err != nil {
		return classifyError(c, "create filter subscription", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogAction(auditCtx, "filter_subscription_create", sub.Name, "")

	return c.JSON(http.StatusCreated, sub)
}

func (h *FilterSubscriptionHandler) Update(c echo.Context) error {
	id := c.Param("id")
	var req model.UpdateFilterSubscriptionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	sub, err := h.service.Update(c.Request().Context(), id, &req)
	if err != nil {
		return classifyError(c, "update filter subscription", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogAction(auditCtx, "filter_subscription_update", sub.Name, "")

	return c.JSON(http.StatusOK, sub)
}

func (h *FilterSubscriptionHandler) Delete(c echo.Context) error {
	id := c.Param("id")

	// Get name for audit log before deleting
	detail, _ := h.service.GetByID(c.Request().Context(), id)
	name := id
	if detail != nil {
		name = detail.Name
	}

	if err := h.service.Delete(c.Request().Context(), id); err != nil {
		return classifyError(c, "delete filter subscription", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogAction(auditCtx, "filter_subscription_delete", name, "")

	return c.NoContent(http.StatusNoContent)
}

func (h *FilterSubscriptionHandler) Refresh(c echo.Context) error {
	id := c.Param("id")

	sub, err := h.service.Refresh(c.Request().Context(), id)
	if err != nil {
		return classifyError(c, "refresh filter subscription", err)
	}
	return c.JSON(http.StatusOK, sub)
}

func (h *FilterSubscriptionHandler) GetCatalog(c echo.Context) error {
	catalog, err := h.service.GetCatalog(c.Request().Context())
	if err != nil {
		return databaseError(c, "get filter catalog", err)
	}
	return c.JSON(http.StatusOK, catalog)
}

func (h *FilterSubscriptionHandler) SubscribeFromCatalog(c echo.Context) error {
	var req model.CatalogSubscribeRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}
	if len(req.Paths) == 0 {
		return badRequestError(c, "paths is required")
	}

	subs, err := h.service.SubscribeFromCatalog(c.Request().Context(), &req)
	if err != nil {
		return classifyError(c, "subscribe from catalog", err)
	}

	auditCtx := service.ContextWithAudit(c.Request().Context(), c)
	h.audit.LogAction(auditCtx, "filter_subscription_catalog_subscribe", "", "")

	return c.JSON(http.StatusCreated, subs)
}

func (h *FilterSubscriptionHandler) ListExclusions(c echo.Context) error {
	id := c.Param("id")
	exclusions, err := h.service.ListExclusions(c.Request().Context(), id)
	if err != nil {
		return databaseError(c, "list exclusions", err)
	}
	return c.JSON(http.StatusOK, exclusions)
}

func (h *FilterSubscriptionHandler) AddExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")
	hostID := c.Param("hostId")

	if err := h.service.AddHostExclusion(c.Request().Context(), subscriptionID, hostID); err != nil {
		return classifyError(c, "add exclusion", err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *FilterSubscriptionHandler) RemoveExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")
	hostID := c.Param("hostId")

	if err := h.service.RemoveHostExclusion(c.Request().Context(), subscriptionID, hostID); err != nil {
		return classifyError(c, "remove exclusion", err)
	}
	return c.NoContent(http.StatusNoContent)
}
```

- [ ] **Step 2: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success

- [ ] **Step 3: Commit**

```bash
git add api/internal/handler/filter_subscription.go
git commit -m "feat: add filter subscription HTTP handler"
```

---

## Task 8: NPG Backend — Scheduler

**Files:**
- Create: `api/internal/scheduler/filter_refresh.go`

- [ ] **Step 1: Create scheduler file**

```go
package scheduler

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

type FilterRefreshScheduler struct {
	service  *service.FilterSubscriptionService
	interval time.Duration
	stopChan chan struct{}
	running  bool
}

func NewFilterRefreshScheduler(svc *service.FilterSubscriptionService) *FilterRefreshScheduler {
	return &FilterRefreshScheduler{
		service:  svc,
		interval: config.FilterRefreshCheckInterval,
		stopChan: make(chan struct{}),
	}
}

func (s *FilterRefreshScheduler) Start() {
	if s.running {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] Filter refresh scheduler started (check interval: %v)", s.interval)
}

func (s *FilterRefreshScheduler) Stop() {
	if !s.running {
		return
	}
	close(s.stopChan)
	s.running = false
	log.Println("[Scheduler] Filter refresh scheduler stopped")
}

func (s *FilterRefreshScheduler) run() {
	// Initial delay to let other services start
	time.Sleep(30 * time.Second)
	s.checkAndRefresh()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndRefresh()
		case <-s.stopChan:
			return
		}
	}
}

func (s *FilterRefreshScheduler) checkAndRefresh() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[FilterRefresh] panic recovered: %v", r)
		}
	}()

	ctx := context.Background()
	subs, err := s.service.List(ctx, 1, 1000)
	if err != nil {
		log.Printf("[FilterRefresh] Failed to list subscriptions: %v", err)
		return
	}

	now := time.Now()
	for _, sub := range subs.Data {
		if !sub.Enabled {
			continue
		}

		if !s.shouldRefresh(&sub, now) {
			continue
		}

		log.Printf("[FilterRefresh] Refreshing subscription: %s (%s)", sub.Name, sub.URL)
		if _, err := s.service.Refresh(ctx, sub.ID); err != nil {
			log.Printf("[FilterRefresh] Failed to refresh %s: %v", sub.Name, err)
		} else {
			log.Printf("[FilterRefresh] Successfully refreshed %s", sub.Name)
		}
	}
}

func (s *FilterRefreshScheduler) shouldRefresh(sub *model.FilterSubscription, now time.Time) bool {
	switch sub.RefreshType {
	case "interval":
		return s.shouldRefreshInterval(sub, now)
	case "daily":
		return s.shouldRefreshDaily(sub, now)
	case "cron":
		return s.shouldRefreshCron(sub, now)
	default:
		return false
	}
}

func (s *FilterRefreshScheduler) shouldRefreshInterval(sub *model.FilterSubscription, now time.Time) bool {
	if sub.LastFetchedAt == nil {
		return true
	}

	interval, err := parseDuration(sub.RefreshValue)
	if err != nil {
		log.Printf("[FilterRefresh] Invalid interval '%s' for %s: %v", sub.RefreshValue, sub.Name, err)
		return false
	}

	return now.After(sub.LastFetchedAt.Add(interval))
}

func (s *FilterRefreshScheduler) shouldRefreshDaily(sub *model.FilterSubscription, now time.Time) bool {
	parts := strings.Split(sub.RefreshValue, ":")
	if len(parts) != 2 {
		return false
	}

	hour, err1 := strconv.Atoi(parts[0])
	minute, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}

	targetToday := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())

	// Check if target time has passed and we haven't fetched since then
	if now.After(targetToday) {
		if sub.LastFetchedAt == nil || sub.LastFetchedAt.Before(targetToday) {
			return true
		}
	}

	return false
}

func (s *FilterRefreshScheduler) shouldRefreshCron(sub *model.FilterSubscription, now time.Time) bool {
	// Simple cron: parse "minute hour * * *" format
	// For full cron support, consider using a cron library
	parts := strings.Fields(sub.RefreshValue)
	if len(parts) < 5 {
		return false
	}

	minuteSpec := parts[0]
	hourSpec := parts[1]

	// Check if current time matches the cron spec
	matchMinute := matchCronField(minuteSpec, now.Minute())
	matchHour := matchCronField(hourSpec, now.Hour())

	if matchMinute && matchHour {
		// Check we haven't already run in this matching window
		if sub.LastFetchedAt == nil {
			return true
		}
		// Allow one run per matching window (within check interval)
		return now.Sub(*sub.LastFetchedAt) > s.interval
	}

	return false
}

func matchCronField(spec string, value int) bool {
	if spec == "*" {
		return true
	}

	// Handle */N (every N)
	if strings.HasPrefix(spec, "*/") {
		n, err := strconv.Atoi(strings.TrimPrefix(spec, "*/"))
		if err != nil || n == 0 {
			return false
		}
		return value%n == 0
	}

	// Handle exact value
	n, err := strconv.Atoi(spec)
	if err != nil {
		return false
	}
	return value == n
}

func parseDuration(s string) (time.Duration, error) {
	// Support "Nh" format
	if strings.HasSuffix(s, "h") {
		hours, err := strconv.Atoi(strings.TrimSuffix(s, "h"))
		if err != nil {
			return 0, err
		}
		return time.Duration(hours) * time.Hour, nil
	}

	return 0, fmt.Errorf("unsupported duration format: %s", s)
}
```

- [ ] **Step 2: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success

- [ ] **Step 3: Commit**

```bash
git add api/internal/scheduler/filter_refresh.go
git commit -m "feat: add filter refresh scheduler"
```

---

## Task 9: NPG Backend — Nginx Config Integration and DI Wiring

**Files:**
- Modify: `api/internal/nginx/proxy_host_template.go` (add fields to `ProxyHostConfigData`)
- Modify: `api/internal/service/proxy_host_config.go` (fetch filter entries in `getHostConfigData`)
- Modify: `api/cmd/server/main.go` (DI wiring + route registration + scheduler start)

- [ ] **Step 1: Add fields to `ProxyHostConfigData` in `proxy_host_template.go`**

Add two new fields to the `ProxyHostConfigData` struct (after `ExploitBlockRules` field, around line 1649):

```go
	FilterSubscriptionIPs  []string // IP/CIDR entries from filter subscriptions
	FilterSubscriptionUAs  []string // User-Agent patterns from filter subscriptions
```

- [ ] **Step 2: Add filter subscription IP rendering to nginx template**

In the banned IPs geo mapping section (around line 26-34 of the template), add filter subscription IPs alongside banned IPs:

Find the existing geo mapping block and extend it to include filter subscription IPs. The entries should be rendered the same way as banned IPs in the `geo $banned_ip_` block:

```nginx
{{range .FilterSubscriptionIPs}}
    {{.}} 1; # filter subscription
{{end}}
```

- [ ] **Step 3: Add filter subscription UA rendering**

In the bot filter section, add filter subscription UAs to the custom blocked agents pattern. This needs to be appended to the existing `toRegexPattern` call for custom blocked agents. If the bot filter is not enabled but there are subscription UAs, a standalone UA block section should be generated.

- [ ] **Step 4: Modify `getHostConfigData` in `proxy_host_config.go`**

Add a goroutine to fetch filter subscription entries alongside existing data fetches. Add after the bot filter fetch block:

```go
	// Fetch filter subscription entries for this host
	if s.filterSubscriptionRepo != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ipEntries, err := s.filterSubscriptionRepo.GetEntriesForHost(ctx, host.ID, "ip")
			if err == nil {
				cidrEntries, err2 := s.filterSubscriptionRepo.GetEntriesForHost(ctx, host.ID, "cidr")
				if err2 == nil {
					var ips []string
					for _, e := range ipEntries {
						ips = append(ips, e.Value)
					}
					for _, e := range cidrEntries {
						ips = append(ips, e.Value)
					}
					mu.Lock()
					data.FilterSubscriptionIPs = ips
					mu.Unlock()
				}
			}
		}()
		go func() {
			defer wg.Done()
			uaEntries, err := s.filterSubscriptionRepo.GetEntriesForHost(ctx, host.ID, "user_agent")
			if err == nil {
				var uas []string
				for _, e := range uaEntries {
					uas = append(uas, e.Value)
				}
				mu.Lock()
				data.FilterSubscriptionUAs = uas
				mu.Unlock()
			}
		}()
	}
```

Also add `filterSubscriptionRepo` field to the `ProxyHostService` struct and wire it via constructor or setter.

- [ ] **Step 5: Wire DI in `main.go`**

Add after existing repository creation:

```go
filterSubscriptionRepo := repository.NewFilterSubscriptionRepository(db.DB)
```

Add service creation:

```go
filterSubscriptionService := service.NewFilterSubscriptionService(filterSubscriptionRepo, proxyHostService)
```

Wire the repo into ProxyHostService (add a setter or constructor param):

```go
proxyHostService.SetFilterSubscriptionRepo(filterSubscriptionRepo)
```

Add handler creation:

```go
filterSubscriptionHandler := handler.NewFilterSubscriptionHandler(filterSubscriptionService, auditService)
```

Add route registration in the `v1` group:

```go
		filterSubs := v1.Group("/filter-subscriptions")
		{
			filterSubs.GET("/catalog", filterSubscriptionHandler.GetCatalog)
			filterSubs.POST("/catalog/subscribe", filterSubscriptionHandler.SubscribeFromCatalog)
			filterSubs.GET("", filterSubscriptionHandler.List)
			filterSubs.POST("", filterSubscriptionHandler.Create)
			filterSubs.GET("/:id", filterSubscriptionHandler.GetByID)
			filterSubs.PUT("/:id", filterSubscriptionHandler.Update)
			filterSubs.DELETE("/:id", filterSubscriptionHandler.Delete)
			filterSubs.POST("/:id/refresh", filterSubscriptionHandler.Refresh)
			filterSubs.GET("/:id/exclusions", filterSubscriptionHandler.ListExclusions)
			filterSubs.POST("/:id/exclusions/:hostId", filterSubscriptionHandler.AddExclusion)
			filterSubs.DELETE("/:id/exclusions/:hostId", filterSubscriptionHandler.RemoveExclusion)
		}
```

**Important:** `/catalog` routes must be registered BEFORE `/:id` to avoid `catalog` being matched as an ID parameter.

Add scheduler start:

```go
filterRefreshScheduler := scheduler.NewFilterRefreshScheduler(filterSubscriptionService)
filterRefreshScheduler.Start()
defer filterRefreshScheduler.Stop()
```

- [ ] **Step 6: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build success

- [ ] **Step 7: Commit**

```bash
git add api/internal/nginx/proxy_host_template.go api/internal/service/proxy_host_config.go api/cmd/server/main.go
git commit -m "feat: wire filter subscription into nginx config generation and DI"
```

---

## Task 10: NPG Frontend — Types and API Client

**Files:**
- Create: `ui/src/types/filter-subscription.ts`
- Create: `ui/src/api/filter-subscriptions.ts`

- [ ] **Step 1: Create TypeScript types (`ui/src/types/filter-subscription.ts`)**

```typescript
export interface FilterSubscription {
  id: string;
  name: string;
  description?: string;
  url: string;
  format: string;
  type: string;
  enabled: boolean;
  refresh_type: string;
  refresh_value: string;
  last_fetched_at?: string;
  last_success_at?: string;
  last_error?: string;
  entry_count: number;
  created_at: string;
  updated_at: string;
}

export interface FilterSubscriptionEntry {
  id: string;
  subscription_id: string;
  value: string;
  reason?: string;
  created_at: string;
}

export interface FilterSubscriptionHostExclusion {
  id: string;
  subscription_id: string;
  proxy_host_id: string;
  created_at: string;
}

export interface FilterSubscriptionDetail extends FilterSubscription {
  entries: FilterSubscriptionEntry[];
  exclusions: FilterSubscriptionHostExclusion[];
}

export interface FilterSubscriptionListResponse {
  data: FilterSubscription[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface CreateFilterSubscriptionRequest {
  url: string;
  name?: string;
  type?: string;
  refresh_type?: string;
  refresh_value?: string;
}

export interface UpdateFilterSubscriptionRequest {
  name?: string;
  enabled?: boolean;
  refresh_type?: string;
  refresh_value?: string;
}

export interface CatalogSubscribeRequest {
  paths: string[];
  refresh_type?: string;
  refresh_value?: string;
}

export interface FilterCatalog {
  version: number;
  generated_at: string;
  lists: FilterCatalogEntry[];
}

export interface FilterCatalogEntry {
  name: string;
  description: string;
  type: string;
  path: string;
  entry_count: number;
  updated_at: string;
  subscribed?: boolean;
}
```

- [ ] **Step 2: Create API client (`ui/src/api/filter-subscriptions.ts`)**

```typescript
import type {
  FilterSubscriptionListResponse,
  FilterSubscriptionDetail,
  FilterSubscription,
  CreateFilterSubscriptionRequest,
  UpdateFilterSubscriptionRequest,
  CatalogSubscribeRequest,
  FilterCatalog,
  FilterSubscriptionHostExclusion,
} from '../types/filter-subscription';
import { apiGet, apiPost, apiPut, apiDelete } from './client';

const API_BASE = '/api/v1/filter-subscriptions';

export async function fetchFilterSubscriptions(
  page = 1,
  perPage = 20
): Promise<FilterSubscriptionListResponse> {
  return apiGet<FilterSubscriptionListResponse>(
    `${API_BASE}?page=${page}&per_page=${perPage}`
  );
}

export async function fetchFilterSubscription(id: string): Promise<FilterSubscriptionDetail> {
  return apiGet<FilterSubscriptionDetail>(`${API_BASE}/${id}`);
}

export async function createFilterSubscription(
  data: CreateFilterSubscriptionRequest
): Promise<FilterSubscription> {
  return apiPost<FilterSubscription>(API_BASE, data);
}

export async function updateFilterSubscription(
  id: string,
  data: UpdateFilterSubscriptionRequest
): Promise<FilterSubscription> {
  return apiPut<FilterSubscription>(`${API_BASE}/${id}`, data);
}

export async function deleteFilterSubscription(id: string): Promise<void> {
  return apiDelete(`${API_BASE}/${id}`);
}

export async function refreshFilterSubscription(id: string): Promise<FilterSubscription> {
  return apiPost<FilterSubscription>(`${API_BASE}/${id}/refresh`);
}

export async function fetchFilterCatalog(): Promise<FilterCatalog> {
  return apiGet<FilterCatalog>(`${API_BASE}/catalog`);
}

export async function subscribeFromCatalog(
  data: CatalogSubscribeRequest
): Promise<FilterSubscription[]> {
  return apiPost<FilterSubscription[]>(`${API_BASE}/catalog/subscribe`, data);
}

export async function fetchExclusions(
  subscriptionId: string
): Promise<FilterSubscriptionHostExclusion[]> {
  return apiGet<FilterSubscriptionHostExclusion[]>(
    `${API_BASE}/${subscriptionId}/exclusions`
  );
}

export async function addExclusion(
  subscriptionId: string,
  hostId: string
): Promise<void> {
  await apiPost(`${API_BASE}/${subscriptionId}/exclusions/${hostId}`);
}

export async function removeExclusion(
  subscriptionId: string,
  hostId: string
): Promise<void> {
  return apiDelete(`${API_BASE}/${subscriptionId}/exclusions/${hostId}`);
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/types/filter-subscription.ts ui/src/api/filter-subscriptions.ts
git commit -m "feat: add filter subscription TypeScript types and API client"
```

---

## Task 11: NPG Frontend — i18n Translations

**Files:**
- Create: `ui/src/i18n/locales/ko/filterSubscription.json`
- Create: `ui/src/i18n/locales/en/filterSubscription.json`
- Modify: `ui/src/i18n/index.ts`

- [ ] **Step 1: Create Korean translations**

```json
{
  "title": "필터 구독",
  "tabs": {
    "catalog": "카탈로그",
    "subscriptions": "내 구독"
  },
  "catalog": {
    "title": "NPG 필터 카탈로그",
    "description": "커뮤니티가 관리하는 보안 필터 리스트입니다.",
    "empty": "카탈로그를 불러올 수 없습니다.",
    "subscribe": "선택한 항목 구독",
    "subscribed": "구독 중",
    "entries": "{{count}}개 항목",
    "fetchError": "카탈로그를 가져올 수 없습니다."
  },
  "list": {
    "empty": "구독 중인 필터가 없습니다.",
    "addUrl": "URL로 추가",
    "lastFetch": "마지막 갱신",
    "status": {
      "ok": "정상",
      "error": "오류",
      "never": "미갱신"
    }
  },
  "form": {
    "url": "필터 리스트 URL",
    "urlPlaceholder": "https://example.com/blocklist.json",
    "name": "이름",
    "namePlaceholder": "자동 감지 또는 직접 입력",
    "type": "타입",
    "refreshType": "갱신 방식",
    "refreshValue": "갱신 값",
    "refreshTypes": {
      "interval": "주기별",
      "daily": "매일",
      "cron": "고급 (Cron)"
    },
    "intervals": {
      "6h": "6시간",
      "12h": "12시간",
      "24h": "24시간",
      "48h": "48시간"
    }
  },
  "settings": {
    "title": "구독 설정",
    "exclusions": "호스트 제외 설정",
    "exclusionDescription": "선택한 호스트에는 이 필터가 적용되지 않습니다.",
    "excluded": "제외됨"
  },
  "actions": {
    "refresh": "지금 갱신",
    "refreshing": "갱신 중...",
    "delete": "구독 삭제",
    "deleteConfirm": "이 필터 구독을 삭제하시겠습니까? 모든 항목이 제거됩니다.",
    "settings": "설정"
  },
  "types": {
    "ip": "IP",
    "cidr": "CIDR",
    "user_agent": "User Agent"
  },
  "messages": {
    "created": "필터 구독이 추가되었습니다.",
    "deleted": "필터 구독이 삭제되었습니다.",
    "refreshed": "필터가 갱신되었습니다.",
    "updated": "설정이 저장되었습니다.",
    "catalogSubscribed": "선택한 필터가 구독되었습니다."
  },
  "badge": {
    "filterSubscription": "필터 구독"
  }
}
```

- [ ] **Step 2: Create English translations**

```json
{
  "title": "Filter Subscriptions",
  "tabs": {
    "catalog": "Catalog",
    "subscriptions": "My Subscriptions"
  },
  "catalog": {
    "title": "NPG Filter Catalog",
    "description": "Community-maintained security filter lists.",
    "empty": "Could not load catalog.",
    "subscribe": "Subscribe Selected",
    "subscribed": "Subscribed",
    "entries": "{{count}} entries",
    "fetchError": "Failed to fetch catalog."
  },
  "list": {
    "empty": "No active filter subscriptions.",
    "addUrl": "Add by URL",
    "lastFetch": "Last refresh",
    "status": {
      "ok": "OK",
      "error": "Error",
      "never": "Never"
    }
  },
  "form": {
    "url": "Filter List URL",
    "urlPlaceholder": "https://example.com/blocklist.json",
    "name": "Name",
    "namePlaceholder": "Auto-detected or enter manually",
    "type": "Type",
    "refreshType": "Refresh Method",
    "refreshValue": "Refresh Value",
    "refreshTypes": {
      "interval": "Interval",
      "daily": "Daily",
      "cron": "Advanced (Cron)"
    },
    "intervals": {
      "6h": "Every 6 hours",
      "12h": "Every 12 hours",
      "24h": "Every 24 hours",
      "48h": "Every 48 hours"
    }
  },
  "settings": {
    "title": "Subscription Settings",
    "exclusions": "Host Exclusions",
    "exclusionDescription": "Selected hosts will not have this filter applied.",
    "excluded": "Excluded"
  },
  "actions": {
    "refresh": "Refresh Now",
    "refreshing": "Refreshing...",
    "delete": "Delete Subscription",
    "deleteConfirm": "Delete this filter subscription? All entries will be removed.",
    "settings": "Settings"
  },
  "types": {
    "ip": "IP",
    "cidr": "CIDR",
    "user_agent": "User Agent"
  },
  "messages": {
    "created": "Filter subscription added.",
    "deleted": "Filter subscription deleted.",
    "refreshed": "Filter refreshed.",
    "updated": "Settings saved.",
    "catalogSubscribed": "Selected filters subscribed."
  },
  "badge": {
    "filterSubscription": "Filter Subscription"
  }
}
```

- [ ] **Step 3: Register namespace in `ui/src/i18n/index.ts`**

Add import for the new namespace files and add `filterSubscription` to both `ko` and `en` resource objects, and add `'filterSubscription'` to the `ns` array in the i18n init config.

- [ ] **Step 4: Commit**

```bash
git add ui/src/i18n/
git commit -m "feat: add filter subscription i18n translations"
```

---

## Task 12: NPG Frontend — FilterSubscriptionList Component

**Files:**
- Create: `ui/src/components/FilterSubscriptionList.tsx`

- [ ] **Step 1: Create the main component**

This component should implement:

1. **Two tabs:** Catalog and My Subscriptions
2. **Catalog tab:** Fetches `fetchFilterCatalog()`, groups by type (IP/CIDR/UA), shows checkboxes, subscribe button with refresh settings modal
3. **My Subscriptions tab:** Fetches `fetchFilterSubscriptions()`, shows list with status, refresh/settings/delete actions
4. **Add URL modal:** URL input, optional name, refresh type/value selectors
5. **Settings modal:** Edit refresh settings + host exclusion checkboxes (fetches proxy hosts list)

Use `useQuery`/`useMutation` from React Query, `useTranslation('filterSubscription')`, Tailwind classes matching existing patterns (card, button, input styles from CLAUDE.md), dark mode support.

The component should be under 600 lines. If it exceeds that, split into:
- `FilterSubscriptionList.tsx` — main page with tabs
- `FilterCatalogTab.tsx` — catalog tab content
- `FilterSubscriptionTab.tsx` — subscriptions tab content

Use the existing component patterns from the codebase: modal overlay with `fixed inset-0 bg-black/50`, card with `bg-white dark:bg-slate-800 rounded-lg shadow p-6`, buttons with `px-4 py-2 rounded-lg font-medium transition-colors`.

- [ ] **Step 2: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build ui
```

Expected: Build success

- [ ] **Step 3: Commit**

```bash
git add ui/src/components/FilterSubscriptionList.tsx
git commit -m "feat: add filter subscription list component"
```

---

## Task 13: NPG Frontend — Route and Navigation Integration

**Files:**
- Modify: `ui/src/App.tsx`

- [ ] **Step 1: Add import for FilterSubscriptionList**

Add at the top of App.tsx with the other lazy imports:

```typescript
const FilterSubscriptionList = lazy(() => import('./components/FilterSubscriptionList'))
```

- [ ] **Step 2: Add route**

Add in the Routes section, after the existing settings routes:

```typescript
<Route path="/settings/filter-subscriptions" element={<SettingsPage subTab="filter-subscriptions" />} />
```

- [ ] **Step 3: Update SettingsPage type and rendering**

Update the `subTab` union type in SettingsPage function signature to include `'filter-subscriptions'`:

```typescript
function SettingsPage({ subTab }: { subTab: 'global' | 'captcha' | 'geoip' | 'ssl' | 'maintenance' | 'backups' | 'botfilter' | 'waf-auto-ban' | 'system-logs' | 'filter-subscriptions' }) {
```

Add a tab button for filter subscriptions (use `cyan` color to distinguish):

```typescript
<button
  onClick={() => navigate('/settings/filter-subscriptions')}
  className={`pb-2 text-[13px] font-semibold border-b-2 transition-colors whitespace-nowrap ${subTab === 'filter-subscriptions'
    ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
    : 'border-transparent text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
    }`}
>
  {t('subTabs.settings.filterSubscriptions', 'Filter Subscriptions')}
</button>
```

Add the rendering:

```typescript
{subTab === 'filter-subscriptions' && <FilterSubscriptionList />}
```

- [ ] **Step 4: Add navigation i18n key**

Add to `ui/src/i18n/locales/ko/navigation.json`:
```json
"filterSubscriptions": "필터 구독"
```

Add to `ui/src/i18n/locales/en/navigation.json`:
```json
"filterSubscriptions": "Filter Subscriptions"
```

(Under `subTabs.settings` key)

- [ ] **Step 5: Build to verify**

```bash
docker compose -f docker-compose.dev.yml build ui
```

Expected: Build success

- [ ] **Step 6: Commit**

```bash
git add ui/src/App.tsx ui/src/i18n/locales/
git commit -m "feat: add filter subscription route and navigation tab"
```

---

## Task 14: Full Integration Build and Test

- [ ] **Step 1: Full dev build**

```bash
docker compose -f docker-compose.dev.yml build api ui
```

Expected: Both build successfully

- [ ] **Step 2: Start dev environment**

```bash
docker compose -f docker-compose.dev.yml up -d
```

- [ ] **Step 3: Verify API endpoints manually**

```bash
# List subscriptions (should return empty)
docker compose exec api wget -qO- "http://localhost:8080/api/v1/filter-subscriptions" 2>/dev/null || \
docker compose -f docker-compose.dev.yml exec api wget -qO- "http://localhost:8080/api/v1/filter-subscriptions"

# Get catalog
docker compose -f docker-compose.dev.yml exec api wget -qO- "http://localhost:8080/api/v1/filter-subscriptions/catalog"
```

- [ ] **Step 4: Verify UI loads**

Navigate to the settings page and verify the "Filter Subscriptions" tab appears and renders without errors.

- [ ] **Step 5: E2E test environment build**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api ui
sudo docker compose -f docker-compose.e2e-test.yml up -d api ui
```

- [ ] **Step 6: Commit any fixes**

If any issues found during testing, fix and commit with:

```bash
git commit -m "fix: resolve filter subscription integration issues"
```

---

## Task 15: Update Documentation

**Files:**
- Modify: `ARCHITECTURE.md`

- [ ] **Step 1: Update ARCHITECTURE.md**

Add filter subscription endpoints to the API catalog section. Add the 3 new tables to the DB schema section. Add the FilterSubscription model to the types section. Add FilterSubscriptionRepository to the repository inventory.

- [ ] **Step 2: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "docs: add filter subscription system to architecture docs"
```

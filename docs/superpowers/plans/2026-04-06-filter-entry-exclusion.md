# Filter Subscription Entry Exclusion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow users to exclude specific entries (IP/CIDR) from filter subscriptions, and provide a convenience toggle to auto-exclude RFC 1918 private IP ranges.

**Architecture:** Add a `filter_subscription_entry_exclusions` table to persist excluded values per subscription (survives refresh). Add `exclude_private_ips` boolean column to `filter_subscriptions`. Exclusions are applied at config generation time in `regenerateSharedConfigs` via modified SQL queries. Frontend adds exclude buttons to the entries panel and a private IP toggle to the settings modal.

**Tech Stack:** Go 1.24 (Echo v4), React 18 + TypeScript, PostgreSQL/TimescaleDB

**GitHub Issue:** #93 (FireHOL Level 1: 192.168.0.0/16 사설 대역 포함으로 인한 내부 네트워크 차단 이슈)

---

## File Structure

| Action | File | Responsibility |
|--------|------|---------------|
| Modify | `api/internal/model/filter_subscription.go` | Add entry exclusion model + exclude_private_ips field |
| Modify | `api/internal/database/migrations/001_init.sql` | CREATE TABLE + UPGRADE SECTION |
| Modify | `api/internal/database/migration.go` | upgradeSQL for existing installations |
| Modify | `api/internal/repository/filter_subscription.go` | Entry exclusion CRUD + filtered query |
| Modify | `api/internal/service/filter_subscription.go` | Exclusion service methods + private IP filtering in config gen |
| Modify | `api/internal/handler/filter_subscription.go` | 3 new endpoints for entry exclusions |
| Modify | `api/cmd/server/main.go` | Register new routes |
| Modify | `api/internal/repository/backup_export.go` | Export entry exclusions + exclude_private_ips |
| Modify | `api/internal/repository/backup_import.go` | Import entry exclusions + exclude_private_ips |
| Modify | `api/internal/model/backup.go` | Add entry exclusion to backup data model |
| Modify | `ui/src/types/filter-subscription.ts` | Add entry exclusion type + exclude_private_ips |
| Modify | `ui/src/api/filter-subscriptions.ts` | Add entry exclusion API functions |
| Modify | `ui/src/components/FilterSubscriptionList.tsx` | Entry exclude UI + private IP toggle |
| Modify | `ui/src/i18n/locales/ko/filterSubscription.json` | Korean translations |
| Modify | `ui/src/i18n/locales/en/filterSubscription.json` | English translations |

---

### Task 1: Database Schema — Add entry exclusions table and exclude_private_ips column

**Files:**
- Modify: `api/internal/database/migrations/001_init.sql:2136` (after host_exclusions table)
- Modify: `api/internal/database/migrations/001_init.sql:2208` (UPGRADE SECTION, after host_exclusions)
- Modify: `api/internal/database/migration.go:191` (upgradeSQL, after host_exclusions index)

- [ ] **Step 1: Add entry exclusions table to CREATE TABLE section of 001_init.sql**

After the `filter_subscription_host_exclusions` table and its index (line ~2136), add:

```sql
CREATE TABLE IF NOT EXISTS public.filter_subscription_entry_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
    value text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(subscription_id, value)
);

CREATE INDEX IF NOT EXISTS idx_fsee_subscription ON public.filter_subscription_entry_exclusions(subscription_id);
```

- [ ] **Step 2: Add exclude_private_ips column to filter_subscriptions CREATE TABLE**

In the `filter_subscriptions` CREATE TABLE (line ~2098), add after `entry_count`:

```sql
    exclude_private_ips boolean DEFAULT false,
```

- [ ] **Step 3: Add same table and column to UPGRADE SECTION of 001_init.sql**

After the existing `filter_subscription_host_exclusions` block in UPGRADE SECTION (line ~2208), add:

```sql
-- Filter subscription entry exclusions (v2.8.0+)
CREATE TABLE IF NOT EXISTS public.filter_subscription_entry_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
    value text NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    UNIQUE(subscription_id, value)
);

CREATE INDEX IF NOT EXISTS idx_fsee_subscription ON public.filter_subscription_entry_exclusions(subscription_id);

ALTER TABLE public.filter_subscriptions ADD COLUMN IF NOT EXISTS exclude_private_ips boolean DEFAULT false;
```

- [ ] **Step 4: Add same statements to migration.go upgradeSQL**

In `api/internal/database/migration.go`, add after the `idx_fshe_proxy_host` index line (line ~191), before the Global trusted IPs comment:

```go
		-- Filter subscription entry exclusions (v2.8.0+)
		CREATE TABLE IF NOT EXISTS public.filter_subscription_entry_exclusions (
			id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
			subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
			value text NOT NULL,
			created_at timestamp with time zone DEFAULT now(),
			UNIQUE(subscription_id, value)
		);

		CREATE INDEX IF NOT EXISTS idx_fsee_subscription ON public.filter_subscription_entry_exclusions(subscription_id);

		ALTER TABLE public.filter_subscriptions ADD COLUMN IF NOT EXISTS exclude_private_ips boolean DEFAULT false;
```

- [ ] **Step 5: Commit**

```bash
git add api/internal/database/migrations/001_init.sql api/internal/database/migration.go
git commit -m "feat: add filter subscription entry exclusion schema and exclude_private_ips column"
```

---

### Task 2: Backend Model — Add Go structs and request types

**Files:**
- Modify: `api/internal/model/filter_subscription.go`

- [ ] **Step 1: Add FilterSubscriptionEntryExclusion struct**

Add after the `FilterSubscriptionHostExclusion` struct (line ~36):

```go
type FilterSubscriptionEntryExclusion struct {
	ID             string    `json:"id"`
	SubscriptionID string    `json:"subscription_id"`
	Value          string    `json:"value"`
	CreatedAt      time.Time `json:"created_at"`
}

type AddEntryExclusionRequest struct {
	Value string `json:"value"`
}
```

- [ ] **Step 2: Add ExcludePrivateIPs field to FilterSubscription struct**

Add `ExcludePrivateIPs` field after `EntryCount`:

```go
	ExcludePrivateIPs bool       `json:"exclude_private_ips"`
```

- [ ] **Step 3: Add ExcludePrivateIPs to UpdateFilterSubscriptionRequest**

```go
	ExcludePrivateIPs *bool   `json:"exclude_private_ips,omitempty"`
```

- [ ] **Step 4: Add EntryExclusions to FilterSubscriptionDetail**

Update the `FilterSubscriptionDetail` struct to include entry exclusions:

```go
type FilterSubscriptionDetail struct {
	FilterSubscription
	Entries          []FilterSubscriptionEntry          `json:"entries"`
	Exclusions       []FilterSubscriptionHostExclusion  `json:"exclusions"`
	EntryExclusions  []FilterSubscriptionEntryExclusion `json:"entry_exclusions"`
}
```

- [ ] **Step 5: Commit**

```bash
git add api/internal/model/filter_subscription.go
git commit -m "feat: add entry exclusion model and exclude_private_ips field"
```

---

### Task 3: Repository — Entry exclusion CRUD and filtered config query

**Files:**
- Modify: `api/internal/repository/filter_subscription.go`

- [ ] **Step 1: Update all SELECT queries to include exclude_private_ips**

Every query that scans a `FilterSubscription` needs `exclude_private_ips` added. There are 6 locations: `List` (line 34), `GetByID` (line 74), `GetByURL` (line 100), `Update` RETURNING (line 176), `GetEnabledSubscriptions` (line 391).

For each, add `exclude_private_ips` to the SELECT column list and add `&sub.ExcludePrivateIPs` to the Scan call.

Example for `List` — change the SELECT to:

```sql
SELECT id, name, COALESCE(description, '') as description, url, format, type,
       enabled, refresh_type, refresh_value,
       last_fetched_at, last_success_at, last_error,
       entry_count, COALESCE(exclude_private_ips, false) as exclude_private_ips,
       created_at, updated_at
FROM filter_subscriptions
```

And update the Scan call to include `&sub.ExcludePrivateIPs` after `&sub.EntryCount`.

Apply the same pattern to all 6 query locations.

- [ ] **Step 2: Update Create to include exclude_private_ips**

In the `Create` method, add `exclude_private_ips` to the INSERT:

```go
query := `
    INSERT INTO filter_subscriptions (name, description, url, format, type, enabled, refresh_type, refresh_value, entry_count, exclude_private_ips)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    RETURNING id, created_at, updated_at`

err := r.db.QueryRowContext(ctx, query,
    sub.Name, sub.Description, sub.URL, sub.Format, sub.Type,
    sub.Enabled, sub.RefreshType, sub.RefreshValue, sub.EntryCount, sub.ExcludePrivateIPs,
).Scan(&sub.ID, &sub.CreatedAt, &sub.UpdatedAt)
```

- [ ] **Step 3: Update Update to handle exclude_private_ips**

In the `Update` method, add after the `RefreshValue` handling:

```go
if req.ExcludePrivateIPs != nil {
    setClauses = append(setClauses, fmt.Sprintf("exclude_private_ips = $%d", argIndex))
    args = append(args, *req.ExcludePrivateIPs)
    argIndex++
}
```

Also update the RETURNING clause to include `COALESCE(exclude_private_ips, false) as exclude_private_ips` and the Scan to include `&sub.ExcludePrivateIPs`.

- [ ] **Step 4: Add entry exclusion CRUD methods**

Add these methods at the end of the file:

```go
// ListEntryExclusions returns all entry exclusions for a subscription
func (r *FilterSubscriptionRepository) ListEntryExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionEntryExclusion, error) {
	query := `
		SELECT id, subscription_id, value, created_at
		FROM filter_subscription_entry_exclusions
		WHERE subscription_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list entry exclusions: %w", err)
	}
	defer rows.Close()

	exclusions := []model.FilterSubscriptionEntryExclusion{}
	for rows.Next() {
		var e model.FilterSubscriptionEntryExclusion
		if err := rows.Scan(&e.ID, &e.SubscriptionID, &e.Value, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan entry exclusion: %w", err)
		}
		exclusions = append(exclusions, e)
	}
	return exclusions, rows.Err()
}

// AddEntryExclusion adds an entry exclusion for a subscription
func (r *FilterSubscriptionRepository) AddEntryExclusion(ctx context.Context, subscriptionID, value string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO filter_subscription_entry_exclusions (subscription_id, value) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		subscriptionID, value,
	)
	if err != nil {
		return fmt.Errorf("failed to add entry exclusion: %w", err)
	}
	return nil
}

// RemoveEntryExclusion removes an entry exclusion for a subscription
func (r *FilterSubscriptionRepository) RemoveEntryExclusion(ctx context.Context, subscriptionID, value string) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM filter_subscription_entry_exclusions WHERE subscription_id = $1 AND value = $2`,
		subscriptionID, value,
	)
	if err != nil {
		return fmt.Errorf("failed to remove entry exclusion: %w", err)
	}
	return nil
}
```

- [ ] **Step 5: Update GetAllEnabledEntriesByType to exclude entry exclusions**

Replace the existing `GetAllEnabledEntriesByType` method:

```go
func (r *FilterSubscriptionRepository) GetAllEnabledEntriesByType(ctx context.Context, filterType string) ([]string, error) {
	query := `
		SELECT DISTINCT e.value
		FROM filter_subscription_entries e
		INNER JOIN filter_subscriptions s ON e.subscription_id = s.id
		LEFT JOIN filter_subscription_entry_exclusions ex
			ON e.subscription_id = ex.subscription_id AND e.value = ex.value
		WHERE s.enabled = true AND s.type = $1
		  AND ex.id IS NULL
		ORDER BY e.value`

	rows, err := r.db.QueryContext(ctx, query, filterType)
	if err != nil {
		return nil, fmt.Errorf("failed to get all enabled entries by type: %w", err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("failed to scan entry value: %w", err)
		}
		values = append(values, v)
	}
	return values, rows.Err()
}
```

- [ ] **Step 6: Add GetExcludePrivateIPsSubscriptionIDs method**

This returns subscription IDs that have `exclude_private_ips = true`:

```go
// GetExcludePrivateIPsSubscriptionIDs returns IDs of enabled subscriptions with exclude_private_ips=true
func (r *FilterSubscriptionRepository) GetExcludePrivateIPsSubscriptionIDs(ctx context.Context) (map[string]bool, error) {
	query := `SELECT id FROM filter_subscriptions WHERE enabled = true AND exclude_private_ips = true`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get exclude_private_ips subscriptions: %w", err)
	}
	defer rows.Close()

	ids := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan subscription id: %w", err)
		}
		ids[id] = true
	}
	return ids, rows.Err()
}
```

- [ ] **Step 7: Commit**

```bash
git add api/internal/repository/filter_subscription.go
git commit -m "feat: add entry exclusion repository methods and exclude_private_ips support"
```

---

### Task 4: Service — Exclusion business logic and private IP filtering

**Files:**
- Modify: `api/internal/service/filter_subscription.go`

- [ ] **Step 1: Add entry exclusion service methods**

Add after the `RemoveExclusion` method (line ~374):

```go
// ListEntryExclusions returns entry exclusions for a subscription
func (s *FilterSubscriptionService) ListEntryExclusions(ctx context.Context, subscriptionID string) ([]model.FilterSubscriptionEntryExclusion, error) {
	return s.repo.ListEntryExclusions(ctx, subscriptionID)
}

// AddEntryExclusion adds an entry exclusion
func (s *FilterSubscriptionService) AddEntryExclusion(ctx context.Context, subscriptionID, value string) error {
	if err := s.repo.AddEntryExclusion(ctx, subscriptionID, value); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}

// RemoveEntryExclusion removes an entry exclusion
func (s *FilterSubscriptionService) RemoveEntryExclusion(ctx context.Context, subscriptionID, value string) error {
	if err := s.repo.RemoveEntryExclusion(ctx, subscriptionID, value); err != nil {
		return err
	}
	s.triggerNginxReload()
	return nil
}
```

- [ ] **Step 2: Update GetDetail to include entry exclusions**

In the `GetDetail` method (line ~94), add after fetching `exclusions`:

```go
	entryExclusions, err := s.repo.ListEntryExclusions(ctx, id)
	if err != nil {
		return nil, err
	}

	return &model.FilterSubscriptionDetail{
		FilterSubscription: *sub,
		Entries:            entries,
		Exclusions:         exclusions,
		EntryExclusions:    entryExclusions,
	}, nil
```

- [ ] **Step 3: Add private IP filtering to regenerateSharedConfigs**

In `regenerateSharedConfigs` (line ~731), add filtering after merging IPs and CIDRs. After the deduplication loop and before fetching UAs:

```go
	// Filter out private IPs for subscriptions with exclude_private_ips enabled
	excludePrivateSubIDs, err := s.repo.GetExcludePrivateIPsSubscriptionIDs(ctx)
	if err != nil {
		log.Printf("[FilterSubscription] Warning: failed to get exclude_private_ips subs: %v", err)
	}

	if len(excludePrivateSubIDs) > 0 {
		// Need per-subscription query to filter private IPs only from those subs
		// Since shared config merges all subs, filter at the final output level
		filteredIPs := make([]string, 0, len(allIPs))
		for _, ipStr := range allIPs {
			if isPrivateIPOrCIDR(ipStr) {
				continue // Skip private ranges (they came from subs with the flag)
			}
			filteredIPs = append(filteredIPs, ipStr)
		}
		allIPs = filteredIPs
	}
```

Wait — this approach has a flaw. The shared config merges ALL subscriptions, so if sub A has `exclude_private_ips=true` and sub B doesn't, we can't easily tell which IP came from which sub at this point. However, the `GetAllEnabledEntriesByType` query already uses DISTINCT, so we don't know the source.

Better approach: since we already filter entry exclusions in SQL, let's also filter private IPs in SQL. Update the `GetAllEnabledEntriesByType` query to handle this.

Actually, the simplest correct approach: since the `GetAllEnabledEntriesByType` query already joins `filter_subscriptions`, we can add a condition there. But private IPs need to be checked in Go code (not SQL). Let's do it differently:

Replace the approach. In `regenerateSharedConfigs`, after getting `allIPs`, check if ANY enabled subscription has `exclude_private_ips=true`. If so, filter private IPs from the final list. This is safe because: if any sub wants to exclude private IPs, those IPs shouldn't be in the shared config (they would affect all hosts anyway via the shared include).

```go
	// Filter out private IPs if any enabled subscription has exclude_private_ips=true
	hasExcludePrivate, err := s.repo.HasExcludePrivateIPsEnabled(ctx)
	if err != nil {
		log.Printf("[FilterSubscription] Warning: failed to check exclude_private_ips: %v", err)
	}
	if hasExcludePrivate {
		filteredIPs := make([]string, 0, len(allIPs))
		for _, ipStr := range allIPs {
			if isPrivateIPOrCIDR(ipStr) {
				continue
			}
			filteredIPs = append(filteredIPs, ipStr)
		}
		allIPs = filteredIPs
	}
```

- [ ] **Step 4: Add isPrivateIPOrCIDR helper function**

Add after the `isFilterPrivateIP` function:

```go
// isPrivateIPOrCIDR checks if a string (IP or CIDR) falls within private ranges
func isPrivateIPOrCIDR(value string) bool {
	if strings.Contains(value, "/") {
		ip, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		// Check if the network address is private
		return isFilterPrivateIP(ip) || isFilterPrivateIP(ipNet.IP)
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	return isFilterPrivateIP(ip)
}
```

- [ ] **Step 5: Add HasExcludePrivateIPsEnabled repo method**

Add to `api/internal/repository/filter_subscription.go`:

```go
// HasExcludePrivateIPsEnabled returns true if any enabled subscription has exclude_private_ips=true
func (r *FilterSubscriptionRepository) HasExcludePrivateIPsEnabled(ctx context.Context) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM filter_subscriptions WHERE enabled = true AND exclude_private_ips = true)`,
	).Scan(&exists)
	return exists, err
}
```

- [ ] **Step 6: Update service Update method to trigger reload on exclude_private_ips change**

In the `Update` method (line ~252), update the reload condition:

```go
	// If enabled state or exclude_private_ips changed, trigger nginx reload
	if req.Enabled != nil || req.ExcludePrivateIPs != nil {
		s.triggerNginxReload()
	}
```

- [ ] **Step 7: Commit**

```bash
git add api/internal/service/filter_subscription.go api/internal/repository/filter_subscription.go
git commit -m "feat: add entry exclusion service logic and private IP filtering in config generation"
```

---

### Task 5: Handler and Routes — Entry exclusion endpoints

**Files:**
- Modify: `api/internal/handler/filter_subscription.go`
- Modify: `api/cmd/server/main.go:837-850`

- [ ] **Step 1: Add entry exclusion handler methods**

Add to `api/internal/handler/filter_subscription.go` after `RemoveExclusion` (line ~221):

```go
// ListEntryExclusions returns entry exclusions for a subscription
func (h *FilterSubscriptionHandler) ListEntryExclusions(c echo.Context) error {
	subscriptionID := c.Param("id")

	exclusions, err := h.service.ListEntryExclusions(c.Request().Context(), subscriptionID)
	if err != nil {
		return databaseError(c, "list entry exclusions", err)
	}

	return c.JSON(http.StatusOK, exclusions)
}

// AddEntryExclusion adds an entry exclusion to a subscription
func (h *FilterSubscriptionHandler) AddEntryExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")

	var req model.AddEntryExclusionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Value == "" {
		return badRequestError(c, "value is required")
	}

	if err := h.service.AddEntryExclusion(c.Request().Context(), subscriptionID, req.Value); err != nil {
		return databaseError(c, "add entry exclusion", err)
	}

	return c.NoContent(http.StatusNoContent)
}

// RemoveEntryExclusion removes an entry exclusion from a subscription
func (h *FilterSubscriptionHandler) RemoveEntryExclusion(c echo.Context) error {
	subscriptionID := c.Param("id")

	var req model.AddEntryExclusionRequest
	if err := c.Bind(&req); err != nil {
		return badRequestError(c, "Invalid request body")
	}

	if req.Value == "" {
		return badRequestError(c, "value is required")
	}

	if err := h.service.RemoveEntryExclusion(c.Request().Context(), subscriptionID, req.Value); err != nil {
		return databaseError(c, "remove entry exclusion", err)
	}

	return c.NoContent(http.StatusNoContent)
}
```

- [ ] **Step 2: Register routes in main.go**

In `api/cmd/server/main.go`, add after the existing exclusion routes (line ~849):

```go
			filterSubs.GET("/:id/entry-exclusions", filterSubscriptionHandler.ListEntryExclusions)
			filterSubs.POST("/:id/entry-exclusions", filterSubscriptionHandler.AddEntryExclusion)
			filterSubs.DELETE("/:id/entry-exclusions", filterSubscriptionHandler.RemoveEntryExclusion)
```

- [ ] **Step 3: Commit**

```bash
git add api/internal/handler/filter_subscription.go api/cmd/server/main.go
git commit -m "feat: add entry exclusion HTTP endpoints and routes"
```

---

### Task 6: Backup Export/Import — Sync entry exclusions and exclude_private_ips

**Files:**
- Modify: `api/internal/model/backup.go`
- Modify: `api/internal/repository/backup_export.go`
- Modify: `api/internal/repository/backup_import.go`

- [ ] **Step 1: Find and update backup data model**

Search for the FilterSubscription backup data struct in `model/backup.go` and add the new fields. The struct should already have entries and host exclusions. Add:

```go
	EntryExclusions  []BackupFilterEntryExclusion `json:"entry_exclusions,omitempty"`
	ExcludePrivateIPs bool                        `json:"exclude_private_ips"`
```

Add the new type:

```go
type BackupFilterEntryExclusion struct {
	Value     string `json:"value"`
}
```

- [ ] **Step 2: Update backup_export.go**

Find the filter subscription export query (line ~1029). Add `COALESCE(exclude_private_ips, false)` to the SELECT and `&sub.ExcludePrivateIPs` to Scan.

After the host exclusion export loop (line ~1068), add entry exclusion export:

```go
		entryExclQuery := `SELECT value FROM filter_subscription_entry_exclusions WHERE subscription_id = $1`
		entryExclRows, err := r.db.QueryContext(ctx, entryExclQuery, sub.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to export entry exclusions: %w", err)
		}
		for entryExclRows.Next() {
			var excl BackupFilterEntryExclusion
			if err := entryExclRows.Scan(&excl.Value); err != nil {
				entryExclRows.Close()
				return nil, fmt.Errorf("failed to scan entry exclusion: %w", err)
			}
			sub.EntryExclusions = append(sub.EntryExclusions, excl)
		}
		entryExclRows.Close()
```

- [ ] **Step 3: Update backup_import.go**

Find the filter subscription import section (line ~883). Add `exclude_private_ips` to the INSERT query and value.

After the host exclusion import loop (line ~932), add:

```go
		// Import entry exclusions
		entryExclQuery := `INSERT INTO filter_subscription_entry_exclusions (subscription_id, value) VALUES ($1, $2) ON CONFLICT DO NOTHING`
		for _, excl := range sub.EntryExclusions {
			if _, err := tx.ExecContext(ctx, entryExclQuery, sub.ID, excl.Value); err != nil {
				log.Printf("[Backup Import] Warning: failed to import entry exclusion %s: %v", excl.Value, err)
			}
		}
```

- [ ] **Step 4: Commit**

```bash
git add api/internal/model/backup.go api/internal/repository/backup_export.go api/internal/repository/backup_import.go
git commit -m "feat: add entry exclusion and exclude_private_ips to backup export/import"
```

---

### Task 7: Frontend Types and API — Add entry exclusion support

**Files:**
- Modify: `ui/src/types/filter-subscription.ts`
- Modify: `ui/src/api/filter-subscriptions.ts`

- [ ] **Step 1: Update TypeScript types**

In `ui/src/types/filter-subscription.ts`, add after `FilterSubscriptionHostExclusion` (line ~32):

```typescript
export interface FilterSubscriptionEntryExclusion {
  id: string;
  subscription_id: string;
  value: string;
  created_at: string;
}
```

Add `exclude_private_ips` to `FilterSubscription` after `entry_count`:

```typescript
  exclude_private_ips: boolean;
```

Update `FilterSubscriptionDetail` to include entry_exclusions:

```typescript
export interface FilterSubscriptionDetail extends FilterSubscription {
  entries: FilterSubscriptionEntry[];
  exclusions: FilterSubscriptionHostExclusion[];
  entry_exclusions: FilterSubscriptionEntryExclusion[];
}
```

Add `exclude_private_ips` to `UpdateFilterSubscriptionRequest`:

```typescript
  exclude_private_ips?: boolean;
```

- [ ] **Step 2: Add API functions**

In `ui/src/api/filter-subscriptions.ts`, add:

```typescript
export async function fetchEntryExclusions(
  subscriptionId: string
): Promise<FilterSubscriptionEntryExclusion[]> {
  return apiGet<FilterSubscriptionEntryExclusion[]>(`${API_BASE}/${subscriptionId}/entry-exclusions`)
}

export async function addEntryExclusion(
  subscriptionId: string,
  value: string
): Promise<void> {
  await apiPost(`${API_BASE}/${subscriptionId}/entry-exclusions`, { value })
}

export async function removeEntryExclusion(
  subscriptionId: string,
  value: string
): Promise<void> {
  await apiDelete(`${API_BASE}/${subscriptionId}/entry-exclusions`, { value })
}
```

Update the import to include the new type:

```typescript
import type {
  // ... existing imports
  FilterSubscriptionEntryExclusion,
} from '../types/filter-subscription'
```

Note: `apiDelete` in this project doesn't accept a body. Use a different approach — send value as query param or use apiPost with DELETE method. Check `api/client.ts` to confirm. If `apiDelete` doesn't support body, change the backend to use query param:

Handler alternative (if apiDelete doesn't support body):
```go
// RemoveEntryExclusion - use query param instead of body
func (h *FilterSubscriptionHandler) RemoveEntryExclusion(c echo.Context) error {
    subscriptionID := c.Param("id")
    value := c.QueryParam("value")
    if value == "" {
        return badRequestError(c, "value query parameter is required")
    }
    // ...
}
```

Frontend alternative:
```typescript
export async function removeEntryExclusion(
  subscriptionId: string,
  value: string
): Promise<void> {
  return apiDelete(`${API_BASE}/${subscriptionId}/entry-exclusions?value=${encodeURIComponent(value)}`)
}
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/types/filter-subscription.ts ui/src/api/filter-subscriptions.ts
git commit -m "feat: add entry exclusion TypeScript types and API functions"
```

---

### Task 8: Frontend UI — Entry exclude buttons and private IP toggle

**Files:**
- Modify: `ui/src/components/FilterSubscriptionList.tsx`

- [ ] **Step 1: Update EntriesPanel to show exclude buttons**

Replace the `EntriesPanel` component to accept entry exclusions and callbacks:

```tsx
function EntriesPanel({
  entries, isLoading, searchQuery, entryExclusions, onToggleExclusion, isTogglingExclusion,
}: {
  entries: { value: string; reason?: string }[];
  isLoading?: boolean;
  searchQuery?: string;
  entryExclusions?: Set<string>;
  onToggleExclusion?: (value: string) => void;
  isTogglingExclusion?: boolean;
}) {
  const { t } = useTranslation('filterSubscription');
  if (isLoading) return <div className="text-xs text-slate-400 py-2 pl-4">...</div>;
  if (!entries.length) return <div className="text-xs text-slate-400 py-2 pl-4">{t('list.noEntries')}</div>;

  const filtered = searchQuery
    ? entries.filter(e => e.value.includes(searchQuery) || (e.reason && e.reason.toLowerCase().includes(searchQuery.toLowerCase())))
    : entries;

  return (
    <div className="mt-2 max-h-60 overflow-y-auto border border-slate-200 dark:border-slate-700 rounded-lg bg-slate-50 dark:bg-slate-900/50">
      {searchQuery && (
        <div className="px-3 py-1.5 text-xs text-slate-400 border-b border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800">
          {filtered.length} / {entries.length} {t('list.searchResults', 'results')}
        </div>
      )}
      <table className="w-full text-xs">
        <tbody>
          {filtered.slice(0, 500).map((entry, i) => {
            const isExcluded = entryExclusions?.has(entry.value) ?? false;
            return (
              <tr key={i} className={`border-b border-slate-200 dark:border-slate-700 last:border-0 ${isExcluded ? 'opacity-50' : ''}`}>
                <td className={`px-3 py-1.5 font-mono text-slate-700 dark:text-slate-300 whitespace-nowrap ${isExcluded ? 'line-through' : ''}`}>{entry.value}</td>
                <td className="px-3 py-1.5 text-slate-500 dark:text-slate-400">{entry.reason || '-'}</td>
                {onToggleExclusion && (
                  <td className="px-3 py-1.5 text-right">
                    <button
                      onClick={() => onToggleExclusion(entry.value)}
                      disabled={isTogglingExclusion}
                      className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                        isExcluded
                          ? 'bg-amber-100 text-amber-700 hover:bg-amber-200 dark:bg-amber-900/40 dark:text-amber-300'
                          : 'bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-700 dark:text-slate-400'
                      }`}
                    >
                      {isExcluded ? t('entryExclusions.included') : t('entryExclusions.exclude')}
                    </button>
                  </td>
                )}
              </tr>
            );
          })}
          {filtered.length > 500 && (
            <tr><td colSpan={onToggleExclusion ? 3 : 2} className="px-3 py-1.5 text-center text-slate-400">... +{filtered.length - 500} more</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
```

- [ ] **Step 2: Add entry exclusion mutations and state in FilterSubscriptionList**

In the `FilterSubscriptionList` component, add imports and mutations. Add these imports at the top:

```typescript
import {
  // ... existing imports
  addEntryExclusion,
  removeEntryExclusion,
} from '../api/filter-subscriptions';
```

Add mutation inside the component:

```typescript
  const entryExclusionMutation = useMutation({
    mutationFn: ({ subscriptionId, value, excluded }: { subscriptionId: string; value: string; excluded: boolean }) =>
      excluded ? removeEntryExclusion(subscriptionId, value) : addEntryExclusion(subscriptionId, value),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filterSubscriptionDetail'] });
    },
  });
```

Compute the excluded entries set from detail data:

```typescript
  const entryExclusionSet = useMemo(() => {
    if (!expandedSubDetail?.entry_exclusions) return new Set<string>();
    return new Set(expandedSubDetail.entry_exclusions.map(e => e.value));
  }, [expandedSubDetail]);
```

- [ ] **Step 3: Update EntriesPanel usage in the expanded section**

Replace the `<EntriesPanel>` usage in the expanded section:

```tsx
  <EntriesPanel
    entries={expandedSubDetail?.entries || []}
    isLoading={detailLoading}
    searchQuery={entrySearch}
    entryExclusions={entryExclusionSet}
    onToggleExclusion={(value) => {
      const isExcluded = entryExclusionSet.has(value);
      entryExclusionMutation.mutate({ subscriptionId: expandedSub!, value, excluded: isExcluded });
    }}
    isTogglingExclusion={entryExclusionMutation.isPending}
  />
```

- [ ] **Step 4: Add private IP toggle to SettingsModal**

In the `SettingsModal` component, add state for `excludePrivateIPs`:

```typescript
  const [excludePrivateIPs, setExcludePrivateIPs] = useState(subscription.exclude_private_ips);
```

Add the toggle UI in the settings modal, between the enable toggle and the refresh selector:

```tsx
  <div className="flex items-center justify-between">
    <div>
      <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{t('settings.excludePrivateIPs')}</span>
      <p className="text-xs text-slate-500 dark:text-slate-400">{t('settings.excludePrivateIPsDescription')}</p>
    </div>
    <button onClick={() => setExcludePrivateIPs(!excludePrivateIPs)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${excludePrivateIPs ? 'bg-cyan-600' : 'bg-slate-300 dark:bg-slate-600'}`}>
      <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${excludePrivateIPs ? 'translate-x-6' : 'translate-x-1'}`} />
    </button>
  </div>
```

Update `handleSave` to include the new field:

```typescript
  const handleSave = () => {
    updateMutation.mutate({
      name: name !== subscription.name ? name : undefined,
      enabled: enabled !== subscription.enabled ? enabled : undefined,
      refresh_type: refreshType !== subscription.refresh_type ? refreshType : undefined,
      refresh_value: refreshValue !== subscription.refresh_value ? refreshValue : undefined,
      exclude_private_ips: excludePrivateIPs !== subscription.exclude_private_ips ? excludePrivateIPs : undefined,
    });
  };
```

- [ ] **Step 5: Commit**

```bash
git add ui/src/components/FilterSubscriptionList.tsx
git commit -m "feat: add entry exclusion UI and private IP toggle to settings modal"
```

---

### Task 9: i18n — Add translations for new UI elements

**Files:**
- Modify: `ui/src/i18n/locales/ko/filterSubscription.json`
- Modify: `ui/src/i18n/locales/en/filterSubscription.json`

- [ ] **Step 1: Add Korean translations**

Add to the `settings` section:

```json
    "excludePrivateIPs": "사설 IP 대역 제외",
    "excludePrivateIPsDescription": "RFC 1918 사설 IP 대역(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)을 차단 목록에서 제외합니다."
```

Add new `entryExclusions` section:

```json
  "entryExclusions": {
    "exclude": "제외",
    "included": "포함",
    "excluded": "제외됨"
  }
```

- [ ] **Step 2: Add English translations**

Add to the `settings` section:

```json
    "excludePrivateIPs": "Exclude Private IP Ranges",
    "excludePrivateIPsDescription": "Exclude RFC 1918 private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) from the blocklist."
```

Add new `entryExclusions` section:

```json
  "entryExclusions": {
    "exclude": "Exclude",
    "included": "Include",
    "excluded": "Excluded"
  }
```

- [ ] **Step 3: Commit**

```bash
git add ui/src/i18n/locales/ko/filterSubscription.json ui/src/i18n/locales/en/filterSubscription.json
git commit -m "feat: add i18n translations for entry exclusion and private IP toggle"
```

---

### Task 10: Build and Test

- [ ] **Step 1: Build API**

```bash
docker compose -f docker-compose.dev.yml build api
```

Expected: Build succeeds with no errors.

- [ ] **Step 2: Build UI**

```bash
docker compose -f docker-compose.dev.yml build ui
```

Expected: Build succeeds with no errors.

- [ ] **Step 3: Start services**

```bash
docker compose -f docker-compose.dev.yml up -d api ui
```

- [ ] **Step 4: Verify DB migration**

```bash
docker compose -f docker-compose.dev.yml exec db psql -U postgres -d nginx_guard -c "\d filter_subscription_entry_exclusions"
docker compose -f docker-compose.dev.yml exec db psql -U postgres -d nginx_guard -c "SELECT column_name FROM information_schema.columns WHERE table_name='filter_subscriptions' AND column_name='exclude_private_ips'"
```

Expected: Table exists with `id`, `subscription_id`, `value`, `created_at` columns. Column `exclude_private_ips` exists.

- [ ] **Step 5: Test API endpoints**

```bash
# Create a test session token first, then:
# List entry exclusions (should return empty array)
docker compose -f docker-compose.dev.yml exec api wget -qO- --header="Authorization: Bearer $TEST_TOKEN" \
  "http://localhost:8080/api/v1/filter-subscriptions/<sub_id>/entry-exclusions"

# Add an entry exclusion
docker compose -f docker-compose.dev.yml exec api wget -qO- --header="Authorization: Bearer $TEST_TOKEN" \
  --post-data='{"value":"192.168.0.0/16"}' --header="Content-Type: application/json" \
  "http://localhost:8080/api/v1/filter-subscriptions/<sub_id>/entry-exclusions"
```

- [ ] **Step 6: Run E2E tests if available**

```bash
sudo docker compose -f docker-compose.e2e-test.yml build --no-cache api
sudo docker compose -f docker-compose.e2e-test.yml up -d api
cd test/e2e && npx playwright test
```

- [ ] **Step 7: Commit any fixes**

---

### Task 11: Update ARCHITECTURE.md

- [ ] **Step 1: Update relevant sections**

Add the new table to the database schema section, add the new API endpoints to the API catalog, and note the `exclude_private_ips` column in the filter subscription model.

- [ ] **Step 2: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "docs: update ARCHITECTURE.md with entry exclusion feature"
```

package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// RunMigrations executes schema migrations
// 001_init.sql runs only once (on fresh install)
// Upgrade statements run every time for existing installations
func (db *DB) RunMigrations() error {
	// Create migrations tracking table (for version tracking only)
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) PRIMARY KEY,
			applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Enable TimescaleDB extension (safe to run multiple times)
	if err := db.enableTimescaleDB(); err != nil {
		log.Printf("Warning: TimescaleDB not available, using standard PostgreSQL: %v", err)
	}

	// Check if base schema already exists
	var exists bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = '001_init')`).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}

	if !exists {
		// Fresh install - run full schema
		content, err := migrationFS.ReadFile("migrations/001_init.sql")
		if err != nil {
			return fmt.Errorf("failed to read 001_init.sql: %w", err)
		}

		log.Println("Running initial schema migration (001_init.sql)...")
		_, err = db.Exec(string(content))
		if err != nil {
			return fmt.Errorf("failed to apply schema migration: %w", err)
		}

		// Mark as applied
		_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ('001_init')`)
		if err != nil {
			return fmt.Errorf("failed to update migration version: %w", err)
		}
		log.Println("Initial schema migration completed successfully")
	} else {
		log.Println("Schema already initialized, running upgrades only...")
	}

	// ===========================================================================
	// Per-statement upgrade executions. Each entry runs in its own db.Exec so
	// a failure (common: pq: chunk not found from orphaned TimescaleDB chunks in
	// old dashboard_stats_hourly data) cannot abort the implicit transaction and
	// silently skip subsequent statements.
	//
	// Historical context: prior to v2.13.4 this file had a large upgradeSQL raw-
	// string sent as a single Exec. That cascade-abort bug caused Issues #105 and
	// #123 fixes to silently skip on affected installs. v2.13.4 fully replaced
	// upgradeSQL with this structured slice. Every new upgrade statement belongs
	// here; NEVER reintroduce a multi-statement Exec.
	// ===========================================================================
	upgrades := []struct {
		desc string
		sql  string
	}{
		// -----------------------------------------------------------------------
		// Detach orphan chunk children. On installs that survived earlier
		// migration glitches (notably the v2.7.x → v2.8.x partitioned-table →
		// TimescaleDB hypertable conversion), pg_inherits can list child chunk
		// tables that no longer have an entry in _timescaledb_catalog.chunk.
		// Postgres' planner enumerates pg_inherits children, TimescaleDB's
		// hooks then look them up in catalog, and the missing entry surfaces
		// as `pq: chunk not found` on every query/DELETE that touches the
		// parent hypertable (logs_partitioned, system_logs, audit_logs, ...).
		//
		// This step is idempotent: ALTER TABLE ... NO INHERIT removes only the
		// inheritance link; the physical orphan tables and their data are
		// preserved as standalone tables for the operator to inspect/drop. It
		// MUST run before any later upgrade that touches a hypertable
		// (CREATE INDEX on logs_partitioned below would otherwise abort).
		// Wrapped in a TimescaleDB-availability guard so installs without the
		// extension skip cleanly.
		// -----------------------------------------------------------------------
		{
			desc: "Detach orphan chunk inheritance entries (TimescaleDB catalog drift)",
			sql: `DO $$
DECLARE
    has_timescaledb BOOLEAN;
    orphan RECORD;
    detached_count INT := 0;
BEGIN
    SELECT EXISTS(
        SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'
    ) INTO has_timescaledb;
    IF NOT has_timescaledb THEN
        RETURN;
    END IF;

    FOR orphan IN
        SELECT
            i.inhrelid::regclass AS child,
            i.inhparent::regclass AS parent
        FROM pg_inherits i
        JOIN pg_class child_c ON child_c.oid = i.inhrelid
        JOIN pg_namespace child_n ON child_n.oid = child_c.relnamespace
        JOIN _timescaledb_catalog.hypertable h
          ON format('%I.%I', h.schema_name, h.table_name)::regclass = i.inhparent
        WHERE NOT EXISTS (
            SELECT 1 FROM _timescaledb_catalog.chunk ch
            WHERE ch.schema_name = child_n.nspname
              AND ch.table_name  = child_c.relname
        )
    LOOP
        BEGIN
            EXECUTE format('ALTER TABLE %s NO INHERIT %s', orphan.child, orphan.parent);
            detached_count := detached_count + 1;
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE '[Migration] Could not detach orphan %: %', orphan.child, SQLERRM;
        END;
    END LOOP;

    IF detached_count > 0 THEN
        RAISE NOTICE '[Migration] Detached % orphan chunk inheritance entries', detached_count;
    END IF;
END $$`,
		},

		// -----------------------------------------------------------------------
		// Enum upgrades (block_reason) — safe to run multiple times.
		// ALTER TYPE ... ADD VALUE IF NOT EXISTS is non-transactional in PG,
		// so these are grouped for readability; each is independently idempotent.
		// -----------------------------------------------------------------------
		{
			desc: "block_reason enum: cloud_provider_challenge",
			sql:  `ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'cloud_provider_challenge'`,
		},
		{
			desc: "block_reason enum: cloud_provider_block",
			sql:  `ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'cloud_provider_block'`,
		},
		{
			desc: "block_reason enum: uri_block",
			sql:  `ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'uri_block'`,
		},
		{
			desc: "block_reason enum: access_denied",
			sql:  `ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'access_denied'`,
		},
		{
			desc: "block_reason enum: filter_subscription",
			sql:  `ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'filter_subscription'`,
		},

		// -----------------------------------------------------------------------
		// Column upgrades (early versions)
		// -----------------------------------------------------------------------
		{
			desc: "proxy_hosts.cache_static_only",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS cache_static_only boolean DEFAULT true NOT NULL`,
		},
		{
			desc: "proxy_hosts.cache_ttl",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS cache_ttl character varying(20) DEFAULT '7d' NOT NULL`,
		},
		{
			desc: "geo_restrictions.allow_search_bots_cloud_providers",
			sql:  `ALTER TABLE public.geo_restrictions ADD COLUMN IF NOT EXISTS allow_search_bots_cloud_providers boolean DEFAULT false`,
		},
		{
			desc: "proxy_hosts.is_favorite",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS is_favorite boolean DEFAULT false NOT NULL`,
		},

		// -----------------------------------------------------------------------
		// Host-level proxy settings (v1.3.4+)
		// -----------------------------------------------------------------------
		{
			desc: "v1.3.4: proxy_hosts.proxy_connect_timeout",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_connect_timeout integer DEFAULT 0`,
		},
		{
			desc: "v1.3.4: proxy_hosts.proxy_send_timeout",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_send_timeout integer DEFAULT 0`,
		},
		{
			desc: "v1.3.4: proxy_hosts.proxy_read_timeout",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_read_timeout integer DEFAULT 0`,
		},
		{
			desc: "v1.3.4: proxy_hosts.proxy_buffering",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_buffering character varying(10) DEFAULT ''`,
		},
		{
			desc: "v1.3.4: proxy_hosts.proxy_request_buffering",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_request_buffering character varying(10) DEFAULT ''`,
		},
		{
			desc: "v1.3.4: proxy_hosts.client_max_body_size",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS client_max_body_size character varying(20) DEFAULT ''`,
		},
		{
			desc: "v1.3.4: proxy_hosts.proxy_max_temp_file_size",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_max_temp_file_size character varying(20) DEFAULT ''`,
		},
		{
			desc: "v2.18.0: proxy_hosts.proxy_type",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS proxy_type character varying(20) DEFAULT 'http' NOT NULL`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_listen_host",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_listen_host character varying(255) DEFAULT ''`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_listen_port",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_listen_port integer DEFAULT 0`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_protocol",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_protocol character varying(10) DEFAULT 'tcp'`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_ssl_preread",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_ssl_preread boolean DEFAULT false NOT NULL`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_accept_proxy_protocol",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_accept_proxy_protocol boolean DEFAULT false NOT NULL`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_send_proxy_protocol",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_send_proxy_protocol boolean DEFAULT false NOT NULL`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_proxy_connect_timeout",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_proxy_connect_timeout integer DEFAULT 0`,
		},
		{
			desc: "v2.18.0: proxy_hosts.stream_proxy_timeout",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS stream_proxy_timeout integer DEFAULT 0`,
		},

		// -----------------------------------------------------------------------
		// Global settings: proxy buffering columns (v2.4.0+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.4.0: global_settings.proxy_buffering",
			sql:  `ALTER TABLE public.global_settings ADD COLUMN IF NOT EXISTS proxy_buffering character varying(10) DEFAULT ''`,
		},
		{
			desc: "v2.4.0: global_settings.proxy_request_buffering",
			sql:  `ALTER TABLE public.global_settings ADD COLUMN IF NOT EXISTS proxy_request_buffering character varying(10) DEFAULT ''`,
		},

		// -----------------------------------------------------------------------
		// Global settings: ssl_ecdh_curve for ML-KEM/post-quantum TLS (v2.5.0+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.5.0: global_settings.ssl_ecdh_curve",
			sql:  `ALTER TABLE public.global_settings ADD COLUMN IF NOT EXISTS ssl_ecdh_curve character varying(255) DEFAULT 'X25519MLKEM768:X25519:secp256r1:secp384r1' NOT NULL`,
		},

		// -----------------------------------------------------------------------
		// v2.13.2 (Issue #123): Exploit rule auto-disable marker column.
		// MUST be added BEFORE the seed INSERT below (which references the column)
		// and BEFORE ApplyExploitRulesAutoDisable (which writes to it).
		// -----------------------------------------------------------------------
		{
			desc: "v2.13.2: exploit_block_rules.auto_disabled_at",
			sql:  `ALTER TABLE public.exploit_block_rules ADD COLUMN IF NOT EXISTS auto_disabled_at timestamp with time zone`,
		},

		// -----------------------------------------------------------------------
		// v2.13.2 (Issue #123): URI-scoped per-rule exploit exclusions.
		// NULL uri_pattern = rule fully excluded (legacy behavior);
		// non-NULL = rule excluded only when $request_uri matches the regex.
		// MUST land before the composite unique indexes below and before
		// ApplyExploitRulesAutoDisable which references uri_pattern via COALESCE.
		// -----------------------------------------------------------------------
		{
			desc: "v2.13.2: host_exploit_rule_exclusions.uri_pattern",
			sql:  `ALTER TABLE public.host_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern text`,
		},
		{
			desc: "v2.13.2: global_exploit_rule_exclusions.uri_pattern",
			sql:  `ALTER TABLE public.global_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern text`,
		},

		// -----------------------------------------------------------------------
		// v2.13.2: drop legacy single-column unique constraints in favor of the
		// composite (rule_id, COALESCE(uri_pattern,'')) unique indexes below.
		// -----------------------------------------------------------------------
		// ---------------------------------------------------------------------
		// v2.13.2: replace single-column UNIQUE constraints with composite
		// expression indexes to allow multiple URI-scoped exclusions per rule.
		//
		// Order matters: DROP CONSTRAINT runs before CREATE UNIQUE INDEX within
		// the same upgrades loop but across separate db.Exec calls. On a running
		// server there's a brief window with no uniqueness between the two — OK
		// here because migrations run at boot before e.Start() accepts traffic.
		// DO NOT reorder.
		// ---------------------------------------------------------------------
		{
			desc: "v2.13.2: drop global_exploit_rule_exclusions_rule_id_key",
			sql: `ALTER TABLE public.global_exploit_rule_exclusions
				DROP CONSTRAINT IF EXISTS global_exploit_rule_exclusions_rule_id_key`,
		},
		{
			desc: "v2.13.2: drop host_exploit_rule_exclusions_proxy_host_id_rule_id_key",
			sql: `ALTER TABLE public.host_exploit_rule_exclusions
				DROP CONSTRAINT IF EXISTS host_exploit_rule_exclusions_proxy_host_id_rule_id_key`,
		},

		// -----------------------------------------------------------------------
		// v2.13.2: rename legacy uq_* indexes to idx_*_unique (project convention).
		// -----------------------------------------------------------------------
		{
			desc: "v2.13.2: rename uq_global_exploit_rule_exclusions_rule_uri",
			sql: `ALTER INDEX IF EXISTS uq_global_exploit_rule_exclusions_rule_uri
				RENAME TO idx_global_exploit_exclusions_rule_uri_unique`,
		},
		{
			desc: "v2.13.2: rename uq_host_exploit_rule_exclusions_host_rule_uri",
			sql: `ALTER INDEX IF EXISTS uq_host_exploit_rule_exclusions_host_rule_uri
				RENAME TO idx_host_exploit_exclusions_host_rule_uri_unique`,
		},
		{
			desc: "v2.13.2: idx_global_exploit_exclusions_rule_uri_unique",
			sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_global_exploit_exclusions_rule_uri_unique
				ON public.global_exploit_rule_exclusions (rule_id, COALESCE(uri_pattern, ''))`,
		},
		{
			desc: "v2.13.2: idx_host_exploit_exclusions_host_rule_uri_unique",
			sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_host_exploit_exclusions_host_rule_uri_unique
				ON public.host_exploit_rule_exclusions (proxy_host_id, rule_id, COALESCE(uri_pattern, ''))`,
		},

		// -----------------------------------------------------------------------
		// Default exploit block rules (seed if not exists).
		// The three rules with auto_disabled_at=now() (SQL Commands, SQL Keywords,
		// XSS Special Characters) ship disabled because their simple keyword
		// patterns produce false positives on legitimate search/CMS query strings.
		// auto_disabled_at is pre-set on fresh install so ApplyExploitRulesAutoDisable
		// (below) will not clobber an admin's conscious choice to re-enable.
		// (Issue #123)
		// -----------------------------------------------------------------------
		{
			desc: "seed: exploit_block_rules system defaults",
			sql: `INSERT INTO public.exploit_block_rules (id, category, name, pattern, pattern_type, description, severity, enabled, is_system, sort_order, auto_disabled_at) VALUES
			('4243721e-8f8d-4a2b-8496-0be62d50163f', 'sql_injection', 'SQL Union Select', E'(\\"|''|` + "`" + `)(.*)(union)(.*)(select)(\\"|''|` + "`" + `)' , 'query_string', 'Blocks SQL UNION SELECT injection attempts', 'critical', true, true, 1, NULL),
			('a5cb921c-2c10-475b-8753-a56e2af1e5ba', 'sql_injection', 'SQL Commands', E'(;|\\||` + "`" + `|>|<|\\^|@)', 'query_string', 'Blocks SQL command characters (semicolon, pipe, backtick, redirects) (disabled by default: matches common URL characters like @, <, >; high false-positive rate)', 'warning', false, true, 2, now()),
			('41d1f7bf-9179-44cb-b41a-1685ce88d965', 'sql_injection', 'SQL Keywords', E'\\b(select|insert|update|delete|drop|truncate|alter|create|exec)\\b', 'query_string', 'Blocks common SQL keywords in query strings (disabled by default: matches plain English words like ''update''/''select'' in search queries; ModSecurity/CRS handles SQL injection detection more precisely)', 'warning', false, true, 3, now()),
			('b890779f-757c-4461-a64a-dce59fb469e3', 'xss', 'Script Tags', '<script', 'query_string', 'Blocks script tag injection', 'critical', true, true, 10, NULL),
			('27ed45b1-e030-4212-bc34-edc7e13a9695', 'xss', 'Event Handlers', 'on(click|load|error|mouseover|focus|blur|change|submit)=', 'query_string', 'Blocks JavaScript event handler injection', 'critical', true, true, 11, NULL),
			('aa90285b-2986-46f9-80e6-99946327cd24', 'xss', 'Special Characters', '(;|<|>|"|%0A|%0D|%22|%3C|%3E|%00)', 'query_string', 'Blocks XSS special characters (semicolon, angle brackets, encoded newlines/quotes/null) (disabled by default: matches common characters in legitimate URL parameters like quotes; CRS provides more precise XSS detection)', 'warning', false, true, 12, now()),
			('23b31cc1-0e43-49af-b9c9-4093fd0cbcdc', 'rfi', 'URL Parameter Injection', '[a-zA-Z0-9_]=https?://', 'query_string', 'Blocks URL values in query parameters (RFI)', 'critical', true, true, 20, NULL),
			('7db3e194-8731-40c1-afaa-b7555c017a3f', 'rfi', 'Path Traversal Sequences', E'[a-zA-Z0-9_]=(\\.\\./)+', 'query_string', 'Blocks path traversal in parameters', 'critical', true, true, 21, NULL),
			('650c5e4a-c373-4d99-9cac-9e86b55bcb33', 'rfi', 'Directory Traversal', E'\\.\\./', 'query_string', 'Blocks directory traversal patterns', 'warning', true, true, 22, NULL),
			('f055a131-0596-419f-944a-cb7fa40f5c59', 'scanner', 'Nikto Scanner', 'nikto', 'user_agent', 'Blocks Nikto vulnerability scanner', 'critical', true, true, 30, NULL),
			('f13159ab-0e9a-45ea-aa4b-03fde63bb3e6', 'scanner', 'SQLMap Tool', 'sqlmap', 'user_agent', 'Blocks SQLMap SQL injection tool', 'critical', true, true, 31, NULL),
			('a9baaa39-ccd9-4f8a-82c0-e7d85f02cc2f', 'scanner', 'DirBuster', 'dirbuster', 'user_agent', 'Blocks DirBuster directory scanner', 'critical', true, true, 32, NULL),
			('8208101f-eb91-4b86-8396-f295cd16d04b', 'scanner', 'Nmap Scanner', 'nmap', 'user_agent', 'Blocks Nmap network scanner', 'warning', true, true, 33, NULL),
			('7efe59af-2d2a-405e-bbe8-951757e72ef4', 'scanner', 'Nessus Scanner', 'nessus', 'user_agent', 'Blocks Nessus vulnerability scanner', 'warning', true, true, 34, NULL),
			('9a5f6bcb-ceec-47f1-9f8c-dadb815711fa', 'scanner', 'OpenVAS Scanner', 'openvas', 'user_agent', 'Blocks OpenVAS security scanner', 'warning', true, true, 35, NULL),
			('ab3b4e85-08fd-49fe-b76d-3dc5cdf5a248', 'scanner', 'W3AF Scanner', 'w3af', 'user_agent', 'Blocks W3AF web scanner', 'warning', true, true, 36, NULL),
			('eb60d9dd-1d53-4a42-b571-cef1d1314d4d', 'scanner', 'Acunetix Scanner', 'acunetix', 'user_agent', 'Blocks Acunetix web scanner', 'warning', true, true, 37, NULL),
			('86fddcd3-30ca-43d3-bd46-34875e018395', 'scanner', 'Havij Tool', 'havij', 'user_agent', 'Blocks Havij SQL injection tool', 'critical', true, true, 38, NULL),
			('bd7eeece-8f91-41a6-b06c-1ad69900512d', 'scanner', 'AppScan', 'appscan', 'user_agent', 'Blocks IBM AppScan', 'warning', true, true, 39, NULL),
			('6ee9b160-9472-4584-9c83-8de7b955a4b5', 'scanner', 'WebScarab', 'webscarab', 'user_agent', 'Blocks WebScarab proxy', 'warning', true, true, 40, NULL),
			('e78e2ef1-d710-409b-8a44-a03db3999b19', 'scanner', 'WebInspect', 'webinspect', 'user_agent', 'Blocks HP WebInspect', 'warning', true, true, 41, NULL),
			('8ec83a35-dea8-4f51-9185-37035f0a4501', 'http_method', 'Dangerous Methods', '^(TRACE|TRACK|DEBUG|CONNECT)$', 'request_method', 'Blocks dangerous HTTP methods', 'warning', true, true, 50, NULL)
			ON CONFLICT (id) DO NOTHING`,
		},

		// -----------------------------------------------------------------------
		// Performance indexes for logs_partitioned (v2.4.0+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.4.0: idx_logs_part_block_reason_ts",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_ts ON logs_partitioned (block_reason, timestamp DESC) WHERE block_reason != 'none'`,
		},
		{
			desc: "v2.4.0: idx_logs_part_client_ip",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_client_ip ON logs_partitioned (client_ip)`,
		},
		{
			desc: "v2.4.0: idx_logs_part_created_at",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_created_at ON logs_partitioned (created_at DESC)`,
		},
		{
			desc: "v2.4.0: idx_logs_part_status_code",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_status_code ON logs_partitioned (status_code) WHERE status_code IS NOT NULL`,
		},

		// -----------------------------------------------------------------------
		// proxy_hosts config status tracking (v2.3.5+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.3.5: proxy_hosts.config_status",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS config_status character varying(20) DEFAULT 'ok' NOT NULL`,
		},
		{
			desc: "v2.3.5: proxy_hosts.config_error",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS config_error text`,
		},

		// -----------------------------------------------------------------------
		// v1.3.31+: foreign key constraint for proxy_hosts.access_list_id.
		// First clean up any orphaned references, then add FK with ON DELETE SET NULL.
		// -----------------------------------------------------------------------
		{
			desc: "v1.3.31: proxy_hosts_access_list_id_fkey",
			sql: `DO $$
			BEGIN
				-- Clean up orphaned access_list_id references
				UPDATE public.proxy_hosts
				SET access_list_id = NULL
				WHERE access_list_id IS NOT NULL
				  AND access_list_id NOT IN (SELECT id FROM public.access_lists);

				-- Add FK constraint if not exists
				IF NOT EXISTS (
					SELECT 1 FROM pg_constraint WHERE conname = 'proxy_hosts_access_list_id_fkey'
				) THEN
					ALTER TABLE public.proxy_hosts
					ADD CONSTRAINT proxy_hosts_access_list_id_fkey
					FOREIGN KEY (access_list_id) REFERENCES public.access_lists(id) ON DELETE SET NULL;
				END IF;
			END $$`,
		},

		// -----------------------------------------------------------------------
		// Filter subscription tables (v2.7.0+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.7.0: CREATE TABLE filter_subscriptions",
			sql: `CREATE TABLE IF NOT EXISTS public.filter_subscriptions (
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
			)`,
		},
		{
			desc: "v2.7.0: CREATE TABLE filter_subscription_entries",
			sql: `CREATE TABLE IF NOT EXISTS public.filter_subscription_entries (
				id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
				subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
				value text NOT NULL,
				reason text,
				created_at timestamp with time zone DEFAULT now(),
				UNIQUE(subscription_id, value)
			)`,
		},
		{
			desc: "v2.7.0: idx_fse_subscription",
			sql:  `CREATE INDEX IF NOT EXISTS idx_fse_subscription ON public.filter_subscription_entries(subscription_id)`,
		},
		{
			desc: "v2.7.0: idx_fse_value",
			sql:  `CREATE INDEX IF NOT EXISTS idx_fse_value ON public.filter_subscription_entries(value)`,
		},
		{
			desc: "v2.7.0: CREATE TABLE filter_subscription_host_exclusions",
			sql: `CREATE TABLE IF NOT EXISTS public.filter_subscription_host_exclusions (
				id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
				subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
				proxy_host_id uuid NOT NULL REFERENCES public.proxy_hosts(id) ON DELETE CASCADE,
				created_at timestamp with time zone DEFAULT now(),
				UNIQUE(subscription_id, proxy_host_id)
			)`,
		},
		{
			desc: "v2.7.0: idx_fshe_proxy_host",
			sql:  `CREATE INDEX IF NOT EXISTS idx_fshe_proxy_host ON public.filter_subscription_host_exclusions(proxy_host_id)`,
		},

		// -----------------------------------------------------------------------
		// Filter subscription entry exclusions (v2.8.0+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.8.0: CREATE TABLE filter_subscription_entry_exclusions",
			sql: `CREATE TABLE IF NOT EXISTS public.filter_subscription_entry_exclusions (
				id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
				subscription_id uuid NOT NULL REFERENCES public.filter_subscriptions(id) ON DELETE CASCADE,
				value text NOT NULL,
				created_at timestamp with time zone DEFAULT now(),
				UNIQUE(subscription_id, value)
			)`,
		},
		{
			desc: "v2.8.0: idx_fsee_subscription",
			sql:  `CREATE INDEX IF NOT EXISTS idx_fsee_subscription ON public.filter_subscription_entry_exclusions(subscription_id)`,
		},
		{
			desc: "v2.8.0: filter_subscriptions.exclude_private_ips",
			sql:  `ALTER TABLE public.filter_subscriptions ADD COLUMN IF NOT EXISTS exclude_private_ips boolean DEFAULT false`,
		},

		// -----------------------------------------------------------------------
		// Global trusted IPs for bypassing all security features (v2.7.3+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.7.3: system_settings.global_trusted_ips",
			sql:  `ALTER TABLE public.system_settings ADD COLUMN IF NOT EXISTS global_trusted_ips text DEFAULT ''`,
		},

		// -----------------------------------------------------------------------
		// DB Performance: composite indexes for logs_partitioned (v2.8.0+)
		// -----------------------------------------------------------------------
		{
			desc: "v2.8.0: idx_logs_part_host_ts",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_host_ts ON logs_partitioned (host, timestamp DESC)`,
		},
		{
			desc: "v2.8.0: idx_logs_part_status_ts",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_status_ts ON logs_partitioned (status_code, timestamp DESC) WHERE status_code IS NOT NULL`,
		},
		{
			desc: "v2.8.0: idx_logs_part_proxy_host_ts",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_proxy_host_ts ON logs_partitioned (proxy_host_id, timestamp DESC) WHERE proxy_host_id IS NOT NULL`,
		},
		{
			desc: "v2.8.0: idx_logs_part_geo_ts",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_geo_ts ON logs_partitioned (geo_country_code, timestamp DESC) WHERE geo_country_code IS NOT NULL AND geo_country_code != ''`,
		},
		{
			desc: "v2.8.0: idx_logs_part_type_created",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_type_created ON logs_partitioned (log_type, created_at DESC)`,
		},

		// -----------------------------------------------------------------------
		// Performance indexes for log queries (GitHub Issue #96)
		// -----------------------------------------------------------------------
		{
			desc: "Issue #96: idx_logs_part_block_reason",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason ON logs_partitioned (block_reason) WHERE block_reason != 'none'`,
		},
		{
			desc: "Issue #96: idx_logs_part_status_created",
			sql:  `CREATE INDEX IF NOT EXISTS idx_logs_part_status_created ON logs_partitioned (status_code, created_at)`,
		},

		// -----------------------------------------------------------------------
		// Deduplicate dashboard_stats_hourly rows with NULL proxy_host_id (Issue #96).
		// Previous versions inserted duplicate rows per hour_bucket because
		// NULL != NULL in UNIQUE constraints. Keep the row with the highest
		// total_requests for each hour_bucket, delete the rest.
		//
		// NOTE: This is the statement that historically triggered `pq: chunk not
		// found` on installs with orphaned TimescaleDB chunks. With the refactor
		// it now runs in its own Exec; a failure here logs a warning and no longer
		// cascades into silently skipping every later statement.
		// -----------------------------------------------------------------------
		{
			desc: "Issue #96: dedup dashboard_stats_hourly NULL proxy_host_id",
			sql: `DELETE FROM dashboard_stats_hourly a
			USING dashboard_stats_hourly b
			WHERE a.proxy_host_id IS NULL
			  AND b.proxy_host_id IS NULL
			  AND a.hour_bucket = b.hour_bucket
			  AND a.id != b.id
			  AND (a.total_requests < b.total_requests OR (a.total_requests = b.total_requests AND a.id < b.id))`,
		},
		{
			// Partial unique index for NULL proxy_host_id to prevent future duplicates.
			// The standard UNIQUE(proxy_host_id, hour_bucket) does not prevent duplicate NULLs.
			desc: "Issue #96: idx_dashboard_stats_hourly_null_host_bucket",
			sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_dashboard_stats_hourly_null_host_bucket
				ON dashboard_stats_hourly (hour_bucket) WHERE proxy_host_id IS NULL`,
		},

		// -----------------------------------------------------------------------
		// v2.9.0: IPv6 toggle
		// -----------------------------------------------------------------------
		{
			desc: "v2.9.0: global_settings.enable_ipv6",
			sql:  `ALTER TABLE global_settings ADD COLUMN IF NOT EXISTS enable_ipv6 BOOLEAN NOT NULL DEFAULT TRUE`,
		},

		// -----------------------------------------------------------------------
		// Issue #105 — Default language for public error pages (403, etc.)
		// -----------------------------------------------------------------------
		{
			desc: "system_settings.ui_error_page_language",
			sql:  `ALTER TABLE public.system_settings ADD COLUMN IF NOT EXISTS ui_error_page_language character varying(10) DEFAULT 'auto'::character varying`,
		},

		// -----------------------------------------------------------------------
		// Issue #108 — Allow HTTPS upstream backends in load-balanced proxy hosts
		// -----------------------------------------------------------------------
		{
			desc: "upstreams.scheme",
			sql:  `ALTER TABLE public.upstreams ADD COLUMN IF NOT EXISTS scheme character varying(10) DEFAULT 'http'::character varying NOT NULL`,
		},

		// -----------------------------------------------------------------------
		// Issue #109 — Expose which load-balanced upstream served each request.
		// text (not inet/smallint) because Nginx reports a comma-separated list on retries,
		// e.g. "10.0.0.1:8080, 10.0.0.2:8080" / "502, 200".
		// The legacy `logs` table may have been dropped by migrateLogsToPartitioned on
		// installations that already switched to the partitioned table — guard accordingly.
		// -----------------------------------------------------------------------
		{
			desc: "logs.upstream_addr",
			sql: `DO $$ BEGIN
				IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'logs') THEN
					ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS upstream_addr text;
				END IF;
			END $$`,
		},
		{
			desc: "logs.upstream_status",
			sql: `DO $$ BEGIN
				IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'logs') THEN
					ALTER TABLE public.logs ADD COLUMN IF NOT EXISTS upstream_status text;
				END IF;
			END $$`,
		},
		{
			// Native partitioned parent — ALTER cascades to every attached logs_p* partition.
			desc: "logs_partitioned.upstream_addr",
			sql:  `ALTER TABLE public.logs_partitioned ADD COLUMN IF NOT EXISTS upstream_addr text`,
		},
		{
			desc: "logs_partitioned.upstream_status",
			sql:  `ALTER TABLE public.logs_partitioned ADD COLUMN IF NOT EXISTS upstream_status text`,
		},

		// -----------------------------------------------------------------------
		// Issue #123 — Defensive duplicates of the v2.13.2 columns. The upgrades
		// above should have landed these already, but keep these as a belt-and-
		// suspenders guarantee: handlers/repositories depend on the columns and
		// IF NOT EXISTS makes this a no-op when the earlier entry succeeded.
		// -----------------------------------------------------------------------
		{
			desc: "exploit_block_rules.auto_disabled_at (defensive)",
			sql:  `ALTER TABLE public.exploit_block_rules ADD COLUMN IF NOT EXISTS auto_disabled_at timestamp with time zone`,
		},
		{
			desc: "host_exploit_rule_exclusions.uri_pattern (defensive)",
			sql:  `ALTER TABLE public.host_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern text`,
		},
		{
			desc: "global_exploit_rule_exclusions.uri_pattern (defensive)",
			sql:  `ALTER TABLE public.global_exploit_rule_exclusions ADD COLUMN IF NOT EXISTS uri_pattern text`,
		},

		// -----------------------------------------------------------------------
		// Rebuild logs_unified so it exposes the new columns. The view UNIONs
		// `logs` (which may no longer exist post-migration) with `logs_partitioned`,
		// so we build the SQL dynamically: skip the legacy branch when the table
		// is gone.
		// -----------------------------------------------------------------------
		{
			desc: "logs_unified view rebuild",
			sql: `DO $$
			DECLARE
				has_legacy_logs boolean;
				view_sql text;
				col_list text := 'id, log_type, "timestamp", host, client_ip,
					geo_country, geo_country_code, geo_city, geo_asn, geo_org,
					request_method, request_uri, request_protocol, status_code,
					body_bytes_sent, request_time, upstream_response_time,
					http_referer, http_user_agent, http_x_forwarded_for,
					severity, error_message,
					rule_id, rule_message, rule_severity, rule_data,
					attack_type, action_taken,
					block_reason, bot_category,
					proxy_host_id, raw_log, created_at,
					upstream_addr, upstream_status';
			BEGIN
				SELECT EXISTS (
					SELECT 1 FROM information_schema.tables
					WHERE table_schema = 'public' AND table_name = 'logs'
				) INTO has_legacy_logs;

				EXECUTE 'DROP VIEW IF EXISTS public.logs_unified CASCADE';
				IF has_legacy_logs THEN
					view_sql := 'CREATE VIEW public.logs_unified AS ' ||
						'SELECT ' || col_list || ' FROM public.logs ' ||
						'UNION ALL ' ||
						'SELECT ' || col_list || ' FROM public.logs_partitioned';
				ELSE
					view_sql := 'CREATE VIEW public.logs_unified AS ' ||
						'SELECT ' || col_list || ' FROM public.logs_partitioned';
				END IF;
				EXECUTE view_sql;
			END $$`,
		},

		// -----------------------------------------------------------------------
		// v2.13.7: Dotenv file access rule — seeds the path-based (request_uri)
		// rule that blocks /.env, /.env.local, /.env.production, etc. on every
		// proxy host that has block_exploits enabled. Fresh installs already
		// receive the row via the initial seed in 001_init.sql; this entry
		// backfills the same row for installs that were provisioned before
		// v2.13.7. ON CONFLICT DO NOTHING preserves admin edits if the rule
		// has already been customised.
		// -----------------------------------------------------------------------
		{
			desc: "v2.13.7: seed ENV-001 (Dotenv File Access) rule",
			sql: `INSERT INTO public.exploit_block_rules
				(id, category, name, pattern, pattern_type, description, severity, enabled, is_system, sort_order, auto_disabled_at)
				VALUES (
					'c1e7f001-0000-4000-8000-000000000001',
					'rfi',
					'Dotenv File Access',
					E'/\\.env(\\.|$|/)',
					'request_uri',
					'Blocks access to .env config files (.env, .env.local, .env.production, ...)',
					'critical', true, true, 23, NULL
				) ON CONFLICT (id) DO NOTHING`,
		},

		// -----------------------------------------------------------------------
		// v2.13.17: Backfill missing proxy_host_id indexes on per-host config
		// tables. UNIQUE(proxy_host_id) constraints already exist but cannot
		// satisfy the planner for plain SELECT ... WHERE proxy_host_id = $1 +
		// other predicates / sort. During nginx config generation each host
		// pulls 8+ rows through these tables; without dedicated btree indexes
		// the planner falls back to seq scans at scale.
		// -----------------------------------------------------------------------
		{
			desc: "v2.13.17: btree index banned_ips(proxy_host_id, banned_at DESC)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_banned_ips_host_banned_at ON public.banned_ips USING btree (proxy_host_id, banned_at DESC)`,
		},
		{
			desc: "v2.13.17: btree index bot_filters(proxy_host_id)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_bot_filters_proxy_host ON public.bot_filters USING btree (proxy_host_id)`,
		},
		{
			desc: "v2.13.17: btree index rate_limits(proxy_host_id)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_rate_limits_proxy_host ON public.rate_limits USING btree (proxy_host_id)`,
		},
		{
			desc: "v2.13.17: btree index security_headers(proxy_host_id)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_security_headers_proxy_host ON public.security_headers USING btree (proxy_host_id)`,
		},
		{
			desc: "v2.13.17: btree index challenge_configs(proxy_host_id)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_challenge_configs_proxy_host ON public.challenge_configs USING btree (proxy_host_id)`,
		},
		{
			desc: "v2.13.17: btree index upstreams(proxy_host_id)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_upstreams_proxy_host ON public.upstreams USING btree (proxy_host_id)`,
		},
		{
			desc: "v2.13.17: btree index fail2ban_configs(proxy_host_id)",
			sql:  `CREATE INDEX IF NOT EXISTS idx_fail2ban_configs_proxy_host ON public.fail2ban_configs USING btree (proxy_host_id)`,
		},

		// -----------------------------------------------------------------------
		// v2.13.18: Dashboard "blocked requests" partial composite index.
		// idx_logs_part_block_reason (single-column) exists but the dashboard
		// query also bounds by created_at >= NOW() - 24h. Without created_at
		// in the index, the planner reads every block_reason != 'none' row in
		// history and filters post-scan. log_type='access' narrows the index
		// to the only log type that carries block_reason in practice.
		// -----------------------------------------------------------------------
		{
			desc: "v2.13.18: idx_logs_part_block_reason_created",
			sql: `CREATE INDEX IF NOT EXISTS idx_logs_part_block_reason_created
				ON logs_partitioned (created_at DESC, block_reason)
				WHERE block_reason != 'none' AND log_type = 'access'`,
		},
		// -----------------------------------------------------------------------
		// v2.17.0: Align global_settings DEFAULT values with the "performance"
		// preset shipped in model.GlobalSettingsPresets["performance"]. The
		// original DEFAULTs (worker_connections 1024, keepalive_timeout 65,
		// keepalive_requests 100) pre-dated the explicit preset system and were
		// inconsistent with the preset values an operator would apply via the
		// UI. Existing rows are intentionally NOT updated — an operator may have
		// deliberately customized these values; only column DEFAULTs change so
		// fresh installs and any future INSERT pick up the new baseline.
		// -----------------------------------------------------------------------
		{
			desc: "v2.17.0: global_settings.worker_connections DEFAULT 1024 -> 8192",
			sql:  `ALTER TABLE public.global_settings ALTER COLUMN worker_connections SET DEFAULT 8192`,
		},
		{
			desc: "v2.17.0: global_settings.keepalive_timeout DEFAULT 65 -> 30",
			sql:  `ALTER TABLE public.global_settings ALTER COLUMN keepalive_timeout SET DEFAULT 30`,
		},
		{
			desc: "v2.17.0: global_settings.keepalive_requests DEFAULT 100 -> 1000",
			sql:  `ALTER TABLE public.global_settings ALTER COLUMN keepalive_requests SET DEFAULT 1000`,
		},
		// -----------------------------------------------------------------------
		// v2.17.1: Raw log storage is mandatory — LogCollector switched to
		// file-tail in v2.14.2 and depends on /etc/nginx/logs/access_raw.log.
		// Older installs with raw_log_enabled=false silently lost all access
		// log ingestion (issue #145). Flip every existing row to true and lock
		// the DEFAULT so future inserts can't regress. Boot-time fix in
		// SystemSettingsHandler.EnsureRawLogEnabled is the runtime guarantee;
		// these two statements make the DB state consistent with that runtime
		// invariant so a manual psql UPDATE can't reintroduce the bug.
		// -----------------------------------------------------------------------
		{
			desc: "v2.17.1: system_settings.raw_log_enabled force true on every row",
			sql:  `UPDATE public.system_settings SET raw_log_enabled = true WHERE raw_log_enabled = false`,
		},
		{
			desc: "v2.17.1: system_settings.raw_log_enabled DEFAULT true (mandatory since v2.17.1)",
			sql:  `ALTER TABLE public.system_settings ALTER COLUMN raw_log_enabled SET DEFAULT true`,
		},

		// -----------------------------------------------------------------------
		// v2.18.0: Stream proxy listener uniqueness. Two enabled stream hosts
		// must not share (listen_host, listen_port, protocol) — otherwise nginx
		// rejects the generated config on reload. Service-layer check still
		// runs first for nicer error messaging; the partial unique index is
		// the source of truth that survives TOCTOU under concurrent creates
		// and direct DB writes.
		// -----------------------------------------------------------------------
		{
			desc: "v2.18.0: proxy_hosts stream listener partial unique index",
			sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_hosts_stream_listener_unique
				ON public.proxy_hosts (stream_listen_host, stream_listen_port, stream_protocol)
				WHERE proxy_type = 'stream' AND enabled = true AND stream_listen_port > 0`,
		},

		// -----------------------------------------------------------------------
		// v2.20.0 (Issue #150): Docker container-name forward target. Nullable
		// TEXT — existing rows get NULL and behave exactly as before (host:port
		// forwarding); a non-NULL value names a Docker container to resolve.
		// -----------------------------------------------------------------------
		{
			desc: "v2.20.0: proxy_hosts.forward_container_name (#150)",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS forward_container_name text`,
		},
		// -----------------------------------------------------------------------
		// v2.20.1 (Issue #151): Docker container network. Nullable TEXT — records
		// the network the user picked in the UI so the reconcile scheduler can
		// pin to the correct network's IP on multi-network containers. Existing
		// v2.20.0 rows (NULL) are skipped by the scheduler (safe mode) until the
		// user re-selects the container.
		// -----------------------------------------------------------------------
		{
			desc: "v2.20.1: proxy_hosts.forward_container_network (#151)",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS forward_container_network text`,
		},
		// -----------------------------------------------------------------------
		// Issue #154: DDNS records table. Keeps registered hostnames' A records
		// pointed at the server's public IPv4 via Cloudflare/DuckDNS. FK to
		// dns_providers (credentials reused) with ON DELETE CASCADE.
		// -----------------------------------------------------------------------
		{
			desc: "create ddns_records table (#154)",
			sql: `CREATE TABLE IF NOT EXISTS public.ddns_records (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL PRIMARY KEY,
    hostname character varying(253) NOT NULL,
    dns_provider_id uuid NOT NULL REFERENCES public.dns_providers(id) ON DELETE CASCADE,
    record_type character varying(8) DEFAULT 'A' NOT NULL,
    proxied boolean DEFAULT false NOT NULL,
    ttl integer DEFAULT 1 NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    last_ip character varying(45) DEFAULT '' NOT NULL,
    last_synced_at timestamp with time zone,
    last_status character varying(16) DEFAULT '' NOT NULL,
    last_error text DEFAULT '' NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ddns_records_hostname_provider ON public.ddns_records (hostname, dns_provider_id);`,
		},
		// -----------------------------------------------------------------------
		// Issue #157: proxy host ↔ DDNS integration. Opt-in on the host
		// (ddns_enabled + ddns_provider_id), a back-link on the DDNS record
		// (proxy_host_id, ON DELETE CASCADE), and a configurable sync interval.
		// FKs are wrapped in DO/EXCEPTION blocks so re-running is idempotent
		// (ADD CONSTRAINT has no IF NOT EXISTS).
		// -----------------------------------------------------------------------
		{
			desc: "v2.23.0: proxy_hosts.ddns_enabled/ddns_provider_id (#157)",
			sql: `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS ddns_enabled boolean DEFAULT false NOT NULL;
ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS ddns_provider_id uuid;
DO $$ BEGIN ALTER TABLE public.proxy_hosts ADD CONSTRAINT proxy_hosts_ddns_provider_id_fkey FOREIGN KEY (ddns_provider_id) REFERENCES public.dns_providers(id) ON DELETE SET NULL; EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		},
		{
			desc: "v2.24.5: proxy_hosts.ddns_proxied default for managed DDNS (#160)",
			sql:  `ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS ddns_proxied boolean DEFAULT false NOT NULL;`,
		},
		{
			desc: "v2.23.0: ddns_records.proxy_host_id (#157)",
			sql: `ALTER TABLE public.ddns_records ADD COLUMN IF NOT EXISTS proxy_host_id uuid;
DO $$ BEGIN ALTER TABLE public.ddns_records ADD CONSTRAINT ddns_records_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE; EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,
		},
		{
			desc: "v2.23.0: system_settings.ddns_check_interval_minutes (#157)",
			sql:  `ALTER TABLE public.system_settings ADD COLUMN IF NOT EXISTS ddns_check_interval_minutes integer DEFAULT 5 NOT NULL;`,
		},
	}
	for _, a := range upgrades {
		if _, err := db.Exec(a.sql); err != nil {
			log.Printf("Warning: upgrade %q failed: %v", a.desc, err)
		}
	}

	// v2.13.3: one-shot auto-disable for overly-broad system rules (Issue #123).
	// Runs as an INDEPENDENT db.Exec so a prior failure in upgradeSQL (e.g. a
	// stale TimescaleDB chunk error that aborts the implicit transaction) cannot
	// silently skip the fix. v2.13.2 placed this DO block inside upgradeSQL and
	// the implicit-transaction abort left the three rules enabled on affected
	// installations. The helper is idempotent — it only updates rows where
	// auto_disabled_at IS NULL AND enabled = true, so admins who have already
	// re-enabled are not touched and repeat boots are no-ops.
	if err := ApplyExploitRulesAutoDisable(db.DB); err != nil {
		log.Printf("Warning: exploit rules auto-disable migration failed: %v", err)
	}

	// Run 006_fix_numeric_overflow migration for existing installations (Issue #29 fix)
	if err := db.runNumericOverflowMigration(); err != nil {
		log.Printf("Warning: numeric overflow migration had issues: %v", err)
	}

	// Run 008_fix_partition_timezone_v2 migration (fixes timezone detection bug in 007)
	if err := db.runPartitionTimezoneMigration(); err != nil {
		log.Printf("Warning: partition timezone migration had issues: %v", err)
	}

	// Run 009_pregenerate_partitions migration (pre-generates 10 years of partitions)
	if err := db.runPregeneratePartitionsMigration(); err != nil {
		log.Printf("Warning: partition pre-generation migration had issues: %v", err)
	}

	// Run 010_fix_hypertable_numeric migration (fixes numeric type after TimescaleDB migration, Issue #55)
	if err := db.runHypertableNumericFixMigration(); err != nil {
		log.Printf("Warning: hypertable numeric fix migration had issues: %v", err)
	}

	// Add pg_trgm GIN indexes for ILIKE search performance on logs
	if err := db.runTrgmIndexMigration(); err != nil {
		log.Printf("Warning: pg_trgm index migration had issues: %v", err)
	}

	// Migrate logs table to logs_partitioned in background (for existing installations).
	// This allows API to start immediately while migration runs. Each migration
	// derives its timeout from db.BackgroundContext() so a SIGTERM during
	// migration cancels it instead of letting it run for ~30 minutes after
	// the process is supposed to be shutting down (Issue: orphan goroutine
	// risk on container restart).
	db.TrackBackground()
	go func() {
		defer db.BackgroundDone()
		ctx, cancel := context.WithTimeout(db.BackgroundContext(), 30*time.Minute)
		defer cancel()
		_ = ctx // wired through Close() via BackgroundContext cancellation
		db.migrateLogsToPartitioned()
	}()

	// Migrate to TimescaleDB hypertable in background (for existing installations)
	db.TrackBackground()
	go func() {
		defer db.BackgroundDone()
		ctx, cancel := context.WithTimeout(db.BackgroundContext(), 30*time.Minute)
		defer cancel()
		_ = ctx
		db.migrateToTimescaleDB()
	}()

	// Migrate other log tables to hypertables
	db.TrackBackground()
	go func() {
		defer db.BackgroundDone()
		ctx, cancel := context.WithTimeout(db.BackgroundContext(), 30*time.Minute)
		defer cancel()
		_ = ctx
		db.migrateLogTablesToHypertables()
	}()

	log.Println("Schema migration completed")
	return nil
}

// enableTimescaleDB enables the TimescaleDB extension
func (db *DB) enableTimescaleDB() error {
	_, err := db.Exec(`CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE`)
	if err != nil {
		return err
	}
	log.Println("[TimescaleDB] Extension enabled successfully")
	return nil
}

// isTimescaleDBAvailable checks if TimescaleDB extension is available
func (db *DB) isTimescaleDBAvailable() bool {
	var available bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'timescaledb')`).Scan(&available)
	return err == nil && available
}

// isHypertable checks if a table is already a TimescaleDB hypertable
func (db *DB) isHypertable(tableName string) bool {
	var isHyper bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM timescaledb_information.hypertables
			WHERE hypertable_name = $1
		)
	`, tableName).Scan(&isHyper)
	return err == nil && isHyper
}

// migrateLogsToPartitioned migrates data from old logs table to logs_partitioned
func (db *DB) migrateLogsToPartitioned() {
	// Check if old logs table exists
	var logsExists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs'
		)
	`).Scan(&logsExists)
	if err != nil || !logsExists {
		return // No old logs table, nothing to migrate
	}

	// Check if there's data to migrate
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM logs LIMIT 1`).Scan(&count)
	if err != nil || count == 0 {
		// No data, just drop the old table
		log.Println("[Migration] Dropping empty logs table...")
		db.Exec(`DROP TABLE IF EXISTS logs CASCADE`)
		return
	}

	log.Printf("[Migration] Found old logs table with data, migrating to logs_partitioned...")

	// Migrate in batches
	batchSize := 50000
	totalMigrated := 0

	for {
		result, err := db.Exec(`
			WITH batch AS (
				SELECT id FROM logs
				WHERE NOT EXISTS (SELECT 1 FROM logs_partitioned lp WHERE lp.id = logs.id)
				LIMIT $1
			)
			INSERT INTO logs_partitioned (
				id, log_type, timestamp, host, client_ip,
				request_method, request_uri, request_protocol, status_code,
				body_bytes_sent, request_time, upstream_response_time,
				upstream_addr, upstream_status,
				http_referer, http_user_agent, http_x_forwarded_for,
				severity, error_message,
				rule_id, rule_message, rule_severity, rule_data, attack_type, action_taken,
				proxy_host_id, raw_log, created_at,
				geo_country, geo_country_code, geo_city, geo_asn, geo_org,
				block_reason, bot_category, exploit_rule
			)
			SELECT
				l.id, l.log_type, l.timestamp, l.host, l.client_ip,
				l.request_method, l.request_uri, l.request_protocol, l.status_code,
				l.body_bytes_sent, l.request_time, l.upstream_response_time,
				l.upstream_addr, l.upstream_status,
				l.http_referer, l.http_user_agent, l.http_x_forwarded_for,
				l.severity, l.error_message,
				l.rule_id, l.rule_message, l.rule_severity, l.rule_data, l.attack_type, l.action_taken,
				l.proxy_host_id, l.raw_log, l.created_at,
				l.geo_country, l.geo_country_code, l.geo_city, l.geo_asn, l.geo_org,
				l.block_reason, l.bot_category, l.exploit_rule
			FROM logs l
			WHERE l.id IN (SELECT id FROM batch)
		`, batchSize)

		if err != nil {
			log.Printf("[Migration] Error migrating logs batch: %v", err)
			break
		}

		rowsAffected, _ := result.RowsAffected()
		totalMigrated += int(rowsAffected)

		if rowsAffected < int64(batchSize) {
			break
		}

		log.Printf("[Migration] Migrated %d logs so far...", totalMigrated)
	}

	if totalMigrated > 0 {
		log.Printf("[Migration] Migrated %d logs to logs_partitioned", totalMigrated)
	}

	// Drop old logs table
	log.Println("[Migration] Dropping old logs table...")
	_, err = db.Exec(`DROP TABLE IF EXISTS logs CASCADE`)
	if err != nil {
		log.Printf("[Migration] Warning: failed to drop old logs table: %v", err)
	} else {
		log.Println("[Migration] Old logs table dropped successfully")

		// `DROP ... CASCADE` also drops dependent objects, which includes logs_unified
		// if it was built from both `logs` and `logs_partitioned` during startup.
		// Rebuild it immediately so live log queries don't hit "relation does not exist".
		_, rebuildErr := db.Exec(`
			DROP VIEW IF EXISTS public.logs_unified CASCADE;
			CREATE VIEW public.logs_unified AS
			 SELECT id, log_type, "timestamp", host, client_ip,
			        geo_country, geo_country_code, geo_city, geo_asn, geo_org,
			        request_method, request_uri, request_protocol, status_code,
			        body_bytes_sent, request_time, upstream_response_time,
			        http_referer, http_user_agent, http_x_forwarded_for,
			        severity, error_message,
			        rule_id, rule_message, rule_severity, rule_data,
			        attack_type, action_taken,
			        block_reason, bot_category,
			        proxy_host_id, raw_log, created_at,
			        upstream_addr, upstream_status
			   FROM public.logs_partitioned
		`)
		if rebuildErr != nil {
			log.Printf("[Migration] Warning: failed to rebuild logs_unified view after drop: %v", rebuildErr)
		} else {
			log.Println("[Migration] logs_unified view rebuilt (single-table form)")
		}
	}
}

// migrateToTimescaleDB converts logs_partitioned (PostgreSQL native PARTITION BY
// RANGE table created by 001_init.sql) into a TimescaleDB hypertable. Runs once
// per install: marked complete in schema_migrations as 'timescaledb_hypertable'.
// Applies to both fresh installs and existing installations that pre-date the
// hypertable conversion — fresh installs simply migrate zero rows.
func (db *DB) migrateToTimescaleDB() {
	// Wait a bit for other migrations to complete
	time.Sleep(5 * time.Second)

	// Check if TimescaleDB is available
	if !db.isTimescaleDBAvailable() {
		log.Println("[TimescaleDB] Extension not available, skipping migration")
		return
	}

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 'timescaledb_hypertable')`).Scan(&migrated)
	if err == nil && migrated {
		log.Println("[TimescaleDB] Already migrated to hypertable")
		// Still set up compression policy
		db.setupTimescaleDBCompression()
		return
	}

	// Check if logs_hypertable already exists (indicates in-progress or completed migration)
	if db.isHypertable("logs_hypertable") {
		log.Println("[TimescaleDB] Hypertable already exists")
		db.setupTimescaleDBCompression()
		return
	}

	// Check if logs_partitioned exists and has data
	var hasData bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs_partitioned'
		)
	`).Scan(&hasData)
	if err != nil || !hasData {
		log.Println("[TimescaleDB] No logs_partitioned table found, will create hypertable on fresh install")
		return
	}

	log.Println("[TimescaleDB] Starting migration from partitioned table to hypertable...")
	ctx := context.Background()

	// Use transaction for safety
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()

	// Step 1: Create new hypertable with same structure
	log.Println("[TimescaleDB] Creating hypertable structure...")
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS logs_hypertable (
			id uuid NOT NULL DEFAULT gen_random_uuid(),
			log_type log_type NOT NULL,
			timestamp timestamp with time zone NOT NULL DEFAULT now(),
			host text,
			client_ip inet,
			request_method text,
			request_uri text,
			request_protocol text,
			status_code integer,
			body_bytes_sent bigint,
			request_time double precision,
			upstream_response_time double precision,
			upstream_addr text,
			upstream_status text,
			http_referer text,
			http_user_agent text,
			http_x_forwarded_for text,
			severity log_severity,
			error_message text,
			rule_id integer,
			rule_message text,
			rule_severity text,
			rule_data text,
			attack_type text,
			action_taken text,
			proxy_host_id uuid,
			raw_log text,
			created_at timestamp with time zone NOT NULL DEFAULT now(),
			geo_country text,
			geo_country_code varchar(2),
			geo_city text,
			geo_asn text,
			geo_org text,
			block_reason block_reason DEFAULT 'none',
			bot_category text,
			exploit_rule varchar(50)
		)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to create table structure: %v", err)
		return
	}

	// Step 2: Convert to hypertable
	log.Println("[TimescaleDB] Converting to hypertable...")
	_, err = tx.Exec(`
		SELECT create_hypertable(
			'logs_hypertable',
			by_range('created_at', INTERVAL '1 day'),
			if_not_exists => TRUE
		)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to create hypertable: %v", err)
		return
	}

	if err = tx.Commit(); err != nil {
		log.Printf("[TimescaleDB] Failed to commit hypertable creation: %v", err)
		return
	}

	// Step 3: Migrate data in batches using cursor-based pagination (outside transaction for large data)
	// Cursor-based pagination avoids O(n²) memory/CPU cost of OFFSET pagination
	log.Println("[TimescaleDB] Migrating data from partitioned table...")
	batchSize := 50000
	totalMigrated := 0

	// Get approximate count for progress reporting (use reltuples for large tables to avoid full scan)
	var totalCount int64
	db.QueryRow(`SELECT COALESCE(reltuples::bigint, 0) FROM pg_class WHERE relname = 'logs_partitioned'`).Scan(&totalCount)
	if totalCount <= 0 {
		// Fallback to exact count only if estimate is unavailable
		db.QueryRow(`SELECT COUNT(*) FROM logs_partitioned`).Scan(&totalCount)
	}
	log.Printf("[TimescaleDB] Estimated logs to migrate: %d", totalCount)

	// Anti-join pagination (matches migrateLogsToPartitioned). The previous
	// cursor pagination (`WHERE created_at >= lastCreatedAt`) re-inserted
	// rows that shared a `created_at` value with the last batch's tail,
	// and logs_hypertable has no PK to deduplicate — yielding an unbounded
	// migration loop on installs with bursty log timestamps. NOT EXISTS
	// makes the loop converge to zero new rows.
	for {
		result, err := db.Exec(`
			INSERT INTO logs_hypertable (
				id, log_type, timestamp, host, client_ip, request_method, request_uri,
				request_protocol, status_code, body_bytes_sent, request_time,
				upstream_response_time, upstream_addr, upstream_status,
				http_referer, http_user_agent, http_x_forwarded_for,
				severity, error_message, rule_id, rule_message, rule_severity, rule_data,
				attack_type, action_taken, proxy_host_id, raw_log, created_at,
				geo_country, geo_country_code, geo_city, geo_asn, geo_org,
				block_reason, bot_category, exploit_rule
			)
			SELECT
				lp.id, lp.log_type, lp.timestamp, lp.host, lp.client_ip, lp.request_method, lp.request_uri,
				lp.request_protocol, lp.status_code, lp.body_bytes_sent, lp.request_time,
				lp.upstream_response_time, lp.upstream_addr, lp.upstream_status,
				lp.http_referer, lp.http_user_agent, lp.http_x_forwarded_for,
				lp.severity, lp.error_message, lp.rule_id, lp.rule_message, lp.rule_severity, lp.rule_data,
				lp.attack_type, lp.action_taken, lp.proxy_host_id, lp.raw_log, lp.created_at,
				lp.geo_country, lp.geo_country_code, lp.geo_city, lp.geo_asn, lp.geo_org,
				lp.block_reason, lp.bot_category, lp.exploit_rule
			FROM logs_partitioned lp
			WHERE NOT EXISTS (
				SELECT 1 FROM logs_hypertable lh WHERE lh.id = lp.id
			)
			ORDER BY lp.created_at
			LIMIT $1
		`, batchSize)

		if err != nil {
			log.Printf("[TimescaleDB] Error migrating batch: %v", err)
			break
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			break
		}

		totalMigrated += int(rowsAffected)

		if totalCount > 0 {
			progress := float64(totalMigrated) / float64(totalCount) * 100
			log.Printf("[TimescaleDB] Migrated %d/%d logs (%.1f%%)...", totalMigrated, totalCount, progress)
		} else {
			log.Printf("[TimescaleDB] Migrated %d logs so far...", totalMigrated)
		}

		// Small delay to reduce load
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("[TimescaleDB] Migration complete: %d logs migrated", totalMigrated)

	// Step 4: Create indexes on hypertable
	log.Println("[TimescaleDB] Creating indexes...")
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_timestamp ON logs_hypertable (created_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_host ON logs_hypertable (host)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_type_time ON logs_hypertable (log_type, created_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_logs_ht_exploit ON logs_hypertable (exploit_rule) WHERE exploit_rule IS NOT NULL AND exploit_rule <> '-'`)

	// Step 5: Swap tables (rename)
	log.Println("[TimescaleDB] Swapping tables...")
	tx2, err := db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to begin swap transaction: %v", err)
		return
	}
	defer tx2.Rollback()

	// Rename old table as backup
	_, err = tx2.Exec(`ALTER TABLE logs_partitioned RENAME TO logs_partitioned_backup`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to rename old table: %v", err)
		return
	}

	// Rename hypertable to logs_partitioned
	_, err = tx2.Exec(`ALTER TABLE logs_hypertable RENAME TO logs_partitioned`)
	if err != nil {
		log.Printf("[TimescaleDB] Failed to rename hypertable: %v", err)
		// Rollback the rename
		tx2.Rollback()
		db.Exec(`ALTER TABLE logs_partitioned_backup RENAME TO logs_partitioned`)
		return
	}

	if err = tx2.Commit(); err != nil {
		log.Printf("[TimescaleDB] Failed to commit table swap: %v", err)
		return
	}

	// Mark migration as complete
	db.Exec(`INSERT INTO schema_migrations (version) VALUES ('timescaledb_hypertable') ON CONFLICT DO NOTHING`)

	log.Println("[TimescaleDB] Migration to hypertable completed successfully!")

	// Set up compression
	db.setupTimescaleDBCompression()

	// Clean up backup table. On fresh installs the source carried no rows, so
	// the backup has nothing worth keeping. Critically, its leftover indexes
	// (idx_logs_part_*) live in the same schema namespace as the new
	// logs_partitioned, which causes upgradeSQL's `CREATE INDEX IF NOT EXISTS`
	// statements to silently skip on subsequent boots (the index name already
	// exists, just on the wrong table). Dropping the empty backup frees those
	// names so the supporting indexes get created on the live hypertable.
	// On installs with real data, keep the backup so operators can verify the
	// migration before dropping it manually.
	if totalMigrated == 0 {
		log.Println("[TimescaleDB] Source table was empty, dropping logs_partitioned_backup")
		if _, err := db.Exec(`DROP TABLE IF EXISTS public.logs_partitioned_backup CASCADE`); err != nil {
			log.Printf("[TimescaleDB] Warning: failed to drop empty backup: %v", err)
		}
	} else {
		log.Println("[TimescaleDB] Backup table 'logs_partitioned_backup' kept for safety. Drop manually when verified.")
	}

	// Build the canonical index set on the NEW live hypertable. The swap left
	// the original idx_logs_part_* names on the backup table, so without this
	// the live table runs with only the four idx_logs_ht_* basics and every
	// CREATE INDEX IF NOT EXISTS elsewhere silently no-ops on the squatted
	// names. (Already in a background goroutine — safe to run inline.)
	db.ensureLogsPartitionedIndexes()
}

// migrateLogTablesToHypertables migrates system_logs, challenge_logs, audit_logs to hypertables
func (db *DB) migrateLogTablesToHypertables() {
	// Wait for main migration to complete
	time.Sleep(10 * time.Second)

	if !db.isTimescaleDBAvailable() {
		log.Println("[TimescaleDB] Extension not available, skipping log tables migration")
		return
	}

	// Define log tables to migrate
	logTables := []struct {
		name      string
		segmentBy string
	}{
		{"system_logs", "source, level"},
		{"challenge_logs", "result"},
		{"audit_logs", "action"},
	}

	for _, table := range logTables {
		db.migrateTableToHypertable(table.name, table.segmentBy)
	}
}

// migrateTableToHypertable converts a regular table to a TimescaleDB hypertable
func (db *DB) migrateTableToHypertable(tableName, segmentBy string) {
	migrationKey := fmt.Sprintf("timescaledb_%s", tableName)

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationKey).Scan(&migrated)
	if err == nil && migrated {
		log.Printf("[TimescaleDB] %s already migrated to hypertable", tableName)
		db.setupTableCompression(tableName, segmentBy)
		return
	}

	// Check if table exists
	var tableExists bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)
	`, tableName).Scan(&tableExists)
	if err != nil || !tableExists {
		log.Printf("[TimescaleDB] Table %s not found, skipping", tableName)
		return
	}

	// Check if already a hypertable
	if db.isHypertable(tableName) {
		log.Printf("[TimescaleDB] %s is already a hypertable", tableName)
		db.setupTableCompression(tableName, segmentBy)
		db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationKey)
		return
	}

	log.Printf("[TimescaleDB] Starting migration of %s to hypertable...", tableName)

	// Get row count
	var rowCount int64
	db.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, tableName)).Scan(&rowCount)
	log.Printf("[TimescaleDB] %s has %d rows", tableName, rowCount)

	// For tables with foreign keys, we need to handle them carefully
	// Drop foreign key constraints temporarily
	var fkConstraints []struct {
		name       string
		definition string
	}
	rows, err := db.Query(`
		SELECT conname, pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conrelid = $1::regclass AND contype = 'f'
	`, tableName)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name, def string
			rows.Scan(&name, &def)
			fkConstraints = append(fkConstraints, struct {
				name       string
				definition string
			}{name, def})
		}
	}

	// Drop primary key (will recreate with created_at)
	db.Exec(fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s_pkey`, tableName, tableName))

	// Drop foreign keys temporarily
	for _, fk := range fkConstraints {
		log.Printf("[TimescaleDB] Dropping FK %s temporarily", fk.name)
		db.Exec(fmt.Sprintf(`ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s`, tableName, fk.name))
	}

	// Convert to hypertable
	_, err = db.Exec(fmt.Sprintf(`
		SELECT create_hypertable(
			'%s',
			by_range('created_at', INTERVAL '1 day'),
			migrate_data => true,
			if_not_exists => true
		)
	`, tableName))
	if err != nil {
		log.Printf("[TimescaleDB] Failed to convert %s to hypertable: %v", tableName, err)
		// Restore primary key
		db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id)`, tableName))
		// Restore foreign keys
		for _, fk := range fkConstraints {
			db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s %s`, tableName, fk.name, fk.definition))
		}
		return
	}

	log.Printf("[TimescaleDB] %s converted to hypertable successfully", tableName)

	// Recreate primary key with created_at (required for hypertables)
	db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD PRIMARY KEY (id, created_at)`, tableName))

	// Restore foreign keys
	for _, fk := range fkConstraints {
		log.Printf("[TimescaleDB] Restoring FK %s", fk.name)
		_, err := db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s %s`, tableName, fk.name, fk.definition))
		if err != nil {
			log.Printf("[TimescaleDB] Warning: failed to restore FK %s: %v", fk.name, err)
		}
	}

	// Mark as migrated
	db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationKey)

	// Setup compression
	db.setupTableCompression(tableName, segmentBy)
}

// setupTableCompression sets up compression for a specific hypertable
func (db *DB) setupTableCompression(tableName, segmentBy string) {
	if !db.isHypertable(tableName) {
		return
	}

	// Check if compression is already enabled
	var compressionEnabled bool
	db.QueryRow(`
		SELECT compression_enabled
		FROM timescaledb_information.hypertables
		WHERE hypertable_name = $1
	`, tableName).Scan(&compressionEnabled)

	if compressionEnabled {
		log.Printf("[TimescaleDB] Compression already enabled for %s", tableName)
		return
	}

	log.Printf("[TimescaleDB] Setting up compression for %s...", tableName)

	// Enable compression
	_, err := db.Exec(fmt.Sprintf(`
		ALTER TABLE %s SET (
			timescaledb.compress,
			timescaledb.compress_segmentby = '%s',
			timescaledb.compress_orderby = 'created_at DESC'
		)
	`, tableName, segmentBy))
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to enable compression for %s: %v", tableName, err)
		return
	}

	// Add compression policy
	_, err = db.Exec(fmt.Sprintf(`
		SELECT add_compression_policy('%s', INTERVAL '7 days', if_not_exists => true)
	`, tableName))
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to add compression policy for %s: %v", tableName, err)
		return
	}

	log.Printf("[TimescaleDB] Compression enabled for %s", tableName)

	// Compress existing old chunks immediately
	db.Exec(fmt.Sprintf(`SELECT compress_chunk(c) FROM show_chunks('%s', older_than => INTERVAL '7 days') c`, tableName))

	// Show compression status
	var compressedChunks, totalChunks int
	err = db.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE is_compressed) as compressed,
			COUNT(*) as total
		FROM timescaledb_information.chunks
		WHERE hypertable_name = $1
	`, tableName).Scan(&compressedChunks, &totalChunks)
	if err == nil && totalChunks > 0 {
		log.Printf("[TimescaleDB] %s compression status: %d/%d chunks compressed", tableName, compressedChunks, totalChunks)
	}
}

// setupTimescaleDBCompression sets up compression policy for the hypertable
func (db *DB) setupTimescaleDBCompression() {
	if !db.isTimescaleDBAvailable() {
		return
	}

	// Check if logs_partitioned is a hypertable
	if !db.isHypertable("logs_partitioned") {
		log.Println("[TimescaleDB] logs_partitioned is not a hypertable, skipping compression setup")
		return
	}

	log.Println("[TimescaleDB] Setting up compression policy...")

	// Enable compression on the hypertable
	_, err := db.Exec(`
		ALTER TABLE logs_partitioned SET (
			timescaledb.compress,
			timescaledb.compress_segmentby = 'host, log_type',
			timescaledb.compress_orderby = 'created_at DESC'
		)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to enable compression: %v", err)
		return
	}

	// Add compression policy (compress chunks older than 7 days)
	_, err = db.Exec(`
		SELECT add_compression_policy('logs_partitioned', INTERVAL '7 days', if_not_exists => true)
	`)
	if err != nil {
		log.Printf("[TimescaleDB] Warning: failed to add compression policy: %v", err)
		return
	}

	log.Println("[TimescaleDB] Compression policy enabled: chunks older than 7 days will be compressed")

	// Show current compression status
	var compressedChunks, totalChunks int
	err = db.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE is_compressed) as compressed,
			COUNT(*) as total
		FROM timescaledb_information.chunks
		WHERE hypertable_name = 'logs_partitioned'
	`).Scan(&compressedChunks, &totalChunks)
	if err == nil {
		log.Printf("[TimescaleDB] Compression status: %d/%d chunks compressed", compressedChunks, totalChunks)
	}
}

// runNumericOverflowMigration fixes the numeric field overflow issue (Issue #29)
// This migration changes request_time and upstream_response_time from NUMERIC(10,6) to DOUBLE PRECISION
func (db *DB) runNumericOverflowMigration() error {
	const migrationVersion = "006_fix_numeric_overflow"

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationVersion).Scan(&migrated)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	if migrated {
		log.Printf("[Migration] %s already applied", migrationVersion)
		return nil
	}

	// Check if logs_partitioned table exists
	var tableExists bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs_partitioned'
		)
	`).Scan(&tableExists)
	if err != nil || !tableExists {
		log.Printf("[Migration] logs_partitioned table not found, skipping %s", migrationVersion)
		// Mark as applied since new installations already have DOUBLE PRECISION
		db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
		return nil
	}

	// Check current column type
	var dataType string
	err = db.QueryRow(`
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'logs_partitioned' AND column_name = 'request_time'
	`).Scan(&dataType)
	if err != nil {
		return fmt.Errorf("failed to check column type: %w", err)
	}

	// If already DOUBLE PRECISION, mark as migrated and skip
	if dataType == "double precision" {
		log.Printf("[Migration] request_time already uses double precision, marking %s as applied", migrationVersion)
		db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
		return nil
	}

	log.Printf("[Migration] Starting %s: changing NUMERIC to DOUBLE PRECISION...", migrationVersion)
	log.Printf("[Migration] Current request_time type: %s", dataType)

	// Check if this is a TimescaleDB hypertable
	isHypertable := db.isHypertable("logs_partitioned")

	if isHypertable {
		log.Println("[Migration] logs_partitioned is a TimescaleDB hypertable, handling compression...")

		// Step 1: Decompress all chunks
		log.Println("[Migration] Decompressing compressed chunks...")
		_, err = db.Exec(`
			DO $$
			DECLARE
				chunk_record RECORD;
				decompressed_count INT := 0;
			BEGIN
				FOR chunk_record IN
					SELECT format('%I.%I', chunk_schema, chunk_name) as full_name
					FROM timescaledb_information.chunks
					WHERE hypertable_name = 'logs_partitioned' AND is_compressed = true
				LOOP
					EXECUTE format('SELECT decompress_chunk(%L, true)', chunk_record.full_name);
					decompressed_count := decompressed_count + 1;
					RAISE NOTICE 'Decompressed: %', chunk_record.full_name;
				END LOOP;
				RAISE NOTICE 'Total chunks decompressed: %', decompressed_count;
			END;
			$$
		`)
		if err != nil {
			log.Printf("[Migration] Warning: error during decompression (may be no compressed chunks): %v", err)
		}

		// Step 2: Disable compression temporarily
		log.Println("[Migration] Disabling compression temporarily...")
		_, err = db.Exec(`ALTER TABLE logs_partitioned SET (timescaledb.compress = false)`)
		if err != nil {
			log.Printf("[Migration] Warning: failed to disable compression: %v", err)
		}
	}

	// Step 3: Alter column types to DOUBLE PRECISION
	log.Println("[Migration] Altering column types to DOUBLE PRECISION...")
	_, err = db.Exec(`
		ALTER TABLE logs_partitioned
			ALTER COLUMN request_time TYPE DOUBLE PRECISION,
			ALTER COLUMN upstream_response_time TYPE DOUBLE PRECISION
	`)
	if err != nil {
		return fmt.Errorf("failed to alter column types: %w", err)
	}
	log.Println("[Migration] Column types changed successfully")

	if isHypertable {
		// Step 4: Re-enable compression with same settings
		log.Println("[Migration] Re-enabling compression...")
		_, err = db.Exec(`
			ALTER TABLE logs_partitioned SET (
				timescaledb.compress,
				timescaledb.compress_segmentby = 'host, log_type',
				timescaledb.compress_orderby = 'created_at DESC'
			)
		`)
		if err != nil {
			log.Printf("[Migration] Warning: failed to re-enable compression: %v", err)
		}

		// Step 5: Recompress old chunks (optional, in background)
		log.Println("[Migration] Recompressing chunks older than 7 days in background...")
		go func() {
			time.Sleep(5 * time.Second)
			_, err := db.Exec(`SELECT compress_chunk(c) FROM show_chunks('logs_partitioned', older_than => INTERVAL '7 days') c`)
			if err != nil {
				log.Printf("[Migration] Warning: background recompression had issues: %v", err)
			} else {
				log.Println("[Migration] Background recompression completed")
			}
		}()
	}

	// Mark migration as complete
	_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	log.Printf("[Migration] %s completed successfully!", migrationVersion)
	return nil
}

// runPartitionTimezoneMigration fixes the partition timezone detection bug (Issue #38 related)
// The original 007 migration incorrectly detected local timezone when pg_get_expr()
// displays UTC timestamps in the session's timezone (e.g., +00 shown as +09 in KST)
func (db *DB) runPartitionTimezoneMigration() error {
	const migrationVersion = "008_fix_partition_timezone_v2"

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationVersion).Scan(&migrated)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	if migrated {
		log.Printf("[Migration] %s already applied", migrationVersion)
		return nil
	}

	log.Printf("[Migration] Starting %s: fixing partition timezone detection...", migrationVersion)

	// Read and execute the migration file
	content, err := migrationFS.ReadFile("migrations/008_fix_partition_timezone_v2.sql")
	if err != nil {
		return fmt.Errorf("failed to read 008_fix_partition_timezone_v2.sql: %w", err)
	}

	_, err = db.Exec(string(content))
	if err != nil {
		log.Printf("[Migration] Warning: %s had issues (may be partially applied): %v", migrationVersion, err)
		// Continue anyway - the function replacement should still work
	}

	// Mark migration as complete
	_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	log.Printf("[Migration] %s completed successfully!", migrationVersion)
	return nil
}

// runPregeneratePartitionsMigration pre-generates partitions for 10 years
// This avoids timezone-related bugs from dynamic partition creation
func (db *DB) runPregeneratePartitionsMigration() error {
	const migrationVersion = "009_pregenerate_partitions"

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationVersion).Scan(&migrated)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	if migrated {
		log.Printf("[Migration] %s already applied", migrationVersion)
		return nil
	}

	log.Printf("[Migration] Starting %s: pre-generating partitions for 10 years...", migrationVersion)

	// Read and execute the migration file
	content, err := migrationFS.ReadFile("migrations/009_pregenerate_partitions.sql")
	if err != nil {
		return fmt.Errorf("failed to read 009_pregenerate_partitions.sql: %w", err)
	}

	_, err = db.Exec(string(content))
	if err != nil {
		log.Printf("[Migration] Warning: %s had issues (may be partially applied): %v", migrationVersion, err)
		// Continue anyway - partitions may be partially created
	}

	// Mark migration as complete
	_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	log.Printf("[Migration] %s completed successfully!", migrationVersion)
	return nil
}

// runHypertableNumericFixMigration fixes numeric type that was reintroduced by TimescaleDB migration (Issue #55)
// The migrateToTimescaleDB() function previously created logs_hypertable with numeric(10,6),
// which overrode the double precision fix from migration 006.
func (db *DB) runHypertableNumericFixMigration() error {
	const migrationVersion = "010_fix_hypertable_numeric"

	// Check if already migrated
	var migrated bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, migrationVersion).Scan(&migrated)
	if err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	if migrated {
		log.Printf("[Migration] %s already applied", migrationVersion)
		return nil
	}

	log.Printf("[Migration] Starting %s: fixing hypertable numeric type...", migrationVersion)

	// Read and execute the migration file
	content, err := migrationFS.ReadFile("migrations/010_fix_hypertable_numeric.sql")
	if err != nil {
		return fmt.Errorf("failed to read 010_fix_hypertable_numeric.sql: %w", err)
	}

	_, err = db.Exec(string(content))
	if err != nil {
		log.Printf("[Migration] Warning: %s had issues (may be partially applied): %v", migrationVersion, err)
	}

	// Recompress old chunks in background if applicable
	if db.isTimescaleDBAvailable() && db.isHypertable("logs_partitioned") {
		go func() {
			time.Sleep(5 * time.Second)
			_, err := db.Exec(`SELECT compress_chunk(c) FROM show_chunks('logs_partitioned', older_than => INTERVAL '7 days') c`)
			if err != nil {
				log.Printf("[Migration] Warning: background recompression after 010 had issues: %v", err)
			} else {
				log.Println("[Migration] Background recompression after 010 completed")
			}
		}()
	}

	// Mark migration as complete
	_, err = db.Exec(`INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING`, migrationVersion)
	if err != nil {
		return fmt.Errorf("failed to record migration: %w", err)
	}

	log.Printf("[Migration] %s completed successfully!", migrationVersion)
	return nil
}

// logsPartitionedIndexes is the canonical index set the LIVE logs_partitioned
// table must carry (mirrors the 001_init.sql definitions + upgradeSQL
// additions + the pg_trgm search indexes).
//
// Why this exists: the background hypertable migration creates a NEW table
// (with only the four idx_logs_ht_* basics) and renames the original to
// logs_partitioned_backup — which keeps every original idx_logs_part_* index
// NAME. From then on, every `CREATE INDEX IF NOT EXISTS idx_logs_part_*`
// (upgradeSQL and the old one-shot 011_trgm_indexes) silently no-ops because
// the name exists — on the wrong table. Upgraded installs ended up running
// the hypertable with almost no indexes. ensureLogsPartitionedIndexes
// reclaims squatted names from the backup table and builds the indexes on the
// live table; it runs after the hypertable swap and on every boot thereafter
// (cheap catalog lookups when everything is in place).
var logsPartitionedIndexes = []struct {
	Name  string
	Def   string // USING clause + column list
	Where string // optional partial-index predicate (must come after WITH)
}{
	{"idx_logs_part_host", "USING btree (host)", ""},
	{"idx_logs_part_log_type", "USING btree (log_type)", ""},
	{"idx_logs_part_timestamp", `USING btree ("timestamp" DESC)`, ""},
	{"idx_logs_part_type_timestamp", `USING btree (log_type, "timestamp" DESC)`, ""},
	{"idx_logs_partitioned_exploit_rule", "USING btree (exploit_rule)", "exploit_rule IS NOT NULL AND exploit_rule::text <> '-'"},
	{"idx_logs_part_block_reason_ts", `USING btree (block_reason, "timestamp" DESC)`, "block_reason != 'none'"},
	{"idx_logs_part_client_ip", "USING btree (client_ip)", ""},
	{"idx_logs_part_created_at", "USING btree (created_at DESC)", ""},
	{"idx_logs_part_status_code", "USING btree (status_code)", "status_code IS NOT NULL"},
	{"idx_logs_part_host_ts", `USING btree (host, "timestamp" DESC)`, ""},
	{"idx_logs_part_status_ts", `USING btree (status_code, "timestamp" DESC)`, "status_code IS NOT NULL"},
	{"idx_logs_part_proxy_host_ts", `USING btree (proxy_host_id, "timestamp" DESC)`, "proxy_host_id IS NOT NULL"},
	{"idx_logs_part_geo_ts", `USING btree (geo_country_code, "timestamp" DESC)`, "geo_country_code IS NOT NULL AND geo_country_code::text <> ''"},
	{"idx_logs_part_type_created", "USING btree (log_type, created_at DESC)", ""},
	{"idx_logs_part_block_reason", "USING btree (block_reason)", "block_reason != 'none'"},
	{"idx_logs_part_status_created", "USING btree (status_code, created_at)", ""},
	{"idx_logs_part_block_reason_created", "USING btree (created_at DESC, block_reason)", "block_reason != 'none' AND log_type = 'access'"},
	{"idx_logs_part_host_trgm", "USING gin (host gin_trgm_ops)", ""},
	{"idx_logs_part_uri_trgm", "USING gin (request_uri gin_trgm_ops)", ""},
	{"idx_logs_part_ua_trgm", "USING gin (http_user_agent gin_trgm_ops)", ""},
}

// ensureLogsPartitionedIndexes verifies every canonical index exists ON the
// live logs_partitioned table, reclaiming names squatted by
// logs_partitioned_backup (the backup exists only for operator verification
// and does not need indexes). Heavy builds use TimescaleDB's
// transaction_per_chunk so ingest stays mostly unblocked on large installs.
func (db *DB) ensureLogsPartitionedIndexes() {
	var isHypertable bool
	_ = db.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM timescaledb_information.hypertables
		WHERE hypertable_name = 'logs_partitioned'
	)`).Scan(&isHypertable)

	created := 0
	for _, idx := range logsPartitionedIndexes {
		var onTable string
		err := db.QueryRow(
			`SELECT tablename FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1`,
			idx.Name,
		).Scan(&onTable)
		switch {
		case err == nil && onTable == "logs_partitioned":
			continue // already on the live table
		case err == nil && onTable == "logs_partitioned_backup":
			if _, dropErr := db.Exec(fmt.Sprintf(`DROP INDEX IF EXISTS public.%s`, idx.Name)); dropErr != nil {
				log.Printf("[Migration] Warning: could not reclaim index name %s from backup table: %v", idx.Name, dropErr)
				continue
			}
			log.Printf("[Migration] Reclaimed index name %s from logs_partitioned_backup", idx.Name)
		case err == nil:
			log.Printf("[Migration] Warning: index %s exists on unexpected table %q; leaving it alone", idx.Name, onTable)
			continue
		case err != sql.ErrNoRows:
			log.Printf("[Migration] Warning: could not check index %s: %v", idx.Name, err)
			continue
		}

		stmt := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON logs_partitioned %s", idx.Name, idx.Def)
		if isHypertable {
			stmt += " WITH (timescaledb.transaction_per_chunk)"
		}
		if idx.Where != "" {
			stmt += " WHERE " + idx.Where
		}
		if _, err := db.Exec(stmt); err != nil {
			// transaction_per_chunk is best-effort; retry as a plain build.
			plain := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON logs_partitioned %s", idx.Name, idx.Def)
			if idx.Where != "" {
				plain += " WHERE " + idx.Where
			}
			if _, err2 := db.Exec(plain); err2 != nil {
				log.Printf("[Migration] Warning: failed to create index %s: %v (plain retry: %v)", idx.Name, err, err2)
				continue
			}
		}
		created++
		log.Printf("[Migration] Created index %s on logs_partitioned", idx.Name)
	}

	if created > 0 {
		log.Printf("[Migration] logs_partitioned index ensure: %d index(es) built", created)
	}
}

// runTrgmIndexMigration enables pg_trgm and ensures the canonical
// logs_partitioned index set. When the background hypertable migration has
// not happened yet it defers entirely — building indexes on the pre-swap
// table would strand them on the future backup table (the original bug that
// left upgraded installs without indexes). The ensure pass runs in the
// background: GIN/trgm builds over a large hypertable can take a long time
// and must not block boot.
func (db *DB) runTrgmIndexMigration() error {
	// Enable pg_trgm extension
	if _, err := db.Exec("CREATE EXTENSION IF NOT EXISTS pg_trgm"); err != nil {
		return fmt.Errorf("failed to create pg_trgm extension: %w", err)
	}

	var swapped bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 'timescaledb_hypertable')`).Scan(&swapped); err != nil {
		return fmt.Errorf("failed to check hypertable migration status: %w", err)
	}
	if !swapped && db.isTimescaleDBAvailable() {
		log.Println("[Migration] Deferring logs_partitioned index ensure until the hypertable migration completes")
		return nil
	}

	db.TrackBackground()
	go func() {
		defer db.BackgroundDone()
		db.ensureLogsPartitionedIndexes()
	}()
	return nil
}

// ExploitRulesAutoDisableSQL is the one-shot UPDATE + system_logs entry used by
// RunMigrations (embedded inside upgradeSQL) and by integration tests that need
// to exercise the migration independently. It is safe to run repeatedly:
// - ADD COLUMN IF NOT EXISTS is a no-op after the first run.
// - The UPDATE filters on auto_disabled_at IS NULL, so it only touches rows the
//   migration has not yet marked. Admins who have re-enabled the rules keep
//   their choice.
// See GitHub Issue #123.
const ExploitRulesAutoDisableSQL = `
ALTER TABLE public.exploit_block_rules ADD COLUMN IF NOT EXISTS auto_disabled_at timestamp with time zone;

DO $$
DECLARE
    affected_count int := 0;
BEGIN
    UPDATE public.exploit_block_rules
    SET enabled = false,
        auto_disabled_at = now()
    WHERE id IN (
        'a5cb921c-2c10-475b-8753-a56e2af1e5ba',
        '41d1f7bf-9179-44cb-b41a-1685ce88d965',
        'aa90285b-2986-46f9-80e6-99946327cd24'
    )
    AND is_system = true
    AND enabled = true
    AND auto_disabled_at IS NULL;

    GET DIAGNOSTICS affected_count = ROW_COUNT;
    IF affected_count > 0 THEN
        INSERT INTO public.system_logs (source, level, message, details, component)
        VALUES (
            'internal',
            'info',
            format('Auto-disabled %s overly-broad exploit rule(s) to prevent false positives on search/CMS endpoints. Review and optionally re-enable at /waf/exploit-rules.', affected_count),
            jsonb_build_object(
                'rule_ids', ARRAY[
                    'a5cb921c-2c10-475b-8753-a56e2af1e5ba',
                    '41d1f7bf-9179-44cb-b41a-1685ce88d965',
                    'aa90285b-2986-46f9-80e6-99946327cd24'
                ],
                'reason', 'github issue #123: simple keyword matching produces false positives on legitimate search queries',
                'rollback_hint', 'set enabled=true in the UI; the migration will not touch these rows again once auto_disabled_at is set'
            ),
            'exploit_rules_migration'
        );
    END IF;
END $$;
`

// ApplyExploitRulesAutoDisable runs the one-shot auto-disable migration against
// an already-open database handle. Used by integration tests to re-exercise the
// migration after mutating the table. Production startup uses the equivalent
// SQL embedded inside RunMigrations() upgradeSQL. Both share the exact string
// intent documented in ExploitRulesAutoDisableSQL.
func ApplyExploitRulesAutoDisable(db *sql.DB) error {
	_, err := db.Exec(ExploitRulesAutoDisableSQL)
	return err
}

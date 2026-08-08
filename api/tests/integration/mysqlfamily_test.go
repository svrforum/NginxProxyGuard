package integration

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/database/dialect"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// 이 테스트들은 실제 MySQL 계열 서버가 필요하다. NPG_MYSQL_TEST_DSN을 빈
// 데이터베이스로 지정하면 MariaDB든 MySQL이든 떠 있는 쪽에 대해 실행된다.
// 설정하지 않으면 건너뛰므로 기본 스위트는 외부 의존 없이 돈다. 같은 테스트가
// 양쪽에서 모두 통과해야 하며, 두 번 돌리는 이유가 바로 그것이다.
//
//	docker run -d --name npg-mariadb-test -e MARIADB_ROOT_PASSWORD=root \
//	    -e MARIADB_DATABASE=npg -p 33061:3306 mariadb:11.4
//	NPG_MYSQL_TEST_DSN='mariadb://root:root@127.0.0.1:33061/npg' \
//	    go test ./tests/integration/ -run MySQLFamily -v
//
//	docker run -d --name npg-mysql-test -e MYSQL_ROOT_PASSWORD=root \
//	    -e MYSQL_DATABASE=npg -p 33071:3306 mysql:8.4
//	NPG_MYSQL_TEST_DSN='mysql://root:root@127.0.0.1:33071/npg' \
//	    go test ./tests/integration/ -run MySQLFamily -v
func mysqlFamilyDSN(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"NPG_MYSQL_TEST_DSN", "NPG_MARIADB_TEST_DSN"} {
		if dsn := os.Getenv(name); dsn != "" {
			return dsn
		}
	}
	t.Skip("NPG_MYSQL_TEST_DSN is not set; skipping the MySQL-family integration tests")
	return ""
}

func openMySQLFamily(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(mysqlFamilyDSN(t))
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// URL 스킴은 드라이버만 골랐다. dialect는 서버 자신의 버전 문자열에서
	// 나와야 한다. 그래야 MariaDB를 가리키는 mysql:// URL도(반대도) 올바르게
	// 동작한다.
	if got := db.Kind(); !got.IsMySQLFamily() {
		t.Fatalf("dialect detected as %q, want mariadb or mysql", got)
	}
	t.Logf("server detected as %s", db.Kind())
	return db
}

func TestMySQLFamilyMigrationsApplyCleanly(t *testing.T) {
	db := openMySQLFamily(t)

	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if count, last := db.MigrationHealth(); count > 0 {
		t.Fatalf("%d migration statement(s) failed; last: %s", count, last)
	}

	// 재실행은 no-op이어야 한다. 업그레이드 전체가 부팅할 때마다 재실행되므로,
	// 멱등하지 않은 문장이 하나라도 있으면 재시작마다 깨진다.
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations (second run): %v", err)
	}
	if count, last := db.MigrationHealth(); count > 0 {
		t.Fatalf("re-run: %d migration statement(s) failed; last: %s", count, last)
	}
}

func TestMySQLFamilySchemaShape(t *testing.T) {
	db := openMySQLFamily(t)
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	t.Run("tables the application depends on exist", func(t *testing.T) {
		for _, table := range []string{
			"users", "roles", "role_permissions", "proxy_hosts", "certificates",
			"logs_partitioned", "logs_unified", "dashboard_stats_hourly",
			"exploit_block_rules", "notification_channels", "notification_outbox",
			"sso_providers", "user_identities", "ddns_records", "global_settings",
			"system_settings", "banned_ips", "access_lists", "filter_subscriptions",
		} {
			var n int
			err := db.QueryRow(`
				SELECT COUNT(*) FROM information_schema.tables
				WHERE table_schema = DATABASE() AND table_name = ?`, table).Scan(&n)
			if err != nil {
				t.Fatalf("%s: %v", table, err)
			}
			if n == 0 {
				t.Errorf("table %q is missing", table)
			}
		}
	})

	t.Run("logs are partitioned by month", func(t *testing.T) {
		var partitions int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM information_schema.partitions
			WHERE table_schema = DATABASE() AND table_name = 'logs_partitioned'
			  AND partition_name IS NOT NULL`).Scan(&partitions)
		if err != nil {
			t.Fatal(err)
		}
		if partitions < 2 {
			t.Errorf("logs_partitioned has %d partitions, want the monthly set", partitions)
		}
	})

	t.Run("exploit rules are seeded", func(t *testing.T) {
		var rules int
		if err := db.QueryRow(`SELECT COUNT(*) FROM exploit_block_rules`).Scan(&rules); err != nil {
			t.Fatal(err)
		}
		// 기본 규칙 22개에 나중 업그레이드가 채워 넣는 dotenv 규칙 하나.
		if rules < 23 {
			t.Errorf("exploit_block_rules has %d rows, want the full default set", rules)
		}
	})

	t.Run("ddns_records carries the upgrade column", func(t *testing.T) {
		var n int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema = DATABASE() AND table_name = 'ddns_records'
			  AND column_name = 'proxy_host_id'`).Scan(&n)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Error("ddns_records.proxy_host_id is missing")
		}
	})
}

// TestMySQLFamilyTranslatedQueries는 리포지토리가 가장 많이 쓰는 SQL 형태들을
// 번역 드라이버를 통해 실제 서버로 보낸다. 각 문장은 리포지토리가 쓰는 그대로의
// PostgreSQL 문장이다.
func TestMySQLFamilyTranslatedQueries(t *testing.T) {
	db := openMySQLFamily(t)
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()

	t.Run("insert with RETURNING", func(t *testing.T) {
		var id string
		err := db.QueryRowContext(ctx, `
			INSERT INTO access_lists (name, description, satisfy_any)
			VALUES ($1, $2, $3) RETURNING id`,
			"translated-"+time.Now().Format("150405.000000"), "from the integration test", true,
		).Scan(&id)
		if err != nil {
			t.Fatalf("INSERT ... RETURNING: %v", err)
		}
		if id == "" {
			t.Fatal("RETURNING produced an empty id")
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx, `DELETE FROM access_lists WHERE id = $1`, id)
		})

		t.Run("reused placeholder", func(t *testing.T) {
			var n int
			err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM access_lists WHERE id = $1 OR name = $2 OR id = $1`,
				id, "nothing-matches-this").Scan(&n)
			if err != nil {
				t.Fatalf("reused placeholder: %v", err)
			}
			if n != 1 {
				t.Errorf("got %d rows, want 1", n)
			}
		})

		t.Run("ILIKE is case-insensitive", func(t *testing.T) {
			var n int
			err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM access_lists WHERE id = $1 AND description ILIKE $2`,
				id, "%FROM THE INTEGRATION TEST%").Scan(&n)
			if err != nil {
				t.Fatalf("ILIKE: %v", err)
			}
			if n != 1 {
				t.Errorf("ILIKE matched %d rows, want 1", n)
			}
		})

		t.Run("= is case-sensitive, as on PostgreSQL", func(t *testing.T) {
			var n int
			err := db.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM access_lists WHERE id = $1 AND description = $2`,
				id, "FROM THE INTEGRATION TEST").Scan(&n)
			if err != nil {
				t.Fatalf("equality: %v", err)
			}
			if n != 0 {
				t.Errorf("case-insensitive equality leaked: matched %d rows, want 0", n)
			}
		})
	})

	t.Run("aggregate FILTER", func(t *testing.T) {
		var total, blocked int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*), COUNT(*) FILTER (WHERE block_reason != 'none')
			FROM logs_partitioned WHERE created_at > NOW() - INTERVAL '24 hours'`,
		).Scan(&total, &blocked)
		if err != nil {
			t.Fatalf("COUNT(*) FILTER: %v", err)
		}
		if blocked > total {
			t.Errorf("filtered count %d exceeds total %d", blocked, total)
		}
	})

	t.Run("upsert", func(t *testing.T) {
		name := "upsert-" + time.Now().Format("150405.000000")
		insert := `
			INSERT INTO access_lists (id, name, description)
			VALUES ($1, $2, $3)
			ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description`
		id := "11111111-2222-3333-4444-" + time.Now().Format("150405000000")

		if _, err := db.ExecContext(ctx, insert, id, name, "first"); err != nil {
			t.Fatalf("upsert insert: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx, `DELETE FROM access_lists WHERE id = $1`, id)
		})
		if _, err := db.ExecContext(ctx, insert, id, name, "second"); err != nil {
			t.Fatalf("upsert update: %v", err)
		}

		var description string
		if err := db.QueryRowContext(ctx,
			`SELECT description FROM access_lists WHERE id = $1`, id).Scan(&description); err != nil {
			t.Fatal(err)
		}
		if description != "second" {
			t.Errorf("description = %q, want %q", description, "second")
		}
	})

	t.Run("unique violations are classified", func(t *testing.T) {
		name := "dup-" + time.Now().Format("150405.000000")
		if _, err := db.ExecContext(ctx,
			`INSERT INTO roles (name, description) VALUES ($1, $2)`, name, "first"); err != nil {
			t.Skipf("roles insert unavailable: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx, `DELETE FROM roles WHERE name = $1`, name)
		})

		_, err := db.ExecContext(ctx,
			`INSERT INTO roles (name, description) VALUES ($1, $2)`, name, "second")
		if err == nil {
			t.Fatal("expected a unique violation on the second insert")
		}
		if !dialect.IsUniqueViolation(err) {
			t.Errorf("IsUniqueViolation(%v) = false, want true", err)
		}
	})

	t.Run("timestamps round-trip in UTC", func(t *testing.T) {
		// DATETIME에는 시간대가 없다. 드라이버가 UTC로 고정돼 있으므로 여기서
		// 쓴 Go 시각은 같은 시점으로 돌아와야 한다.
		want := time.Date(2026, 3, 14, 15, 9, 26, 535000000, time.UTC)
		var got time.Time
		if err := db.QueryRowContext(ctx, `SELECT CAST($1 AS DATETIME(6))`, want).Scan(&got); err != nil {
			t.Fatalf("timestamp round-trip: %v", err)
		}
		if !got.UTC().Equal(want) {
			t.Errorf("got %s, want %s", got.UTC(), want)
		}
	})

	t.Run("transactions are translated too", func(t *testing.T) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()

		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM proxy_hosts WHERE enabled = $1`, true).Scan(&n); err != nil {
			t.Fatalf("query inside a transaction: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("prepared statements are translated too", func(t *testing.T) {
		stmt, err := db.PrepareContext(ctx,
			`SELECT COUNT(*) FROM exploit_block_rules WHERE category = $1 AND enabled = $2`)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		defer stmt.Close()

		var n int
		if err := stmt.QueryRowContext(ctx, "scanner", true).Scan(&n); err != nil {
			t.Fatalf("execute prepared: %v", err)
		}
		if n == 0 {
			t.Error("expected at least one enabled scanner rule")
		}
	})

	t.Run("null handling matches", func(t *testing.T) {
		var got sql.NullString
		if err := db.QueryRowContext(ctx,
			`SELECT NULLIF($1, '')`, "").Scan(&got); err != nil {
			t.Fatalf("NULLIF: %v", err)
		}
		if got.Valid {
			t.Errorf("NULLIF('', '') returned %q, want NULL", got.String)
		}
	})
}

// TestMySQLFamilyReturningIsEmulated는 서버가 직접 표현할 수 없는 문장 형태를
// 다룬다. MySQL에서는 모든 RETURNING 형태가, MariaDB에서도 UPDATE와 업서트
// 형태가 여기 해당한다. 번역기가 이들을 쓰기와 재조회로 나누고, 드라이버가 그
// 둘을 한 트랜잭션 안에서 실행한다.
func TestMySQLFamilyReturningIsEmulated(t *testing.T) {
	db := openMySQLFamily(t)
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()

	t.Run("UPDATE ... RETURNING", func(t *testing.T) {
		var id string
		err := db.QueryRowContext(ctx,
			`INSERT INTO access_lists (name, description) VALUES ($1, $2) RETURNING id`,
			"upd-"+time.Now().Format("150405.000000"), "before").Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.ExecContext(ctx, `DELETE FROM access_lists WHERE id = $1`, id) })

		var gotID, gotName, gotDescription string
		err = db.QueryRowContext(ctx, `
			UPDATE access_lists SET description = $1, updated_at = now()
			WHERE id = $2
			RETURNING id, name, description`, "after", id).Scan(&gotID, &gotName, &gotDescription)
		if err != nil {
			t.Fatalf("UPDATE ... RETURNING: %v", err)
		}
		if gotID != id {
			t.Errorf("returned id = %q, want %q", gotID, id)
		}
		if gotDescription != "after" {
			t.Errorf("returned description = %q, want the post-update value %q", gotDescription, "after")
		}
	})

	t.Run("UPDATE ... RETURNING matching no rows", func(t *testing.T) {
		// 쓰기 쪽이 아무 행도 건드리지 않으므로, 재조회는 PostgreSQL의
		// RETURNING과 똑같이 sql.ErrNoRows를 내야 한다.
		var id string
		err := db.QueryRowContext(ctx,
			`UPDATE access_lists SET description = $1 WHERE id = $2 RETURNING id`,
			"unreachable", "00000000-0000-0000-0000-000000000000").Scan(&id)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("got %v, want sql.ErrNoRows", err)
		}
	})

	t.Run("upsert ... RETURNING", func(t *testing.T) {
		hostID := createProxyHost(t, db, "returning-upsert")

		upsert := `
			INSERT INTO rate_limits (proxy_host_id, enabled, requests_per_second, burst_size)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (proxy_host_id) DO UPDATE
			   SET enabled = EXCLUDED.enabled, burst_size = EXCLUDED.burst_size
			RETURNING id, proxy_host_id, enabled, burst_size`

		var id, gotHost string
		var enabled bool
		var burst int
		if err := db.QueryRowContext(ctx, upsert, hostID, true, 10, 20).
			Scan(&id, &gotHost, &enabled, &burst); err != nil {
			t.Fatalf("insert path: %v", err)
		}
		if gotHost != hostID || !enabled || burst != 20 {
			t.Fatalf("insert path returned (%s, %v, %d)", gotHost, enabled, burst)
		}

		var secondID string
		if err := db.QueryRowContext(ctx, upsert, hostID, false, 10, 99).
			Scan(&secondID, &gotHost, &enabled, &burst); err != nil {
			t.Fatalf("update path: %v", err)
		}
		if secondID != id {
			t.Errorf("upsert created a second row: %q then %q", id, secondID)
		}
		if enabled || burst != 99 {
			t.Errorf("update path returned stale values (%v, %d)", enabled, burst)
		}
	})
}

// TestMySQLFamilyArrayColumns는 TEXT 안에 담긴 text[] 표현을 확인한다. Go에서는
// lib/pq의 배열 코덱이 그대로 왕복하고, SQL에서는 dialect 분기 술어가 그 안의
// 값을 찾아낸다.
func TestMySQLFamilyArrayColumns(t *testing.T) {
	db := openMySQLFamily(t)
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()

	suffix := time.Now().Format("150405.000000")
	domains := []string{"alpha-" + suffix + ".example", "beta-" + suffix + ".example"}

	var id string
	err := db.QueryRowContext(ctx, `
		INSERT INTO proxy_hosts (domain_names, forward_scheme, forward_host, forward_port, enabled)
		VALUES ($1, 'http', '127.0.0.1', 8080, true) RETURNING id`,
		pq.Array(domains)).Scan(&id)
	if err != nil {
		t.Fatalf("insert with an array column: %v", err)
	}
	t.Cleanup(func() { db.ExecContext(ctx, `DELETE FROM proxy_hosts WHERE id = $1`, id) })

	t.Run("round-trips through lib/pq", func(t *testing.T) {
		var got pq.StringArray
		if err := db.QueryRowContext(ctx,
			`SELECT domain_names FROM proxy_hosts WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if len(got) != len(domains) || got[0] != domains[0] || got[1] != domains[1] {
			t.Errorf("got %v, want %v", got, domains)
		}
	})

	t.Run("membership predicate finds whole elements only", func(t *testing.T) {
		var found string
		err := db.QueryRowContext(ctx,
			`SELECT id FROM proxy_hosts WHERE domain_names LIKE CONCAT('%"', $1, '"%')`,
			domains[1]).Scan(&found)
		if err != nil {
			t.Fatalf("membership lookup: %v", err)
		}
		if found != id {
			t.Errorf("found %q, want %q", found, id)
		}

		// 저장된 원소의 앞부분만 일치하는 값은 매칭되면 안 된다.
		var any string
		err = db.QueryRowContext(ctx,
			`SELECT id FROM proxy_hosts WHERE domain_names LIKE CONCAT('%"', $1, '"%')`,
			"alpha-"+suffix).Scan(&any)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("a partial element matched: %v", err)
		}
	})
}

// TestMySQLFamilyLogIngestion은 로그 수집기가 쓰는 배치 쓰기 경로를 실행한다.
func TestMySQLFamilyLogIngestion(t *testing.T) {
	db := openMySQLFamily(t)
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()

	repo := repository.NewLogRepository(db)
	host := "ingest-" + time.Now().Format("150405.000000") + ".example"

	batch := make([]model.CreateLogRequest, 0, 25)
	for i := 0; i < 25; i++ {
		batch = append(batch, model.CreateLogRequest{
			LogType:       model.LogTypeAccess,
			Timestamp:     time.Now().UTC(),
			Host:          host,
			ClientIP:      "203.0.113.7",
			RequestMethod: "GET",
			RequestURI:    "/batch",
			StatusCode:    200,
			BodyBytesSent: int64(1024 + i),
			RequestTime:   0.125,
		})
	}
	if err := repo.CreateBatch(ctx, batch); err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	t.Cleanup(func() { db.ExecContext(ctx, `DELETE FROM logs_partitioned WHERE host = $1`, host) })

	var stored int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM logs_partitioned WHERE host = $1`, host).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != len(batch) {
		t.Errorf("stored %d rows, want %d", stored, len(batch))
	}

	t.Run("empty strings become NULL, as on PostgreSQL", func(t *testing.T) {
		var nullReferers int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM logs_partitioned WHERE host = $1 AND http_referer IS NULL`,
			host).Scan(&nullReferers); err != nil {
			t.Fatal(err)
		}
		if nullReferers != len(batch) {
			t.Errorf("%d rows have a NULL referer, want %d", nullReferers, len(batch))
		}
	})

	t.Run("readable through logs_unified", func(t *testing.T) {
		var viaView int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM logs_unified WHERE host = $1`, host).Scan(&viaView); err != nil {
			t.Fatalf("logs_unified: %v", err)
		}
		if viaView != len(batch) {
			t.Errorf("logs_unified shows %d rows, want %d", viaView, len(batch))
		}
	})
}

// createProxyHost는 최소한의 활성 호스트를 삽입하고 그 id를 돌려준다.
func createProxyHost(t *testing.T, db *database.DB, label string) string {
	t.Helper()
	var id string
	err := db.QueryRow(`
		INSERT INTO proxy_hosts (domain_names, forward_scheme, forward_host, forward_port, enabled)
		VALUES ($1, 'http', '127.0.0.1', 8080, true) RETURNING id`,
		pq.Array([]string{label + "-" + time.Now().Format("150405.000000") + ".example"}),
	).Scan(&id)
	if err != nil {
		t.Fatalf("failed to create a proxy host: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM proxy_hosts WHERE id = $1`, id) })
	return id
}

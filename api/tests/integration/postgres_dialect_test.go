package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/database/dialect"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// MySQL 계열 지원을 추가하면서 공유 리포지토리 코드를 손봐야 했다. `= ANY($1)`,
// 파라미터화된 interval 캐스트, UPDATE ... RETURNING을 쓰던 질의들을 두 엔진이
// 모두 받아주는 형태로 바꿨다. 이 파일은 바로 그 경로들을 PostgreSQL에서 다시
// 실행한다. MySQL 계열을 위한 변경이 거의 모든 설치가 실제로 돌리는 백엔드를
// 조용히 망가뜨리지 못하게 하기 위해서다.
//
// NPG_POSTGRES_TEST_DSN을 빈 데이터베이스로 지정하면 실행되고, 설정하지 않으면
// 건너뛴다.
//
//	docker run -d --name npg-pg-test -e POSTGRES_PASSWORD=postgres \
//	    -e POSTGRES_DB=npg -p 55432:5432 timescale/timescaledb:latest-pg17 \
//	    -c shared_preload_libraries=timescaledb
//	NPG_POSTGRES_TEST_DSN='postgres://postgres:postgres@127.0.0.1:55432/npg?sslmode=disable' \
//	    go test ./tests/integration/ -run PostgresSharedPaths -v
func TestPostgresSharedPaths(t *testing.T) {
	dsn := os.Getenv("NPG_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("NPG_POSTGRES_TEST_DSN is not set; skipping the PostgreSQL regression tests")
	}

	db, err := database.New(dsn)
	if err != nil {
		t.Fatalf("failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	if got := db.Kind(); got != dialect.Postgres {
		t.Fatalf("dialect detected as %q, want %q", got, dialect.Postgres)
	}
	if err := db.RunMigrations(); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	// 업그레이드 실패는 설계상 경고 후 계속 진행이며, 일부는 사용 중인
	// TimescaleDB 빌드에 따라 달라진다. 그래서 여기서는 치명적 실패가 아니라
	// 보고만 한다.
	if n, last := db.MigrationHealth(); n > 0 {
		t.Logf("note: %d upgrade statement(s) failed on this server: %s", n, last)
	}

	ctx := context.Background()

	t.Run("IN list in place of = ANY", func(t *testing.T) {
		rl := repository.NewRateLimitRepository(db.DB)
		if _, err := rl.GetActiveBannedIPSet(ctx, []string{"192.0.2.1", "192.0.2.2"}); err != nil {
			t.Errorf("GetActiveBannedIPSet: %v", err)
		}
		if _, err := rl.GetBannedIPsByIDs(ctx, []string{"00000000-0000-0000-0000-000000000000"}); err != nil {
			t.Errorf("GetBannedIPsByIDs: %v", err)
		}
	})

	t.Run("parameterised interval retention", func(t *testing.T) {
		if _, err := db.ExecContext(ctx,
			`DELETE FROM audit_logs WHERE created_at < NOW() - ($1 || ' days')::INTERVAL`, 3650); err != nil {
			t.Errorf("interval retention: %v", err)
		}
	})

	t.Run("array membership predicate", func(t *testing.T) {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM proxy_hosts WHERE $1 = ANY(domain_names)`,
			"absent.example").Scan(&n); err != nil {
			t.Errorf("array membership: %v", err)
		}
	})

	t.Run("certificate recovery selects before it updates", func(t *testing.T) {
		if _, _, err := repository.NewCertificateRepository(db).RecoverInterruptedStates(ctx); err != nil {
			t.Errorf("RecoverInterruptedStates: %v", err)
		}
	})

	t.Run("domain existence check", func(t *testing.T) {
		if _, err := repository.NewProxyHostRepository(db).
			CheckDomainExists(ctx, []string{"a.example", "b.example"}, ""); err != nil {
			t.Errorf("CheckDomainExists: %v", err)
		}
	})

	t.Run("COPY batch log insert", func(t *testing.T) {
		host := "pgpaths-" + time.Now().Format("150405.000000") + ".example"
		logs := make([]model.CreateLogRequest, 0, 5)
		for i := 0; i < 5; i++ {
			logs = append(logs, model.CreateLogRequest{
				LogType: model.LogTypeAccess, Timestamp: time.Now().UTC(),
				Host: host, ClientIP: "203.0.113.9", RequestMethod: "GET",
				RequestURI: "/x", StatusCode: 200,
			})
		}
		if err := repository.NewLogRepository(db).CreateBatch(ctx, logs); err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		t.Cleanup(func() { db.ExecContext(ctx, `DELETE FROM logs_partitioned WHERE host = $1`, host) })

		var stored int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM logs_partitioned WHERE host = $1`, host).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != len(logs) {
			t.Errorf("stored %d rows, want %d", stored, len(logs))
		}
	})

	t.Run("array columns round-trip", func(t *testing.T) {
		domains := []string{"pgarray-" + time.Now().Format("150405.000000") + ".example"}
		var id string
		err := db.QueryRowContext(ctx, `
			INSERT INTO proxy_hosts (domain_names, forward_scheme, forward_host, forward_port, enabled)
			VALUES ($1, 'http', '127.0.0.1', 8080, true) RETURNING id`,
			pq.Array(domains)).Scan(&id)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		t.Cleanup(func() { db.ExecContext(ctx, `DELETE FROM proxy_hosts WHERE id = $1`, id) })

		var got pq.StringArray
		if err := db.QueryRowContext(ctx,
			`SELECT domain_names FROM proxy_hosts WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != domains[0] {
			t.Errorf("got %v, want %v", got, domains)
		}
	})
}

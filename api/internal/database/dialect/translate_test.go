package dialect

import (
	"strings"
	"testing"
)

// normalise는 공백을 접어서, 테스트가 재작성기가 우연히 내놓은 정확한 띄어쓰기가
// 아니라 SQL의 형태를 검증하게 한다.
func normalise(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func mustTranslate(t *testing.T, in string) (string, []int) {
	t.Helper()
	got, err := Translate(in)
	if err != nil {
		t.Fatalf("Translate(%q) returned error: %v", in, err)
	}
	if got.FollowUp != nil {
		t.Fatalf("Translate(%q) produced an unexpected follow-up statement", in)
	}
	return normalise(got.SQL), got.ArgOrder
}

// mustSplit은 쓰기와 재조회로 나뉠 것으로 기대되는 문장을 번역하고 두 쪽을 모두
// 돌려준다.
func mustSplit(t *testing.T, in string) (write, read string, writeOrder, readOrder []int) {
	t.Helper()
	got, err := Translate(in)
	if err != nil {
		t.Fatalf("Translate(%q) returned error: %v", in, err)
	}
	if got.FollowUp == nil {
		t.Fatalf("Translate(%q) did not produce a follow-up statement", in)
	}
	return normalise(got.SQL), normalise(got.FollowUp.SQL), got.ArgOrder, got.FollowUp.ArgOrder
}

func TestTranslatePlaceholders(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		want  string
		order []int
	}{
		{
			name:  "sequential",
			in:    `SELECT * FROM users WHERE id = $1 AND name = $2`,
			want:  `SELECT * FROM users WHERE id = ? AND name = ?`,
			order: []int{0, 1},
		},
		{
			// argOrder가 존재하는 이유 그 자체. MySQL은 위치로 바인딩하므로
			// 재사용된 Postgres 플레이스홀더는 두 번 넘겨야 한다.
			name:  "reused placeholder is duplicated",
			in:    `SELECT * FROM t WHERE a = $1 OR b = $1 OR c = $2`,
			want:  `SELECT * FROM t WHERE a = ? OR b = ? OR c = ?`,
			order: []int{0, 0, 1},
		},
		{
			name:  "out of order",
			in:    `UPDATE t SET a = $2, b = $1 WHERE id = $3`,
			want:  `UPDATE t SET a = ?, b = ? WHERE id = ?`,
			order: []int{1, 0, 2},
		},
		{
			name:  "placeholder inside a string literal is left alone",
			in:    `SELECT '$1 is not a placeholder' , $1`,
			want:  `SELECT '$1 is not a placeholder' , ?`,
			order: []int{0},
		},
		{
			name:  "placeholder inside a comment is left alone",
			in:    "SELECT a -- $9 in a comment\n, $1 FROM t",
			want:  `SELECT a -- $9 in a comment , ? FROM t`,
			order: []int{0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, order := mustTranslate(t, tc.in)
			if got != tc.want {
				t.Errorf("sql:\n got %q\nwant %q", got, tc.want)
			}
			if len(order) != len(tc.order) {
				t.Fatalf("argOrder: got %v want %v", order, tc.order)
			}
			for i := range order {
				if order[i] != tc.order[i] {
					t.Fatalf("argOrder: got %v want %v", order, tc.order)
				}
			}
		})
	}
}

func TestTranslateNoPlaceholdersReturnsNilOrder(t *testing.T) {
	got, err := Translate(`SELECT count(*) FROM users`)
	if err != nil {
		t.Fatal(err)
	}
	if got.ArgOrder != nil {
		t.Fatalf("expected nil ArgOrder for a parameterless query, got %v", got.ArgOrder)
	}
}

func TestTranslateExpressions(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			"casts are dropped",
			`SELECT id::text, config::jsonb, ip::inet FROM t WHERE u = $1::uuid`,
			`SELECT id, config, ip FROM t WHERE u = ?`,
		},
		{
			"two-word cast types are consumed whole",
			`SELECT NULLIF($1::double precision, 0), $2::character varying`,
			`SELECT NULLIF(?, 0), ?`,
		},
		{
			// ::date를 제거하면 시각 부분이 남아 모든 행이 제각각의 GROUP BY
			// 버킷으로 흩어진다.
			"date cast becomes DATE()",
			`SELECT created_at::date, count(*) FROM logs GROUP BY created_at::date`,
			`SELECT DATE(created_at), count(*) FROM logs GROUP BY DATE(created_at)`,
		},
		{
			"ILIKE becomes a case-insensitively collated LIKE",
			`SELECT * FROM t WHERE host ILIKE $1`,
			`SELECT * FROM t WHERE host LIKE ? COLLATE utf8mb4_general_ci`,
		},
		{
			"ILIKE over a concatenation covers the whole operand",
			`SELECT * FROM t WHERE host ILIKE '%' || $1 || '%'`,
			`SELECT * FROM t WHERE host LIKE '%' || ? || '%' COLLATE utf8mb4_general_ci`,
		},
		{
			"interval literals become interval expressions",
			`SELECT * FROM logs WHERE created_at > NOW() - INTERVAL '24 hours'`,
			`SELECT * FROM logs WHERE created_at > NOW(6) - INTERVAL 24 HOUR`,
		},
		{
			"singular interval unit",
			`SELECT NOW() + INTERVAL '7 days', NOW() - INTERVAL '35 seconds'`,
			`SELECT NOW(6) + INTERVAL 7 DAY, NOW(6) - INTERVAL 35 SECOND`,
		},
		{
			"uuid generation is renamed",
			`INSERT INTO t (id) VALUES (gen_random_uuid())`,
			`INSERT INTO t (id) VALUES (UUID())`,
		},
		{
			"now keeps microsecond precision",
			`UPDATE t SET updated_at = now() WHERE id = $1`,
			`UPDATE t SET updated_at = NOW(6) WHERE id = ?`,
		},
		{
			"bare CURRENT_TIMESTAMP keeps microsecond precision",
			`SELECT CURRENT_TIMESTAMP`,
			`SELECT CURRENT_TIMESTAMP(6)`,
		},
		{
			"date_trunc becomes a formatted cast",
			`SELECT date_trunc('hour', created_at) FROM logs`,
			`SELECT CAST(DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00') AS DATETIME) FROM logs`,
		},
		{
			"epoch extraction becomes UNIX_TIMESTAMP",
			`SELECT EXTRACT(EPOCH FROM created_at) FROM t`,
			`SELECT UNIX_TIMESTAMP(created_at) FROM t`,
		},
		{
			// 이 코드베이스가 쓰는 유일한 파라미터화된 interval 형태. 수량은
			// 바인딩된 채로 두고 단위만 SQL로 끌어올린다.
			"concatenated interval becomes INTERVAL n UNIT",
			`DELETE FROM audit_logs WHERE created_at < NOW() - ($1 || ' days')::INTERVAL`,
			`DELETE FROM audit_logs WHERE created_at < NOW(6) - INTERVAL ? DAY`,
		},
		{
			"FOR UPDATE loses the table qualifier but keeps SKIP LOCKED",
			`SELECT * FROM outbox o FOR UPDATE OF o SKIP LOCKED`,
			`SELECT * FROM outbox o FOR UPDATE SKIP LOCKED`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := mustTranslate(t, tc.in)
			if got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTranslateAggregateFilter(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			"COUNT(*) FILTER counts a constant",
			`SELECT COUNT(*) FILTER (WHERE block_reason = 'waf') FROM logs`,
			`SELECT COUNT(CASE WHEN (block_reason = 'waf') THEN 1 END) FROM logs`,
		},
		{
			"aggregate argument is preserved",
			`SELECT AVG(captcha_score) FILTER (WHERE captcha_score IS NOT NULL) FROM c`,
			`SELECT AVG(CASE WHEN (captcha_score IS NOT NULL) THEN captcha_score END) FROM c`,
		},
		{
			"nested inside COALESCE",
			`SELECT COALESCE(AVG(solve_time) FILTER (WHERE solve_time IS NOT NULL), 0) FROM c`,
			`SELECT COALESCE(AVG(CASE WHEN (solve_time IS NOT NULL) THEN solve_time END), 0) FROM c`,
		},
		{
			"several filters in one select list",
			`SELECT COUNT(*) FILTER (WHERE a), COUNT(*) FILTER (WHERE b) FROM t`,
			`SELECT COUNT(CASE WHEN (a) THEN 1 END), COUNT(CASE WHEN (b) THEN 1 END) FROM t`,
		},
		{
			"condition containing a placeholder keeps its argument slot",
			`SELECT COUNT(*) FILTER (WHERE status = $1) FROM t WHERE id = $2`,
			`SELECT COUNT(CASE WHEN (status = ?) THEN 1 END) FROM t WHERE id = ?`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := mustTranslate(t, tc.in)
			if got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTranslateFilterKeepsArgumentOrder(t *testing.T) {
	// FILTER 재작성은 토큰을 옮긴다. 조건 안의 플레이스홀더는 방출 순서대로
	// 호출자의 인자에 계속 대응돼야 한다.
	_, order := mustTranslate(t, `SELECT COUNT(*) FILTER (WHERE status = $2) FROM t WHERE id = $1`)
	if len(order) != 2 || order[0] != 1 || order[1] != 0 {
		t.Fatalf("argOrder: got %v want [1 0]", order)
	}
}

func TestTranslateUpsert(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			// INSERT IGNORE가 아니라 아무 일도 하지 않는 자기 대입. IGNORE는
			// 외래 키 위반과 잘림 오류까지 삼킨다.
			"DO NOTHING uses the conflict target column",
			`INSERT INTO t (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
			`INSERT INTO t (id, name) VALUES (?, ?) ON DUPLICATE KEY UPDATE id = id`,
		},
		{
			"DO NOTHING without a target falls back to the first inserted column",
			`INSERT INTO t (slug, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			`INSERT INTO t (slug, name) VALUES (?, ?) ON DUPLICATE KEY UPDATE slug = slug`,
		},
		{
			"DO UPDATE maps EXCLUDED onto VALUES()",
			`INSERT INTO t (id, a, b) VALUES ($1, $2, $3)
			 ON CONFLICT (id) DO UPDATE SET a = EXCLUDED.a, b = EXCLUDED.b`,
			`INSERT INTO t (id, a, b) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE a = VALUES(a), b = VALUES(b)`,
		},
		{
			"composite conflict target",
			`INSERT INTO t (a, b, c) VALUES ($1, $2, $3) ON CONFLICT (a, b) DO UPDATE SET c = EXCLUDED.c`,
			`INSERT INTO t (a, b, c) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE c = VALUES(c)`,
		},
		{
			"non-EXCLUDED assignments survive",
			`INSERT INTO t (id, n) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET n = t.n + 1, updated_at = now()`,
			`INSERT INTO t (id, n) VALUES (?, ?) ON DUPLICATE KEY UPDATE n = t.n + 1, updated_at = NOW(6)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := mustTranslate(t, tc.in)
			if got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTranslateStringLiterals(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			// Postgres는 평범한 문자열에서 \를 문자 그대로 다루지만 MySQL
			// 계열은 이스케이프로 다루므로 두 배로 늘려야 한다.
			"backslashes in plain literals are doubled",
			`SELECT '\d+' AS pattern`,
			`SELECT '\\d+' AS pattern`,
		},
		{
			// E''는 이미 "백슬래시는 이스케이프"라는 뜻이고 이는 MySQL 계열의
			// 기본 해석과 같으므로 본문이 그대로 통과한다.
			"E-prefixed literals lose the prefix and keep their escapes",
			`SELECT E'\\.env' AS pattern`,
			`SELECT '\\.env' AS pattern`,
		},
		{
			"doubled quotes are untouched",
			`SELECT 'it''s fine'`,
			`SELECT 'it''s fine'`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := mustTranslate(t, tc.in)
			if got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTranslateQuotedIdentifiersSurvive(t *testing.T) {
	// 로그 테이블에는 이름이 말 그대로 "timestamp"인 컬럼이 있다. 커넥션에
	// ANSI_QUOTES가 켜져 있으므로 큰따옴표가 계속 유효하다.
	got, _ := mustTranslate(t, `SELECT "timestamp", host FROM logs_partitioned WHERE "timestamp" > $1`)
	want := `SELECT "timestamp", host FROM logs_partitioned WHERE "timestamp" > ?`
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
}

func TestTranslateRejectsUntranslatable(t *testing.T) {
	tests := []struct{ name, in, wantSubstring string }{
		{"array containment", `SELECT * FROM c WHERE events @> ARRAY[$1]::text[]`, "containment"},
		{"any over array", `SELECT * FROM t WHERE slug = ANY($1)`, "ANY"},
		{"array_length", `SELECT array_length(ip_ranges, 1) FROM p`, "array_length"},
		{"json arrow", `SELECT payload->'fields'->>'subject' FROM n`, "json operator"},
		{"jsonb_set", `UPDATE n SET config = jsonb_set(config, '{a}', $1)`, "jsonb_set"},
		{"update returning whose predicate is updated", `UPDATE t SET status = $1 WHERE status = 'pending' RETURNING id`, "cannot be re-selected"},
		{"update returning without a predicate", `UPDATE t SET a = $1 RETURNING id`, "without a WHERE"},
		{"conditional upsert", `INSERT INTO t (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET a = 1 WHERE t.b = 2`, "conditional upsert"},
		{"interval cast from an opaque value", `SELECT NOW() - $1::interval`, "interval"},
		{"plpgsql block", `DO $$ BEGIN NULL; END $$`, "PostgreSQL-only"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Translate(tc.in)
			if err == nil {
				t.Fatalf("expected an error for %q", tc.in)
			}
			if !strings.Contains(err.Error(), tc.wantSubstring) {
				t.Errorf("error %q does not mention %q", err, tc.wantSubstring)
			}
		})
	}
}

func TestTranslateAllowsSupportedReturning(t *testing.T) {
	// MariaDB는 INSERT와 DELETE에 RETURNING을 지원하며, 이 프로젝트가 쓰는
	// 지점이 바로 그곳이다.
	for _, q := range []string{
		`INSERT INTO t (a) VALUES ($1) RETURNING id`,
		`DELETE FROM t WHERE id = $1 RETURNING id`,
	} {
		if _, err := Translate(q); err != nil {
			t.Errorf("Translate(%q): unexpected error %v", q, err)
		}
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		url  string
		want Kind
	}{
		{"postgres://u:p@db:5432/npg?sslmode=disable", Postgres},
		{"postgresql://u:p@db:5432/npg", Postgres},
		{"mysql://u:p@db:3306/npg", MariaDB},
		{"mariadb://u:p@db:3306/npg", MariaDB},
		{"MariaDB://u:p@db/npg", MariaDB},
		{"u:p@tcp(db:3306)/npg", MariaDB},
		{"", Postgres},
		{"nonsense", Postgres},
	}
	for _, tc := range tests {
		if got := Detect(tc.url); got != tc.want {
			t.Errorf("Detect(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestMySQLDSN(t *testing.T) {
	dsn, err := MySQLDSN("mariadb://npg:secret@db/nginx_proxy_guard", false)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(dsn, "npg:secret@tcp(db:3306)/nginx_proxy_guard?") {
		t.Errorf("unexpected DSN prefix: %s", dsn)
	}
	for _, required := range []string{
		"parseTime=true",
		"loc=UTC",
		"clientFoundRows=true",
		"collation=utf8mb4_bin",
		"ANSI_QUOTES",
		"PIPES_AS_CONCAT",
	} {
		if !strings.Contains(dsn, strings.ReplaceAll(required, ",", "%2C")) && !strings.Contains(dsn, required) {
			t.Errorf("DSN is missing %q: %s", required, dsn)
		}
	}
	if strings.Contains(dsn, "multiStatements") {
		t.Errorf("serving DSN must not allow multi-statement queries: %s", dsn)
	}

	migration, err := MySQLDSN("mariadb://npg:secret@db/nginx_proxy_guard", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(migration, "multiStatements=true") {
		t.Errorf("migration DSN must allow multi-statement execution: %s", migration)
	}
}

func TestMySQLDSNPreservesExplicitPortAndParams(t *testing.T) {
	dsn, err := MySQLDSN("mysql://u:p@10.0.0.5:3307/npg?tls=skip-verify", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dsn, "u:p@tcp(10.0.0.5:3307)/npg?") {
		t.Errorf("unexpected DSN: %s", dsn)
	}
	if !strings.Contains(dsn, "tls=skip-verify") {
		t.Errorf("operator-supplied parameter was dropped: %s", dsn)
	}
}

func TestMySQLDSNRejectsIncomplete(t *testing.T) {
	for _, url := range []string{
		"mariadb://user@/npg",
		"mariadb://user@db/",
	} {
		if _, err := MySQLDSN(url, false); err == nil {
			t.Errorf("expected an error for %q", url)
		}
	}
}

func TestRedactHidesPassword(t *testing.T) {
	got := Redact("mariadb://npg:supersecret@db:3306/npg")
	if strings.Contains(got, "supersecret") {
		t.Fatalf("password leaked: %s", got)
	}
	if !strings.Contains(got, "npg") {
		t.Fatalf("redaction removed too much: %s", got)
	}
}

func TestTranslateSplitsUpdateReturning(t *testing.T) {
	// MariaDB에는 UPDATE ... RETURNING이 없으므로, 문장은 쓰기와 같은 술어를 쓰는
	// 재조회로 나뉜다. 드라이버가 이 쌍을 한 트랜잭션에서 실행한다.
	write, read, writeOrder, readOrder := mustSplit(t,
		`UPDATE proxy_hosts SET enabled = $1, updated_at = now() WHERE id = $2 RETURNING id, domain_names, enabled`)

	if want := `UPDATE proxy_hosts SET enabled = ?, updated_at = NOW(6) WHERE id = ?`; write != want {
		t.Errorf("write:\n got %q\nwant %q", write, want)
	}
	if want := `SELECT id, domain_names, enabled FROM proxy_hosts WHERE id = ?`; read != want {
		t.Errorf("read:\n got %q\nwant %q", read, want)
	}
	if len(writeOrder) != 2 || writeOrder[0] != 0 || writeOrder[1] != 1 {
		t.Errorf("write argOrder = %v, want [0 1]", writeOrder)
	}
	if len(readOrder) != 1 || readOrder[0] != 1 {
		t.Errorf("read argOrder = %v, want [1]", readOrder)
	}
}

func TestTranslateSplitsUpsertReturning(t *testing.T) {
	// RETURNING과 ON DUPLICATE KEY UPDATE도 함께 쓸 수 없다. 재조회는 충돌
	// 대상에 넣은 값을 키로 삼는데, 업서트가 삽입했든 갱신했든 그 값이 쓰인 행을
	// 특정해 준다.
	write, read, _, readOrder := mustSplit(t,
		`INSERT INTO rate_limits (proxy_host_id, enabled, burst_size)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (proxy_host_id) DO UPDATE SET enabled = EXCLUDED.enabled
		 RETURNING id, proxy_host_id, enabled`)

	wantWrite := `INSERT INTO rate_limits (proxy_host_id, enabled, burst_size) VALUES (?, ?, ?) ` +
		`ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)`
	if write != wantWrite {
		t.Errorf("write:\n got %q\nwant %q", write, wantWrite)
	}
	if want := `SELECT id, proxy_host_id, enabled FROM rate_limits WHERE proxy_host_id = ?`; read != want {
		t.Errorf("read:\n got %q\nwant %q", read, want)
	}
	if len(readOrder) != 1 || readOrder[0] != 0 {
		t.Errorf("read argOrder = %v, want [0]", readOrder)
	}
}

func TestTranslateUpsertWithPartialIndexPredicate(t *testing.T) {
	// `ON CONFLICT (col) WHERE ...`는 부분 유니크 인덱스를 지정한다. 대상 엔진은
	// 위반된 유니크 키가 무엇이든 그것에 반응하고, 스키마가 그 인덱스들을 진짜
	// 유니크 키로 재현하므로 술어는 버린다.
	got, _ := mustTranslate(t,
		`INSERT INTO banned_ips (ip_address, reason) VALUES ($1, $2)
		 ON CONFLICT (ip_address) WHERE proxy_host_id IS NULL DO UPDATE SET reason = EXCLUDED.reason`)
	want := `INSERT INTO banned_ips (ip_address, reason) VALUES (?, ?) ON DUPLICATE KEY UPDATE reason = VALUES(reason)`
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
}

func TestMySQLDSNTranslatesPostgresParameters(t *testing.T) {
	// 잘 돌아가던 PostgreSQL URL을 복사해 스킴만 바꾸는 것이 MySQL 계열을 시험해
	// 보는 가장 자연스러운 방법이다. go-sql-driver는 알 수 없는 파라미터를
	// `SET <name>=<value>`로 재생하므로, sslmode가 남아 있으면
	// "Unknown system variable 'sslmode'"로 접속이 실패한다. 진짜 원인은 전혀
	// 알려주지 않는 오류다.
	tests := []struct {
		name         string
		url          string
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:         "sslmode=disable becomes tls=false",
			url:          "mariadb://u:p@db/npg?sslmode=disable",
			wantContains: []string{"tls=false"},
			wantAbsent:   []string{"sslmode"},
		},
		{
			name:         "verifying sslmode becomes tls=true",
			url:          "mariadb://u:p@db/npg?sslmode=verify-full",
			wantContains: []string{"tls=true"},
			wantAbsent:   []string{"sslmode"},
		},
		{
			name:         "an explicit tls parameter wins over sslmode",
			url:          "mariadb://u:p@db/npg?sslmode=disable&tls=skip-verify",
			wantContains: []string{"tls=skip-verify"},
			wantAbsent:   []string{"sslmode", "tls=false"},
		},
		{
			name:         "connect_timeout is renamed and given a unit",
			url:          "mariadb://u:p@db/npg?connect_timeout=10",
			wantContains: []string{"timeout=10s"},
			wantAbsent:   []string{"connect_timeout"},
		},
		{
			name:       "other libpq parameters are dropped",
			url:        "mariadb://u:p@db/npg?search_path=public&application_name=npg&sslrootcert=/ca.pem",
			wantAbsent: []string{"search_path", "application_name", "sslrootcert"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dsn, err := MySQLDSN(tc.url, false)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(dsn, want) {
					t.Errorf("DSN is missing %q: %s", want, dsn)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(dsn, absent) {
					t.Errorf("DSN still carries %q: %s", absent, dsn)
				}
			}
		})
	}
}

func TestTranslateLeavesIndexPrefixesAlone(t *testing.T) {
	// `host`는 로그 테이블의 컬럼이면서 PostgreSQL의 inet 함수이기도 하다.
	// DDL에서 `host(191)`은 접두사 길이다. 진짜 인자를 받는 호출만 재작성한다.
	got, _ := mustTranslate(t,
		`CREATE INDEX idx_logs_created_host ON logs (created_at DESC, host(191))`)
	want := `CREATE INDEX idx_logs_created_host ON logs (created_at DESC, host(191))`
	if got != want {
		t.Errorf("\n got %q\nwant %q", got, want)
	}
}

func TestTranslateInetAndTextFunctions(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{
			// PostgreSQL은 넷마스크를 뺀 inet을 만들지만, 대상 엔진의 컬럼은
			// 이미 뗄 것이 없는 평범한 VARCHAR다.
			"host() unwraps to its argument",
			`SELECT * FROM logs WHERE host(client_ip) LIKE $1`,
			`SELECT * FROM logs WHERE client_ip LIKE ?`,
		},
		{
			"split_part on the first field becomes SUBSTRING_INDEX",
			`SELECT split_part(request_uri, '?', 1) AS path FROM logs`,
			`SELECT SUBSTRING_INDEX(request_uri, '?', 1) AS path FROM logs`,
		},
		{
			"current_database becomes DATABASE",
			`SELECT current_database()`,
			`SELECT DATABASE()`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := mustTranslate(t, tc.in)
			if got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestTranslateRejectsAmbiguousSplitPart(t *testing.T) {
	// 첫 필드를 넘어가면 두 함수의 동작이 갈린다. PostgreSQL은 n번째 필드를,
	// MySQL 계열은 앞의 n개를 이어 붙여 돌려준다.
	if _, err := Translate(`SELECT split_part(a, ',', 2) FROM t`); err == nil {
		t.Fatal("expected split_part with n>1 to be rejected")
	}
}

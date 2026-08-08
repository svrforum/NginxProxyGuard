package dialect

import (
	"strings"
	"testing"
)

// withFlavor는 주어진 서버 플레이버로 fn을 실행하고 이전 값을 되돌린다. 재작성
// 규칙이 프로세스 전역 active dialect를 읽으므로, 플레이버는 인자로 넘기는 게
// 아니라 설정해야 한다.
func withFlavor(t *testing.T, k Kind, fn func()) {
	t.Helper()
	previous := Active()
	SetActive(k)
	defer SetActive(previous)
	fn()
}

func TestMySQLStripsUnsupportedIfExists(t *testing.T) {
	// MySQL은 이 스키마가 IF NOT EXISTS를 쓰는 자리 중 CREATE TABLE에서만
	// 받아준다. 절을 제거하면 재실행 시 중복 객체 오류가 나는데, 마이그레이션
	// 러너가 그것을 성공으로 인식한다. IsAlreadyApplied 참고.
	tests := []struct{ name, in, want string }{
		{
			"CREATE INDEX loses the clause",
			`CREATE INDEX IF NOT EXISTS idx_a ON t (a)`,
			`CREATE INDEX idx_a ON t (a)`,
		},
		{
			"ADD COLUMN loses the clause",
			`ALTER TABLE t ADD COLUMN IF NOT EXISTS c INT DEFAULT 0`,
			`ALTER TABLE t ADD COLUMN c INT DEFAULT 0`,
		},
		{
			"FOREIGN KEY loses the clause",
			`ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY IF NOT EXISTS (a) REFERENCES u(id) ON DELETE CASCADE`,
			`ALTER TABLE t ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES u(id) ON DELETE CASCADE`,
		},
		{
			"DROP INDEX loses the clause",
			`ALTER TABLE t DROP INDEX IF EXISTS idx_a`,
			`ALTER TABLE t DROP INDEX idx_a`,
		},
		{
			"CREATE TABLE keeps it",
			`CREATE TABLE IF NOT EXISTS t (a INT)`,
			`CREATE TABLE IF NOT EXISTS t (a INT)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withFlavor(t, MySQL, func() {
				got, _ := mustTranslate(t, tc.in)
				if got != tc.want {
					t.Errorf("\n got %q\nwant %q", got, tc.want)
				}
			})
			withFlavor(t, MariaDB, func() {
				// MariaDB는 전부 지원한다. 아무것도 바뀌면 안 된다.
				got, _ := mustTranslate(t, tc.in)
				if got != normalise(tc.in) {
					t.Errorf("MariaDB statement was altered:\n got %q\nwant %q", got, normalise(tc.in))
				}
			})
		})
	}
}

func TestMySQLCompressionSyntax(t *testing.T) {
	in := `CREATE TABLE IF NOT EXISTS logs (a TEXT) ENGINE=InnoDB PAGE_COMPRESSED=1 PAGE_COMPRESSION_LEVEL=1`

	withFlavor(t, MySQL, func() {
		got, _ := mustTranslate(t, in)
		want := `CREATE TABLE IF NOT EXISTS logs (a TEXT) ENGINE=InnoDB COMPRESSION='zlib'`
		if got != want {
			t.Errorf("\n got %q\nwant %q", got, want)
		}
	})
	withFlavor(t, MariaDB, func() {
		got, _ := mustTranslate(t, in)
		if !strings.Contains(got, "PAGE_COMPRESSED=1") {
			t.Errorf("MariaDB lost its own compression attributes: %s", got)
		}
	})
}

func TestMySQLEmulatesInsertReturning(t *testing.T) {
	// MySQL에는 RETURNING이 아예 없다. 행의 키를 드라이버가 만들어 명시적으로
	// 삽입하는 것이 그 행을 다시 찾는 유일한 방법이다.
	withFlavor(t, MySQL, func() {
		write, read, writeOrder, readOrder := mustSplit(t,
			`INSERT INTO access_lists (name, description) VALUES ($1, $2) RETURNING id, name`)

		wantWrite := `INSERT INTO access_lists (name, description, id) VALUES (?, ?, ?)`
		if write != wantWrite {
			t.Errorf("write:\n got %q\nwant %q", write, wantWrite)
		}
		if want := `SELECT id, name FROM access_lists WHERE id = ?`; read != want {
			t.Errorf("read:\n got %q\nwant %q", read, want)
		}

		// 쓰기의 세 번째 슬롯과 읽기의 유일한 슬롯을 드라이버가 같은 생성 값으로
		// 채운다.
		if len(writeOrder) != 3 || writeOrder[2] != ArgSynthesisedUUID {
			t.Errorf("write argOrder = %v, want the third slot synthesised", writeOrder)
		}
		if len(readOrder) != 1 || readOrder[0] != ArgSynthesisedUUID {
			t.Errorf("read argOrder = %v, want a synthesised slot", readOrder)
		}
	})

	// MariaDB는 INSERT ... RETURNING을 지원하므로 건드리면 안 된다.
	withFlavor(t, MariaDB, func() {
		got, err := Translate(`INSERT INTO access_lists (name) VALUES ($1) RETURNING id`)
		if err != nil {
			t.Fatal(err)
		}
		if got.FollowUp != nil {
			t.Error("MariaDB should run INSERT ... RETURNING natively")
		}
	})
}

func TestMySQLInsertReturningKeepsACallerSuppliedKey(t *testing.T) {
	// 호출자가 이미 키를 준 경우에는 합성할 것이 없다. 재조회는 호출자가
	// 바인딩한 값을 키로 쓴다.
	withFlavor(t, MySQL, func() {
		write, read, _, readOrder := mustSplit(t,
			`INSERT INTO access_lists (id, name) VALUES ($1, $2) RETURNING id, name`)

		if want := `INSERT INTO access_lists (id, name) VALUES (?, ?)`; write != want {
			t.Errorf("write:\n got %q\nwant %q", write, want)
		}
		if want := `SELECT id, name FROM access_lists WHERE id = ?`; read != want {
			t.Errorf("read:\n got %q\nwant %q", read, want)
		}
		if len(readOrder) != 1 || readOrder[0] != 0 {
			t.Errorf("read argOrder = %v, want [0]", readOrder)
		}
	})
}

func TestMySQLEmulatesDeleteReturning(t *testing.T) {
	// UPDATE와 달리 나중에 다시 조회할 것이 없으므로, SELECT를 먼저 실행하고
	// 드라이버가 그 행들을 들고 있어야 한다.
	withFlavor(t, MySQL, func() {
		got, err := Translate(`DELETE FROM sso_login_states WHERE state = $1 RETURNING provider_id, nonce`)
		if err != nil {
			t.Fatal(err)
		}
		if got.FollowUp == nil {
			t.Fatal("expected DELETE ... RETURNING to be split")
		}
		if !got.FollowUpFirst {
			t.Error("the SELECT must run before the DELETE")
		}
		if want := `DELETE FROM sso_login_states WHERE state = ?`; normalise(got.SQL) != want {
			t.Errorf("write:\n got %q\nwant %q", normalise(got.SQL), want)
		}
		if want := `SELECT provider_id, nonce FROM sso_login_states WHERE state = ?`; normalise(got.FollowUp.SQL) != want {
			t.Errorf("read:\n got %q\nwant %q", normalise(got.FollowUp.SQL), want)
		}
	})

	withFlavor(t, MariaDB, func() {
		got, err := Translate(`DELETE FROM t WHERE a = $1 RETURNING id`)
		if err != nil {
			t.Fatal(err)
		}
		if got.FollowUp != nil {
			t.Error("MariaDB should run DELETE ... RETURNING natively")
		}
	})
}

func TestMySQLRefusesUnboundedDeleteReturning(t *testing.T) {
	withFlavor(t, MySQL, func() {
		if _, err := Translate(`DELETE FROM t RETURNING id`); err == nil {
			t.Fatal("expected a DELETE ... RETURNING with no WHERE to be refused")
		}
	})
}

func TestDetectFlavorReadsTheServerVersion(t *testing.T) {
	// URL 스킴은 선언이 아니라 습관이다. MariaDB를 가리키는 mysql:// URL도
	// 여전히 MariaDB로 다뤄져야 한다.
	if got := Detect("mysql://u:p@db/npg"); got != MariaDB {
		t.Errorf("Detect chose %q; the scheme should only select the driver", got)
	}
	if !MySQL.IsMySQLFamily() || !MariaDB.IsMySQLFamily() || Postgres.IsMySQLFamily() {
		t.Error("IsMySQLFamily misclassifies a backend")
	}
}

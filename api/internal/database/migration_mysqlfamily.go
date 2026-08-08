package database

import (
	"embed"
	"fmt"
	"log"
	"strings"

	"nginx-proxy-guard/internal/database/dialect"
)

//go:embed migrations/mariadb/*.sql
var mariadbMigrationFS embed.FS

// MySQL 계열 엔진용 마이그레이션 파일들. 적용 순서대로다.
//
// migrations/mariadb/ 아래에 있는 이유는 그 방언으로 쓰였기 때문이다. MySQL도
// 똑같은 파일을 실행하며, MySQL이 거부하는 소수의 구문만 번역기가 실행 도중
// 재작성한다.
//
//   - 001_init.sql은 신규 설치 시 한 번만 실행되며, scripts/pg2mariadb-schema.py가
//     PostgreSQL 스키마에서 생성한다.
//   - 002_upgrades.sql은 migration.go의 업그레이드 목록에서 생성되고, 그것과
//     마찬가지로 부팅할 때마다 재실행된다. 기존 설치가 현재 바이너리가 기대하는
//     상태를 따라잡게 하기 위해서다.
//   - 003_mariadb.sql은 손으로 작성한 파일로, 두 생성기 모두 유도할 수 없는
//     것들을 담는다. 역시 부팅할 때마다 재실행된다.
const (
	mariadbInitFile     = "migrations/mariadb/001_init.sql"
	mariadbUpgradesFile = "migrations/mariadb/002_upgrades.sql"
	mariadbSupplement   = "migrations/mariadb/003_mariadb.sql"
)

// runMySQLFamilyMigrations는 MariaDB나 MySQL 데이터베이스를 이 바이너리가
// 기대하는 스키마 상태로 만든다.
//
// 둘 다 같은 파일 세 개를 실행한다. MySQL은 생성된 스키마가 쓰는 편의 문법 몇
// 가지 — 인덱스, 컬럼, 외래 키의 IF NOT EXISTS — 를 거부하므로 번역기가 내보낼
// 때 제거하고, 그 결과로 나오는 중복 객체 오류를 여기서 "이미 적용됨"으로
// 인식한다(dialect.IsAlreadyApplied 참고). 겉으로 드러나는 동작은 동일하다.
//
// PostgreSQL 경로의 계약을 그대로 따른다. 기본 스키마는 한 번만 적용하고
// 기록하며, 이후 업그레이드 문장은 부팅할 때마다 각자의 Exec으로 재실행해서
// 하나가 실패해도 나머지를 건너뛰지 않게 한다. 실패는 기동을 중단시키는 대신
// 로그로 남기고 MigrationHealth()에 기록한다. 부분적으로만 마이그레이션된
// 스키마는 개별 기능을 저하시킬 뿐이지만, 부팅을 거부하면 프록시 전체가
// 내려간다.
func (db *DB) runMySQLFamilyMigrations() error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(255) NOT NULL PRIMARY KEY,
			applied_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
	`); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	var applied int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM schema_migrations WHERE version = '001_init'`,
	).Scan(&applied); err != nil {
		return fmt.Errorf("failed to check migration status: %w", err)
	}

	if applied == 0 {
		log.Printf("[Migration] Running the initial %s schema (001_init.sql)...", db.kind)
		// 기본 스키마는 온전히 적용돼야 한다. 절반만 만들어진 테이블 집합은
		// 업그레이드 재실행으로 고칠 수 있는 것이 아니다.
		if err := db.execMigrationFile(mariadbInitFile, false); err != nil {
			return fmt.Errorf("failed to apply the %s schema: %w", db.kind, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES ('001_init')`); err != nil {
			return fmt.Errorf("failed to update migration version: %w", err)
		}
		log.Printf("[Migration] Initial %s schema applied", db.kind)
	} else {
		log.Println("[Migration] Schema already initialized, running upgrades only...")
	}

	for _, file := range []string{mariadbUpgradesFile, mariadbSupplement} {
		if err := db.execMigrationFile(file, true); err != nil {
			return err
		}
	}

	if count, lastErr := db.MigrationHealth(); count > 0 {
		log.Printf("[Migration] ERROR: %d upgrade statement(s) failed — schema may be partially migrated and affected features can return errors until a restart retries them. Last failure: %s", count, lastErr)
	}

	if err := db.applyExploitRulesAutoDisable(); err != nil {
		log.Printf("Warning: exploit rules auto-disable migration failed: %v", err)
	}

	// PostgreSQL 경로와 달리 의도적으로 빠진 것들: TimescaleDB 전환,
	// 하이퍼테이블과 청크 복구, pg_trgm 인덱스 생성, 레거시 logs ->
	// logs_partitioned 백필. 전부 PostgreSQL 설치에만 있을 수 있는 과거를
	// 고치는 작업이다. 이쪽 설치는 처음부터 파티션 테이블로 시작하고, 파티션
	// 관리는 마이그레이션이 아니라 파티션 스케줄러가 맡는다.

	log.Println("Schema migration completed")
	return nil
}

// overlyBroadExploitRuleIDs는 키워드 패턴이 평범한 검색어와 CMS 질의 문자열에도
// 걸리는 시스템 규칙 세 개다. Issue #123에서 기본 비활성으로 바꿨다. 자세한
// 이유는 ExploitRulesAutoDisableSQL 참고.
var overlyBroadExploitRuleIDs = []string{
	"a5cb921c-2c10-475b-8753-a56e2af1e5ba", // SQL Commands
	"41d1f7bf-9179-44cb-b41a-1685ce88d965", // SQL Keywords
	"aa90285b-2986-46f9-80e6-99946327cd24", // XSS Special Characters
}

// applyExploitRulesAutoDisable은 ExploitRulesAutoDisableSQL의 MySQL 계열
// 대응물이다.
//
// PostgreSQL 버전이 PL/pgSQL DO 블록인 이유는 감사 로그를 남길지 ROW_COUNT로
// 분기해야 하기 때문이다. MariaDB에도 MySQL에도 저장 루틴 밖에서는 그런 수단이
// 없으므로 분기를 Go에 둔다. 문장 두 개, 가드, 멱등성은 모두 같다. UPDATE는
// auto_disabled_at이 NULL인 행만 건드리므로, 규칙을 다시 켠 관리자의 선택은
// 유지되고 반복 부팅은 no-op이 된다.
func (db *DB) applyExploitRulesAutoDisable() error {
	result, err := db.Exec(`
		UPDATE exploit_block_rules
		SET enabled = false, auto_disabled_at = NOW(6)
		WHERE id IN (?, ?, ?)
		  AND is_system = true
		  AND enabled = true
		  AND auto_disabled_at IS NULL`,
		overlyBroadExploitRuleIDs[0], overlyBroadExploitRuleIDs[1], overlyBroadExploitRuleIDs[2],
	)
	if err != nil {
		return fmt.Errorf("failed to auto-disable overly-broad exploit rules: %w", err)
	}

	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return nil
	}

	details := fmt.Sprintf(
		`{"rule_ids": ["%s"], "reason": %q, "rollback_hint": %q}`,
		strings.Join(overlyBroadExploitRuleIDs, `", "`),
		"github issue #123: simple keyword matching produces false positives on legitimate search queries",
		"set enabled=true in the UI; the migration will not touch these rows again once auto_disabled_at is set",
	)
	message := fmt.Sprintf(
		"Auto-disabled %d overly-broad exploit rule(s) to prevent false positives on search/CMS endpoints. Review and optionally re-enable at /waf/exploit-rules.",
		affected)

	if _, err := db.Exec(`
		INSERT INTO system_logs (source, level, message, details, component)
		VALUES ('internal', 'info', ?, ?, 'exploit_rules_migration')`,
		message, details,
	); err != nil {
		return fmt.Errorf("failed to record the auto-disable audit entry: %w", err)
	}
	return nil
}

// execMigrationFile은 내장된 마이그레이션 파일 하나를 문장 단위로 적용한다.
//
// 통째로 보내지 않고 Go에서 문장을 나누는 이유는 셋이다. 드라이버의 번역기가 한
// 번에 한 문장씩만 다루고, 서비스용 커넥션은 다중 문장 질의를 켜두지 않으며,
// 문장 단위 실행이라야 하나가 실패해도 배치 전체를 중단하지 않고 넘어갈 수
// 있다.
//
// tolerate가 설정되면 실패한 문장은 로그와 기록만 남기고 나머지는 계속
// 실행된다. v2.13.4 이후 PostgreSQL 업그레이드 루프가 지켜 온 계약이다.
func (db *DB) execMigrationFile(name string, tolerate bool) error {
	content, err := mariadbMigrationFS.ReadFile(name)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", name, err)
	}

	statements := dialect.SplitStatements(string(content))
	log.Printf("[Migration] %s: %d statements", name, len(statements))

	applied, alreadyThere := 0, 0
	for _, stmt := range statements {
		_, err := db.Exec(stmt)
		if err == nil {
			applied++
			continue
		}
		// MySQL에서는 번역기가 서버가 거부하는 IF NOT EXISTS 절을 제거하므로,
		// 마이그레이션을 다시 실행하면 아무 일도 하지 않는 대신 객체가
		// 중복이라고 알려 온다. 결과는 같으며 실패가 아니다.
		if dialect.IsAlreadyApplied(err) {
			alreadyThere++
			continue
		}
		if !tolerate {
			return fmt.Errorf("%s: %w\nstatement: %s", name, err, truncateStatement(stmt))
		}
		desc := fmt.Sprintf("%s: %s", name, truncateStatement(stmt))
		log.Printf("Warning: upgrade %q failed: %v", desc, err)
		db.RecordMigrationFailure(desc, err)
	}

	if alreadyThere > 0 {
		log.Printf("[Migration] %s: %d applied, %d already in place", name, applied, alreadyThere)
	}
	return nil
}

// truncateStatement는 마이그레이션 로그를 읽을 만하게 유지한다. 시드 INSERT는
// 수 킬로바이트에 이르는데 그 뒷부분은 실패에 대해 알려주는 게 없다.
func truncateStatement(stmt string) string {
	stmt = strings.Join(strings.Fields(stmt), " ")
	if len(stmt) > 160 {
		return stmt[:160] + "..."
	}
	return stmt
}

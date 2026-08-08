package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// MySQL 계열 파티션 관리.
//
// PostgreSQL 경로는 두 가지 형태를 다뤄야 한다. 청크를 알아서 관리해 주는
// TimescaleDB 하이퍼테이블과, CREATE TABLE ... PARTITION OF로 만드는 네이티브
// 선언적 파티션이다. MySQL 계열에는 둘 다 없다. 파티션은 테이블 정의의 일부이며
// ALTER TABLE로 추가하고 제거한다.
//
// 여기 설계 전체를 좌우하는 사정이 하나 있다. 스키마 끝에는 어떤 범위에도
// 속하지 않는 행이 거부되지 않도록 `p_max VALUES LESS THAN (MAXVALUE)`라는
// 포괄 파티션이 있다. RANGE 파티션 목록은 순서를 지켜야 하므로 p_max 뒤에는
// 아무것도 덧붙일 수 없다. 다음 달 파티션은 REORGANIZE PARTITION으로 그 안에서
// 떼어내야 한다.

// partitionedTables는 파티션 테이블과 그 파티션 키를 짝지어 둔 것이다.
var partitionedTables = []struct {
	table  string
	column string
}{
	{"logs_partitioned", "created_at"},
	{"dashboard_stats_hourly_partitioned", "hour_bucket"},
}

// maxPartitionName은 모든 파티션 테이블 끝에 있는 포괄 파티션이며, 새 달을
// 떼어내는 대상이기도 하다.
const maxPartitionName = "p_max"

// createPartitionsMariaDB는 각 파티션 테이블에 이번 달과 앞으로 몇 달치 파티션이
// 있는지 확인하고 없으면 만든다.
func (s *PartitionScheduler) createPartitionsMariaDB(ctx context.Context) {
	const monthsAhead = 3

	for _, pt := range partitionedTables {
		existing, err := s.existingPartitions(ctx, pt.table)
		if err != nil {
			log.Printf("[PartitionScheduler] Failed to read partitions of %s: %v", pt.table, err)
			continue
		}
		if len(existing) == 0 {
			// 파티션 테이블이 아니거나 아예 없다. 관리할 것이 없다.
			continue
		}

		month := time.Now().UTC().Truncate(time.Hour)
		month = time.Date(month.Year(), month.Month(), 1, 0, 0, 0, 0, time.UTC)

		for i := 0; i <= monthsAhead; i++ {
			target := month.AddDate(0, i, 0)
			name := partitionName(target)
			if existing[name] {
				continue
			}
			if err := s.addMonthlyPartition(ctx, pt.table, name, target.AddDate(0, 1, 0)); err != nil {
				log.Printf("[PartitionScheduler] Failed to add partition %s to %s: %v", name, pt.table, err)
				continue
			}
			existing[name] = true
			log.Printf("[PartitionScheduler] Added partition %s to %s", name, pt.table)
		}
	}
}

// addMonthlyPartition은 포괄 파티션에서 한 달치를 떼어낸다.
//
// REORGANIZE는 지금 p_max에 들어 있는 행만 다시 쓴다. 정상적인 설치라면 그런
// 행은 없다. 파티션은 데이터가 들어오기 몇 달 전에 미리 만들어지기 때문이다.
func (s *PartitionScheduler) addMonthlyPartition(ctx context.Context, table, name string, upperBound time.Time) error {
	stmt := fmt.Sprintf(
		`ALTER TABLE %s REORGANIZE PARTITION %s INTO (
			PARTITION %s VALUES LESS THAN ('%s'),
			PARTITION %s VALUES LESS THAN (MAXVALUE)
		)`,
		table, maxPartitionName, name, upperBound.Format("2006-01-02 15:04:05"), maxPartitionName)

	_, err := s.db.ExecContext(ctx, stmt)
	return err
}

// dropOldPartitionsMariaDB는 보존 기간보다 오래된 파티션을 통째로 버린다.
//
// 파티션 삭제는 메타데이터 작업이다. PostgreSQL 경로가 대신 쓰는 행 단위
// DELETE는 모든 행을 훑고 로그로 남겨야 한다. 보존 기간 바깥에 완전히 놓인
// 파티션만 삭제하므로 아직 기간 안에 있는 행은 절대 잃지 않는다. 경계에 걸친
// 파티션은 행 단위 정리에 맡긴다.
func (s *PartitionScheduler) dropOldPartitionsMariaDB(ctx context.Context, table string, retentionDays int) {
	if retentionDays < 1 {
		return
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	// 파티션은 그 상한 — 즉 그 파티션이 담지 *않는* 첫 시점 — 이 컷오프
	// 이하일 때만 삭제할 수 있다.
	rows, err := s.db.QueryContext(ctx, `
		SELECT partition_name, partition_description
		FROM information_schema.partitions
		WHERE table_schema = DATABASE() AND table_name = ?
		  AND partition_name IS NOT NULL AND partition_name <> ?
		ORDER BY partition_ordinal_position`, table, maxPartitionName)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to list partitions of %s: %v", table, err)
		return
	}
	defer rows.Close()

	type candidate struct {
		name  string
		upper time.Time
	}
	var drops []candidate

	for rows.Next() {
		var name string
		var description sql.NullString
		if err := rows.Scan(&name, &description); err != nil {
			log.Printf("[PartitionScheduler] Failed to scan partition of %s: %v", table, err)
			return
		}
		upper, ok := parsePartitionBound(description.String)
		if !ok || upper.After(cutoff) {
			continue
		}
		drops = append(drops, candidate{name: name, upper: upper})
	}
	if err := rows.Err(); err != nil {
		log.Printf("[PartitionScheduler] Failed to iterate partitions of %s: %v", table, err)
		return
	}

	for _, d := range drops {
		if _, err := s.db.ExecContext(ctx,
			fmt.Sprintf("ALTER TABLE %s DROP PARTITION %s", table, d.name)); err != nil {
			log.Printf("[PartitionScheduler] Failed to drop partition %s of %s: %v", d.name, table, err)
			continue
		}
		log.Printf("[PartitionScheduler] Dropped partition %s of %s (holds data before %s, retention %d days)",
			d.name, table, d.upper.Format("2006-01-02"), retentionDays)
	}
}

// analyzeMariaDB는 파티션된 로그 테이블의 옵티마이저 통계를 갱신한다.
// PostgreSQL 경로의 ANALYZE 순회에 해당한다.
func (s *PartitionScheduler) analyzeMariaDB(ctx context.Context) {
	for _, pt := range partitionedTables {
		if _, err := s.db.ExecContext(ctx, fmt.Sprintf("ANALYZE TABLE %s", pt.table)); err != nil {
			log.Printf("[PartitionScheduler] ANALYZE TABLE %s failed: %v", pt.table, err)
		}
	}
}

// existingPartitions는 테이블의 파티션 이름들을 조회하기 좋은 형태로 돌려준다.
func (s *PartitionScheduler) existingPartitions(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT partition_name FROM information_schema.partitions
		WHERE table_schema = DATABASE() AND table_name = ? AND partition_name IS NOT NULL`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// partitionName은 001_init.sql이 정한 명명 규칙이다: p2026_03.
func partitionName(month time.Time) string {
	return "p" + month.Format("2006_01")
}

// parsePartitionBound는 partition_description 컬럼에서 상한을 읽는다. RANGE
// COLUMNS 파티션에서는 '2026-01-01 00:00:00' 같은 형태다.
func parsePartitionBound(description string) (time.Time, bool) {
	trimmed := description
	for _, cut := range []string{"'", `"`} {
		trimmed = trimQuotes(trimmed, cut)
	}
	if trimmed == "" || trimmed == "MAXVALUE" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, trimmed); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func trimQuotes(s, quote string) string {
	if len(s) >= 2*len(quote) && s[:len(quote)] == quote && s[len(s)-len(quote):] == quote {
		return s[len(quote) : len(s)-len(quote)]
	}
	return s
}

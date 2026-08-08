package repository

import (
	"fmt"
	"strings"

	"nginx-proxy-guard/internal/database/dialect"
)

// 두 백엔드에 대해 한 번에 쓸 수 없는 소수의 문장을 위한 질의 조각들.
//
// 리포지토리 SQL은 거의 전부 PostgreSQL 방언이고, 번역 드라이버를 통해 그대로
// MySQL 계열에 도달한다. 번역되지 않는 것은 배열이나 JSON 컬럼 *안쪽*으로
// 들어가는 경우다. 두 엔진의 저장 방식이 다르기 때문이다. PostgreSQL에는 진짜
// text[]와 jsonb 타입과 그에 맞는 연산자가 있지만, MySQL 계열 스키마는 바로 그
// PostgreSQL 배열 리터럴을 TEXT 컬럼에 담아 lib/pq의 배열 코덱이 양쪽에서 그대로
// 동작하게 한다. 그 덕에 Go 쪽 왕복은 완전히 같아지고 SQL 쪽 조회만 백엔드별로
// 갈린다. 이 파일이 치르는 대가가 그것이다.

// placeholders는 IN 목록용으로 `$start, $start+1, ...`을 만든다.
//
// 값이 Go 슬라이스에서 오는 곳이라면 `= ANY($1)`보다 이쪽이 낫다. IN 목록은 두
// 엔진 모두 받아주는 평범한 SQL이라 dialect 분기가 아예 필요 없다.
func placeholders(start, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("$%d", start+i)
	}
	return strings.Join(parts, ", ")
}

// stringArgs는 placeholders로 만든 질의에 넘기려고 []string을 넓힌다.
func stringArgs(values []string) []interface{} {
	args := make([]interface{}, len(values))
	for i, v := range values {
		args[i] = v
	}
	return args
}

// arrayContains는 배열 컬럼이 $n에 바인딩된 값을 담고 있는지 검사하는 술어를
// 만든다. PostgreSQL의 `$n = ANY(col)` / `col @> ARRAY[$n]`에 해당한다.
//
// MySQL 계열에서 그 컬럼은 텍스트로 담긴 PostgreSQL 배열 리터럴이고, lib/pq는
// 각 원소를 항상 큰따옴표로 감싼다(`{"a.example","b.example"}`). 따옴표까지
// 포함해 `"값"`으로 매칭하면 원소 전체만 걸리므로, 다른 원소의 부분 문자열인
// 값에 속지 않는다.
func arrayContains(column string, n int) string {
	if dialect.ActiveIsMySQLFamily() {
		return fmt.Sprintf(`%s LIKE CONCAT('%%"', $%d, '"%%')`, column, n)
	}
	return fmt.Sprintf(`$%d = ANY(%s)`, n, column)
}

// arrayNotEmpty는 PostgreSQL의 `array_length(col, 1) > 0`을 만든다.
func arrayNotEmpty(column string) string {
	if dialect.ActiveIsMySQLFamily() {
		return fmt.Sprintf(`%s IS NOT NULL AND %s <> '{}'`, column, column)
	}
	return fmt.Sprintf(`array_length(%s, 1) > 0`, column)
}

// arrayLength는 배열 컬럼의 원소 개수를 만든다.
//
// MySQL 계열 형태는 리터럴 안의 구분자를 센다. 이 함수가 쓰이는 값들(CIDR
// 범위와 공급자 슬러그로, 어느 쪽도 쉼표를 포함할 수 없다)에는 정확하며, 쉼표를
// 품은 원소가 있을 때만 과다 집계된다.
func arrayLength(column string) string {
	if dialect.ActiveIsMySQLFamily() {
		return fmt.Sprintf(
			`(CASE WHEN %s IS NULL OR %s = '{}' THEN 0
			       ELSE CHAR_LENGTH(%s) - CHAR_LENGTH(REPLACE(%s, ',', '')) + 1 END)`,
			column, column, column, column)
	}
	return fmt.Sprintf(`array_length(%s, 1)`, column)
}

// jsonSetString은 JSON 컬럼 안의 문자열 필드 하나를 갱신하는 식을 만든다.
func jsonSetString(column, field string, n int) string {
	if dialect.ActiveIsMySQLFamily() {
		return fmt.Sprintf(`JSON_SET(%s, '$.%s', $%d)`, column, field, n)
	}
	return fmt.Sprintf(`jsonb_set(%s, '{%s}', to_jsonb($%d::text))`, column, field, n)
}

// latestJSONField는 "그룹에서 가장 최근 행의 JSON 필드 값"을 만든다. 알림
// 다이제스트가 연속된 발생 건에 제목을 붙일 때 쓴다.
//
// PostgreSQL은 정렬된 array_agg의 첫 원소를 가져온다. MySQL 계열에는 배열
// 타입이 없으므로 GROUP_CONCAT을 정렬해 첫 구간을 취하는 방식으로 같은 일을
// 한다. 구분자는 유닛 세퍼레이터 제어 문자로, 알림 제목에 나타날 수 없다.
func latestJSONField(column, field, orderBy string) string {
	if dialect.ActiveIsMySQLFamily() {
		return fmt.Sprintf(
			`COALESCE(SUBSTRING_INDEX(GROUP_CONCAT(JSON_UNQUOTE(JSON_EXTRACT(%s, '$.%s')) ORDER BY %s SEPARATOR 0x1f), 0x1f, 1), '')`,
			column, field, orderBy)
	}
	return fmt.Sprintf(`COALESCE((array_agg(%s->'fields'->>'%s' ORDER BY %s))[1], '')`, column, field, orderBy)
}

// tablesExistSQL은 지정한 테이블이 모두 존재하는지를 불리언 하나로 돌려주는
// 질의를 만든다.
//
// SSO, RBAC, 알림 등 몇몇 기능은 그 기능이 필요로 하는 스키마보다 나중에
// 출시됐고, 업그레이드 마이그레이션은 경고 후 계속 진행한다. 따라서 업그레이드가
// 실패한 설치도 해당 기능만 꺼진 채로 기동할 수 있어야 한다. PostgreSQL은
// to_regclass()로 답하지만 MySQL 계열에는 대응물이 없어 information_schema 행을
// 세는 방식을 쓴다.
func tablesExistSQL(tables ...string) string {
	if dialect.ActiveIsMySQLFamily() {
		quoted := make([]string, len(tables))
		for i, t := range tables {
			quoted[i] = "'" + t + "'"
		}
		return fmt.Sprintf(
			`SELECT (SELECT COUNT(*) FROM information_schema.tables
			         WHERE table_schema = DATABASE() AND table_name IN (%s)) = %d`,
			strings.Join(quoted, ", "), len(tables))
	}

	checks := make([]string, len(tables))
	for i, t := range tables {
		checks[i] = fmt.Sprintf("to_regclass('public.%s') IS NOT NULL", t)
	}
	return "SELECT " + strings.Join(checks, "\n   AND ")
}

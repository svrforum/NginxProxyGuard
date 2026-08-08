package dialect

import (
	"fmt"
	"strings"
)

// MariaDB는 INSERT와 DELETE에는 RETURNING을 지원하지만 UPDATE에는, 그리고
// ON DUPLICATE KEY UPDATE와 함께 쓰는 경우에는 지원하지 않는다. MySQL은 아예
// 지원하지 않는다. 이 프로젝트는 그런 형태를 스무 곳 남짓에서 쓰는데, 모두 방금
// 쓴 행을 다시 읽기 위해서다.
//
// 그 호출부들을 갈라내는 대신, 해당 형태의 문장을 둘로 나눈다. 쓰기와, 같은
// 행을 다시 읽는 SELECT다. 드라이버가 이 쌍을 한 트랜잭션 안에서 실행하고 결과를
// 버퍼링하므로, 호출자에게는 여전히 행을 돌려주는 질의 하나로 보인다
// (driver.go 참고).
//
// 분할은 동등함이 증명될 때만 시도한다. WHERE 절이 SET 절에서 대입하는 컬럼을
// 검사하는 UPDATE는 다시 조회할 수 없다. 매칭됐던 행이 더 이상 매칭되지 않기
// 때문이다. 그런 경우 잘못된 집합을 조용히 돌려주는 대신 거부한다.

// splitPlan은 RETURNING 문장을 수행할 쓰기와 호출자의 행을 만들어 낼 SELECT로
// 쪼갠 것이다.
type splitPlan struct {
	write     []token
	read      []token
	readFirst bool
}

// splitReturning은 문장의 RETURNING 절을 흉내내야 하는지, 그렇다면 어떻게
// 해야 하는지 정한다. 계획이 nil이면 대상 서버가 자체적으로 처리한다는 뜻이다.
//
// 플레이버별 지원 현황:
//
//	                          MariaDB   MySQL
//	INSERT ... RETURNING        yes      no
//	DELETE ... RETURNING        yes      no
//	UPDATE ... RETURNING         no      no
//	upsert  ... RETURNING        no      no
func splitReturning(toks []token) (*splitPlan, error) {
	if findTopLevel(toks, "RETURNING") < 0 {
		return nil, nil
	}
	verb := nextCode(toks, 0)
	if verb < 0 {
		return nil, nil
	}

	switch {
	case isWord(toks[verb], "UPDATE"):
		return splitUpdateReturning(toks)
	case isWord(toks[verb], "DELETE"):
		if targetFlavor() != MySQL {
			return nil, nil
		}
		return splitDeleteReturning(toks)
	case isWord(toks[verb], "INSERT"):
		return splitInsertReturning(toks)
	}
	return nil, nil
}

// splitUpdateReturning은
//
//	UPDATE t SET a = $1 WHERE id = $2 RETURNING a, b
//
// 을 UPDATE와 같은 술어를 쓰는 SELECT로 나눈다.
//
// 동등함이 증명될 때만 나눈다. WHERE 절이 SET 절에서 대입하는 컬럼을 검사하는
// UPDATE는 다시 조회할 수 없으므로, 잘못된 집합을 조용히 돌려주는 대신
// 거부한다.
func splitUpdateReturning(toks []token) (*splitPlan, error) {
	ret := findTopLevel(toks, "RETURNING")
	where := findTopLevel(toks, "WHERE")
	if where < 0 || where > ret {
		return nil, fmt.Errorf(
			"mariadb: UPDATE ... RETURNING without a WHERE clause cannot be re-selected safely")
	}
	set := findTopLevel(toks, "SET")
	if set < 0 || set > where {
		return nil, fmt.Errorf("mariadb: malformed UPDATE ... RETURNING")
	}
	if from := findTopLevel(toks, "FROM"); from > 0 && from < where {
		return nil, fmt.Errorf(
			"mariadb: UPDATE ... FROM ... RETURNING has no single-table re-select")
	}

	first := nextCode(toks, 0)
	table := prevCode(toks, set-1)
	if table < 0 || (toks[table].kind != tkWord && toks[table].kind != tkQuotedName) {
		return nil, fmt.Errorf("mariadb: cannot identify the table in UPDATE ... RETURNING")
	}
	// 별칭(`UPDATE t AS x SET ...`)이 붙으면 재조회가 모호해진다.
	if table != nextCode(toks, first+1) {
		return nil, fmt.Errorf("mariadb: aliased UPDATE ... RETURNING is unsupported")
	}

	assigned := assignedColumns(toks, set, where)
	for _, name := range referencedColumns(toks, where+1, ret) {
		if assigned[strings.ToLower(name)] {
			return nil, fmt.Errorf(
				"mariadb: UPDATE ... RETURNING whose WHERE tests the updated column %q cannot be re-selected", name)
		}
	}

	read := []token{kw("SELECT"), space()}
	read = append(read, trimNoise(toks[ret+1:])...)
	read = append(read, space(), kw("FROM"), space(), toks[table], space(), kw("WHERE"), space())
	read = append(read, trimNoise(toks[where+1:ret])...)

	return &splitPlan{write: append([]token(nil), toks[:ret]...), read: read}, nil
}

// splitDeleteReturning은 행을 지우기 전에 먼저 읽는다.
//
// MySQL에는 DELETE ... RETURNING이 없고, UPDATE와 달리 나중에 다시 조회할 것이
// 남지 않는다. 그래서 SELECT를 먼저 실행하고, 삭제가 커밋될 때까지 드라이버가
// 그 행들을 들고 있는다.
func splitDeleteReturning(toks []token) (*splitPlan, error) {
	ret := findTopLevel(toks, "RETURNING")
	from := findTopLevel(toks, "FROM")
	if from < 0 || from > ret {
		return nil, fmt.Errorf("mysql: malformed DELETE ... RETURNING")
	}
	table := nextCode(toks, from+1)
	if table < 0 || (toks[table].kind != tkWord && toks[table].kind != tkQuotedName) {
		return nil, fmt.Errorf("mysql: cannot identify the table in DELETE ... RETURNING")
	}
	where := findTopLevel(toks, "WHERE")
	if where < 0 || where > ret {
		return nil, fmt.Errorf(
			"mysql: DELETE ... RETURNING without a WHERE clause is refused; it would read the whole table")
	}

	read := []token{kw("SELECT"), space()}
	read = append(read, trimNoise(toks[ret+1:])...)
	read = append(read, space(), kw("FROM"), space(), toks[table], space(), kw("WHERE"), space())
	read = append(read, trimNoise(toks[where+1:ret])...)

	return &splitPlan{
		write:     append([]token(nil), toks[:ret]...),
		read:      read,
		readFirst: true,
	}, nil
}

// splitInsertReturning은 행을 돌려주는 INSERT를, 그 INSERT와 방금 쓴 행을 키로
// 조회하는 SELECT로 나눈다.
//
// 여기에 도달하는 형태는 셋이다.
//
//   - 업서트. 어느 플레이버든 RETURNING과 ON DUPLICATE KEY UPDATE를 함께 쓸 수
//     없기 때문이다. 충돌 대상은 유니크 키이므로, 거기 넣은 값이 문장이
//     삽입했든 갱신했든 그 행을 특정해 준다.
//   - MySQL에서의 평범한 INSERT. MySQL에는 RETURNING이 아예 없다. 키는 첫
//     번째로 돌려주는 컬럼이다. 호출자가 그 값을 주지 않았다면 — 스키마가
//     UUID()를 기본값으로 두고 있어 보통 그렇다 — 드라이버가 하나 만들어
//     명시적으로 삽입하고, 재조회가 그것을 키로 삼는다.
//   - MariaDB에서의 평범한 INSERT. 자체 지원하므로 계획을 만들지 않는다.
func splitInsertReturning(toks []token) (*splitPlan, error) {
	ret := findTopLevel(toks, "RETURNING")
	conflict := findConflictClause(toks)
	if conflict < 0 && targetFlavor() != MySQL {
		return nil, nil
	}

	first := nextCode(toks, 0)
	table := nextCode(toks, nextCode(toks, first+1)+1) // INSERT INTO <table>
	if table < 0 || (toks[table].kind != tkWord && toks[table].kind != tkQuotedName) {
		return nil, fmt.Errorf("mariadb: cannot identify the table in INSERT ... RETURNING")
	}

	columns, values, listEnd, err := insertColumnsAndValues(toks, table)
	if err != nil {
		return nil, err
	}

	var targets []conflictTarget
	if conflict >= 0 {
		targets, err = conflictTargetColumns(toks, conflict)
		if err != nil {
			return nil, err
		}
	} else {
		// 키는 문장이 첫 번째로 돌려주는 것이다. 이 스키마에서는 전부 `id`다.
		returned := trimNoise(splitTopLevel(toks[ret+1:])[0])
		if len(returned) != 1 || (returned[0].kind != tkWord && returned[0].kind != tkQuotedName) {
			return nil, fmt.Errorf(
				"mysql: INSERT ... RETURNING must return a plain key column first for the row to be re-selected")
		}
		targets = []conflictTarget{{
			column:  strings.Trim(returned[0].text, `"`),
			compare: compareEqual,
		}}
	}

	write := append([]token(nil), toks[:ret]...)

	var predicate []token
	for _, target := range targets {
		idx := -1
		for i, name := range columns {
			if strings.EqualFold(name, target.column) {
				idx = i
				break
			}
		}

		var value []token
		switch {
		case idx >= 0 && idx < len(values):
			value = values[idx]
		case conflict >= 0:
			return nil, fmt.Errorf(
				"mariadb: conflict target %q is not in the INSERT column list, so the written row cannot be re-selected", target.column)
		default:
			// 호출자가 주지 않았다. 드라이버가 만들게 하고, 서버가 정확히 그
			// 값을 저장하도록 INSERT에 추가한다.
			write = addSynthesisedColumn(write, listEnd, target.column)
			value = []token{{kind: tkSynth}}
		}

		if len(predicate) > 0 {
			predicate = append(predicate, space(), kw("AND"), space())
		}
		predicate = append(predicate, target.compare(kw(target.column), value)...)
	}

	read := []token{kw("SELECT"), space()}
	read = append(read, trimNoise(toks[ret+1:])...)
	read = append(read, space(), kw("FROM"), space(), toks[table], space(), kw("WHERE"), space())
	read = append(read, predicate...)

	return &splitPlan{write: write, read: read}, nil
}

// addSynthesisedColumn은 INSERT 컬럼 목록에 `, <컬럼>`을, VALUES 목록에 대응하는
// 드라이버 제공 값을 덧붙인다.
//
// listEnd가 두 닫는 괄호의 위치를 들고 있어 다시 파싱하지 않고 양쪽을 늘릴 수
// 있다. 값 목록을 먼저 편집해서 앞쪽 인덱스가 유효하게 남도록 한다.
func addSynthesisedColumn(toks []token, listEnd insertListEnds, column string) []token {
	toks = splice(toks, listEnd.values, listEnd.values,
		[]token{raw(","), space(), {kind: tkSynth}, raw(")")})
	return splice(toks, listEnd.columns, listEnd.columns,
		[]token{raw(","), space(), kw(column), raw(")")})
}

// ---------------------------------------------------------------------------
// 헬퍼
// ---------------------------------------------------------------------------

// findTopLevel은 괄호 바깥에서 word가 처음 나타나는 인덱스를 돌려준다.
// 없으면 -1.
func findTopLevel(toks []token, word string) int {
	depth := 0
	for i, t := range toks {
		switch {
		case isPunct(t, "("):
			depth++
		case isPunct(t, ")"):
			depth--
		case depth == 0 && isWord(t, word):
			return i
		}
	}
	return -1
}

// findConflictClause는 `ON CONFLICT`의 ON 인덱스를 돌려준다. 없으면 -1.
func findConflictClause(toks []token) int {
	depth := 0
	for i, t := range toks {
		switch {
		case isPunct(t, "("):
			depth++
		case isPunct(t, ")"):
			depth--
		case depth == 0 && isWord(t, "ON"):
			if j := nextCode(toks, i+1); j >= 0 && isWord(toks[j], "CONFLICT") {
				return i
			}
		}
	}
	return -1
}

// assignedColumns는 SET부터 SET 절 끝까지의 모든 대입에서 좌변을 모은다.
func assignedColumns(toks []token, set, end int) map[string]bool {
	out := map[string]bool{}
	depth := 0
	expectTarget := true
	for i := set + 1; i < end; i++ {
		switch {
		case isPunct(toks[i], "("):
			depth++
		case isPunct(toks[i], ")"):
			depth--
		case depth == 0 && isPunct(toks[i], ","):
			expectTarget = true
		case depth == 0 && expectTarget && (toks[i].kind == tkWord || toks[i].kind == tkQuotedName):
			out[strings.ToLower(strings.Trim(toks[i].text, `"`))] = true
			expectTarget = false
		}
	}
	return out
}

// 술어가 읽는 컬럼 이름을 모을 때 건너뛸 키워드들. 덕분에
// `WHERE status = 'pending' AND expires_at IS NOT NULL`에서 컬럼 이름 두 개만
// 나온다.
var sqlKeywords = map[string]bool{
	"and": true, "or": true, "not": true, "is": true, "null": true, "in": true,
	"like": true, "ilike": true, "between": true, "exists": true, "any": true,
	"all": true, "true": true, "false": true, "case": true, "when": true,
	"then": true, "else": true, "end": true, "select": true, "from": true,
	"where": true, "as": true, "distinct": true, "collate": true, "escape": true,
}

// referencedColumns는 구간이 읽는 식별자들을 나열한다. 키워드와 함수 이름은
// 무시한다.
func referencedColumns(toks []token, from, to int) []string {
	var out []string
	for i := from; i < to && i < len(toks); i++ {
		t := toks[i]
		if t.kind != tkWord && t.kind != tkQuotedName {
			continue
		}
		name := strings.Trim(t.text, `"`)
		if sqlKeywords[strings.ToLower(name)] {
			continue
		}
		// 뒤에 '('가 오는 이름은 컬럼이 아니라 함수 호출이다.
		if n := nextCode(toks, i+1); n >= 0 && isPunct(toks[n], "(") {
			continue
		}
		out = append(out, name)
	}
	return out
}

// insertListEnds는 INSERT의 두 괄호 목록을 각각 닫는 ')'의 인덱스를 기록한다.
type insertListEnds struct {
	columns int
	values  int
}

// insertColumnsAndValues는 `INSERT INTO t (a, b) VALUES ($1, $2)`를 분해한다.
func insertColumnsAndValues(toks []token, table int) ([]string, [][]token, insertListEnds, error) {
	var ends insertListEnds

	open := nextCode(toks, table+1)
	if open < 0 || !isPunct(toks[open], "(") {
		return nil, nil, ends, fmt.Errorf("mariadb: INSERT ... RETURNING without an explicit column list cannot be re-selected")
	}
	close := matchOpen(toks, open)
	if close < 0 {
		return nil, nil, ends, fmt.Errorf("mariadb: unbalanced INSERT column list")
	}
	ends.columns = close

	var columns []string
	for _, group := range splitTopLevel(toks[open+1 : close]) {
		g := trimNoise(group)
		if len(g) != 1 || (g[0].kind != tkWord && g[0].kind != tkQuotedName) {
			return nil, nil, ends, fmt.Errorf("mariadb: unexpected INSERT column list entry")
		}
		columns = append(columns, strings.Trim(g[0].text, `"`))
	}

	valuesKw := nextCode(toks, close+1)
	if valuesKw < 0 || !isWord(toks[valuesKw], "VALUES") {
		return nil, nil, ends, fmt.Errorf("mariadb: INSERT ... SELECT ... RETURNING cannot be re-selected")
	}
	vopen := nextCode(toks, valuesKw+1)
	if vopen < 0 || !isPunct(toks[vopen], "(") {
		return nil, nil, ends, fmt.Errorf("mariadb: malformed VALUES clause")
	}
	vclose := matchOpen(toks, vopen)
	if vclose < 0 {
		return nil, nil, ends, fmt.Errorf("mariadb: unbalanced VALUES clause")
	}
	// 다중 행 VALUES 목록은 여러 행을 쓰므로 단일 행 재조회는 틀린 결과가
	// 된다.
	if n := nextCode(toks, vclose+1); n >= 0 && isPunct(toks[n], ",") {
		return nil, nil, ends, fmt.Errorf("mariadb: multi-row INSERT ... RETURNING cannot be re-selected")
	}

	var values [][]token
	for _, group := range splitTopLevel(toks[vopen+1 : vclose]) {
		values = append(values, trimNoise(group))
	}
	if len(values) != len(columns) {
		return nil, nil, ends, fmt.Errorf("mariadb: INSERT column and value counts differ")
	}
	ends.values = vclose
	return columns, values, ends, nil
}

// conflictTarget은 ON CONFLICT 대상 목록의 한 항목이며, 그 컬럼을 INSERT가
// 바인딩한 값과 어떻게 비교할지도 함께 담는다.
type conflictTarget struct {
	column  string
	compare func(column token, value []token) []token
}

func compareEqual(column token, value []token) []token {
	out := []token{column, space(), raw("="), space()}
	return append(out, value...)
}

// compareCoalesced는 PostgreSQL의 COALESCE(col, 빈 문자열) 식 인덱스와 맞춘다.
// NULL과 빈 문자열이 같은 키이므로 비교에서도 양쪽을 함께 접어야 한다.
func compareCoalesced(column token, value []token) []token {
	out := []token{kw("COALESCE"), raw("("), column, raw(","), space(), str("''"), raw(")"),
		space(), raw("="), space(), kw("COALESCE"), raw("(")}
	out = append(out, value...)
	return append(out, raw(","), space(), str("''"), raw(")"))
}

// compareLowered는 `lower(col)` 식 인덱스와 맞춘다.
func compareLowered(column token, value []token) []token {
	out := []token{kw("LOWER"), raw("("), column, raw(")"), space(), raw("="), space(), kw("LOWER"), raw("(")}
	out = append(out, value...)
	return append(out, raw(")"))
}

// conflictTargetColumns는 `ON CONFLICT (a, b)`를 읽는다. 이 스키마가 대소문자
// 무시 및 NULL 접기 유니크 인덱스에 쓰는 식 형태도 함께 처리한다. 대상 엔진은
// 둘 다 생성 컬럼으로 재현하므로 업서트 자체에는 대상이 필요 없지만, 재조회는
// 어느 행이 쓰였는지 알아야 한다.
func conflictTargetColumns(toks []token, conflict int) ([]conflictTarget, error) {
	open := nextCode(toks, nextCode(toks, conflict+1)+1)
	if open < 0 || !isPunct(toks[open], "(") {
		return nil, fmt.Errorf("mariadb: ON CONFLICT without a column target cannot be re-selected")
	}
	close := matchOpen(toks, open)
	if close < 0 {
		return nil, fmt.Errorf("mariadb: unbalanced ON CONFLICT target")
	}

	var out []conflictTarget
	for _, group := range splitTopLevel(toks[open+1 : close]) {
		target, err := parseConflictTarget(trimNoise(group))
		if err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, nil
}

func parseConflictTarget(g []token) (conflictTarget, error) {
	if len(g) == 1 && (g[0].kind == tkWord || g[0].kind == tkQuotedName) {
		return conflictTarget{column: strings.Trim(g[0].text, `"`), compare: compareEqual}, nil
	}

	if len(g) > 1 && g[0].kind == tkWord {
		fn := strings.ToLower(g[0].text)
		if column, ok := soleIdentifierArgument(g); ok {
			switch fn {
			case "coalesce":
				return conflictTarget{column: column, compare: compareCoalesced}, nil
			case "lower":
				return conflictTarget{column: column, compare: compareLowered}, nil
			}
		}
	}

	return conflictTarget{}, fmt.Errorf("mariadb: unsupported ON CONFLICT target expression")
}

// soleIdentifierArgument는 감싸는 호출에서 컬럼 이름 하나를 꺼낸다. pg_dump가
// 내보내는 불필요한 괄호와 캐스트를 허용한다. `lower((name)::text)`가 가리키는
// 컬럼은 `name`이다.
func soleIdentifierArgument(g []token) (string, bool) {
	var names []string
	for _, t := range g[1:] {
		switch t.kind {
		case tkWord, tkQuotedName:
			name := strings.Trim(t.text, `"`)
			// `::` 뒤에 오는 캐스트 타입 이름은 컬럼이 아니다.
			if sqlKeywords[strings.ToLower(name)] {
				continue
			}
			names = append(names, name)
		case tkString, tkNumber, tkPunct, tkSpace, tkComment:
		default:
			return "", false
		}
	}
	// 캐스트는 타입 이름을 남긴다. 컬럼은 첫 번째 식별자다.
	if len(names) == 0 {
		return "", false
	}
	return names[0], true
}

// splitTopLevel은 괄호 안에 있지 않은 쉼표를 기준으로 토큰 구간을 나눈다.
func splitTopLevel(toks []token) [][]token {
	var out [][]token
	depth, start := 0, 0
	for i, t := range toks {
		switch {
		case isPunct(t, "("):
			depth++
		case isPunct(t, ")"):
			depth--
		case depth == 0 && isPunct(t, ","):
			out = append(out, toks[start:i])
			start = i + 1
		}
	}
	if start <= len(toks) {
		out = append(out, toks[start:])
	}
	return out
}

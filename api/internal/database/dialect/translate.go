package dialect

import (
	"fmt"
	"strconv"
	"strings"
)

// Statement는 번역이 끝나 드라이버에 넘길 준비가 된 문장이다.
//
// ArgOrder는 방출된 각 `?`를 호출자의 인자 슬라이스로 되짚어 준다. ArgOrder[i]는
// i번째 자리에 들어갈 인자의 0 기반 인덱스다. Postgres 플레이스홀더는 순번으로
// 이름 붙고 반복되거나 순서가 뒤바뀔 수 있지만, MySQL 것은 철저히 위치 기반이라
// 인자를 다시 배열해야 한다. ArgOrder가 nil이면 인자를 그대로 넘긴다는 뜻이다.
//
// FollowUp이 설정돼 있으면, 호출자가 요청한 행을 만들어 내기 위해 드라이버가
// SQL 직후에 실행해야 하는 SELECT다. MariaDB가 UPDATE에도, ON DUPLICATE KEY
// UPDATE 업서트에도 RETURNING을 지원하지 않기 때문에 필요하다. returning.go 참고.
type Statement struct {
	SQL      string
	ArgOrder []int
	FollowUp *Statement
	// FollowUpFirst는 FollowUp을 SQL보다 *먼저* 실행해야 함을 뜻한다.
	// DELETE ... RETURNING이 그런 경우로, 쓰기가 끝나면 행이 사라진다.
	FollowUpFirst bool
}

// ArgSynthesisedUUID는 호출자의 인자가 아니라 드라이버가 직접 만든 UUID로 채울
// ArgOrder 슬롯을 표시한다. 실행 한 번당 UUID 하나를 만들어 이 표시가 붙은 모든
// 슬롯에 쓰며, 덕분에 쓰기와 재조회가 같은 행을 두고 합의할 수 있다.
const ArgSynthesisedUUID = -1

// Translate는 PostgreSQL 문장 하나를 대상 엔진의 대응 문장으로 재작성한다.
//
// 충실한 대응물이 없는 구문은 최선을 다한 재작성 대신 오류를 돌려준다. 실행은
// 되지만 의미가 조금 다른 SQL을 조용히 만들어 내는 것이야말로 이 계층이 절대
// 저지르면 안 되는 실패 방식이다. 오류를 받은 호출자는 개발 중에 즉시 알아채지만,
// 미묘하게 잘못된 번역은 몇 달 뒤 대시보드 숫자가 망가진 형태로 드러난다.
// 프로젝트가 실제로 쓰는 그런 구문은 전부 호출부에서 Kind로 분기해 처리한다.
// 이 오류는 나머지를 막는 최후의 방어선이다.
func Translate(query string) (*Statement, error) {
	toks := lex(query)

	if err := rejectUntranslatable(toks); err != nil {
		return nil, err
	}

	plan, err := splitReturning(toks)
	if err != nil {
		return nil, err
	}
	if plan != nil {
		write, err := translateTokens(plan.write)
		if err != nil {
			return nil, err
		}
		read, err := translateTokens(plan.read)
		if err != nil {
			return nil, err
		}
		write.FollowUp = read
		write.FollowUpFirst = plan.readFirst
		return write, nil
	}

	return translateTokens(toks)
}

// translateTokens는 한 문장의 토큰에 재작성 파이프라인을 적용한다.
func translateTokens(toks []token) (*Statement, error) {
	if targetFlavor() == MySQL {
		toks = stripUnsupportedIfExists(toks)
		toks = rewriteTableCompression(toks)
	}

	toks, err := rewriteOnConflict(toks)
	if err != nil {
		return nil, err
	}
	toks = rewriteAggregateFilter(toks)
	toks, err = rewriteExpressions(toks)
	if err != nil {
		return nil, err
	}

	sql, order, err := emit(toks)
	if err != nil {
		return nil, err
	}
	return &Statement{SQL: sql, ArgOrder: order}, nil
}

// ---------------------------------------------------------------------------
// 토큰 탐색 헬퍼
// ---------------------------------------------------------------------------

func isNoise(t token) bool { return t.kind == tkSpace || t.kind == tkComment }

// nextCode는 i 이후(i 포함)에서 공백도 주석도 아닌 첫 토큰의 인덱스를 돌려준다.
// 없으면 -1.
func nextCode(toks []token, i int) int {
	for ; i < len(toks); i++ {
		if !isNoise(toks[i]) {
			return i
		}
	}
	return -1
}

// prevCode는 i 이전(i 포함)에서 공백도 주석도 아닌 첫 토큰의 인덱스를 돌려준다.
// 없으면 -1.
func prevCode(toks []token, i int) int {
	for ; i >= 0; i-- {
		if !isNoise(toks[i]) {
			return i
		}
	}
	return -1
}

func isWord(t token, word string) bool {
	return t.kind == tkWord && strings.EqualFold(t.text, word)
}

func isPunct(t token, p string) bool {
	return t.kind == tkPunct && t.text == p
}

// matchOpen은 open 위치의 '('를 닫는 ')'의 인덱스를 돌려준다. 없으면 -1.
func matchOpen(toks []token, open int) int {
	depth := 0
	for i := open; i < len(toks); i++ {
		if isPunct(toks[i], "(") {
			depth++
		} else if isPunct(toks[i], ")") {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// matchClose는 close 위치의 ')'에 대응하는 '('의 인덱스를 돌려준다. 없으면 -1.
func matchClose(toks []token, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		if isPunct(toks[i], ")") {
			depth++
		} else if isPunct(toks[i], "(") {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// trimNoise는 잘라낸 구간의 앞뒤 공백·주석 토큰을 버린다. 다시 조립한 식이
// 원본의 띄어쓰기를 물려받지 않게 하기 위해서다.
func trimNoise(toks []token) []token {
	start := 0
	for start < len(toks) && isNoise(toks[start]) {
		start++
	}
	end := len(toks)
	for end > start && isNoise(toks[end-1]) {
		end--
	}
	return toks[start:end]
}

func splice(toks []token, from, to int, with []token) []token {
	out := make([]token, 0, len(toks)-(to-from+1)+len(with))
	out = append(out, toks[:from]...)
	out = append(out, with...)
	out = append(out, toks[to+1:]...)
	return out
}

// 토큰 생성자. 복합 리터럴은 인자 목록에서 타입을 생략할 수 없는데 이 재작성
// 규칙들은 출력 대부분을 append(...) 안에서 만든다. 생성자를 두면 규칙이 읽기
// 쉬워진다.
func kw(text string) token  { return token{kind: tkWord, text: text} }
func num(text string) token { return token{kind: tkNumber, text: text} }
func str(text string) token { return token{kind: tkString, text: text} }
func raw(text string) token { return token{kind: tkPunct, text: text} }
func space() token          { return token{kind: tkSpace, text: " "} }

// ---------------------------------------------------------------------------
// 피연산자 스캔
//
// 몇몇 재작성은 키워드 한쪽에 붙어 있는 식이 필요하다. `x::date`는 DATE(x)가
// 돼야 하고, `a ILIKE $1`은 패턴 뒤에 COLLATE를 붙여야 한다. 둘 다 그 식이 어디서
// 시작하고 끝나는지 알아야 하는데, 함수 호출·수식된 이름·|| 연결이 끼면 토큰
// 하나로 끝나지 않는다.
// ---------------------------------------------------------------------------

// operandStart는 end(포함)에서 끝나는 식의 첫 토큰 인덱스를 돌려준다.
func operandStart(toks []token, end int) int {
	i := prevCode(toks, end)
	if i < 0 {
		return -1
	}

	if isPunct(toks[i], ")") {
		open := matchClose(toks, i)
		if open < 0 {
			return i
		}
		i = open
		// 맨 단어 뒤에 오는 '('는 그 함수의 인자 목록이다.
		if p := prevCode(toks, i-1); p >= 0 && toks[p].kind == tkWord {
			i = p
		}
	}

	// 수식된 이름을 거슬러 올라간다: schema.table.column.
	for {
		p := prevCode(toks, i-1)
		if p < 0 || !isPunct(toks[p], ".") {
			break
		}
		q := prevCode(toks, p-1)
		if q < 0 || (toks[q].kind != tkWord && toks[q].kind != tkQuotedName) {
			break
		}
		i = q
	}
	return i
}

// operandEnd는 start 이후(포함)에서 시작하는 식의 마지막 토큰 인덱스를
// 돌려준다. || 연결 체인을 따라간다.
func operandEnd(toks []token, start int) int {
	i := nextCode(toks, start)
	if i < 0 {
		return -1
	}

	if isPunct(toks[i], "(") {
		if close := matchOpen(toks, i); close >= 0 {
			i = close
		}
	} else {
		// 수식된 이름, 그리고 호출이라면 뒤따르는 인자 목록.
		for {
			n := nextCode(toks, i+1)
			if n < 0 || !isPunct(toks[n], ".") {
				break
			}
			q := nextCode(toks, n+1)
			if q < 0 || (toks[q].kind != tkWord && toks[q].kind != tkQuotedName) {
				break
			}
			i = q
		}
		if n := nextCode(toks, i+1); n >= 0 && isPunct(toks[n], "(") && toks[i].kind == tkWord {
			if close := matchOpen(toks, n); close >= 0 {
				i = close
			}
		}
	}

	// '||'를 건너뛰며 이어가서 `'%' || $1 || '%'`를 한 피연산자로 다룬다.
	if n := nextCode(toks, i+1); n >= 0 && isPunct(toks[n], "||") {
		if e := operandEnd(toks, n+1); e >= 0 {
			return e
		}
	}
	return i
}

// ---------------------------------------------------------------------------
// 지원 불가 구문 검출
// ---------------------------------------------------------------------------

// pgOnlyFunctions는 기계적 재작성으로는 대응물을 만들 수 없는 함수들이다.
// 이들이 필요한 호출부는 Kind로 분기해 자기 SQL을 제공한다. 번역기까지 도달한
// 것은 드러낼 만한 버그다.
var pgOnlyFunctions = map[string]string{
	"array_agg":          "array aggregate",
	"array_length":       "array function",
	"array_to_string":    "array function",
	"array_position":     "array function",
	"unnest":             "array function",
	"string_agg":         "use GROUP_CONCAT via a dialect branch",
	"jsonb_set":          "jsonb function",
	"jsonb_each":         "jsonb function",
	"jsonb_each_text":    "jsonb function",
	"jsonb_build_object": "jsonb function",
	"to_jsonb":           "jsonb function",
	"row_to_json":        "json function",
	"generate_series":    "set-returning function",
	"regexp_matches":     "use REGEXP via a dialect branch",

	// 카탈로그와 크기 조회 함수들. 예전에는 알 수 없는 식별자인 채로 서버까지
	// 가서 실패했다. 여기에 이름을 올려 두면 대신 TestEveryQueryTranslates에서
	// 빌드 시점 실패가 된다.
	"pg_database_size":          "use information_schema.tables via a dialect branch",
	"pg_total_relation_size":    "use information_schema.tables via a dialect branch",
	"pg_relation_size":          "use information_schema.tables via a dialect branch",
	"pg_size_pretty":            "format the size in Go instead",
	"hypertable_size":           "TimescaleDB-only",
	"to_regclass":               "check information_schema.tables via a dialect branch",
	"drop_chunks":               "TimescaleDB-only",
	"drop_old_partitions":       "PL/pgSQL helper; MariaDB uses ALTER TABLE DROP PARTITION",
	"create_monthly_partitions": "PL/pgSQL helper; MariaDB uses ALTER TABLE REORGANIZE PARTITION",
}

func rejectUntranslatable(toks []token) error {
	depth := 0
	for i, t := range toks {
		switch {
		case isPunct(t, "("):
			depth++
		case isPunct(t, ")"):
			depth--
		}

		if t.kind == tkDollarStr {
			return fmt.Errorf("mariadb: dollar-quoted PL/pgSQL body is PostgreSQL-only")
		}

		if t.kind == tkPunct {
			switch t.text {
			case "@>", "<@":
				return fmt.Errorf("mariadb: containment operator %q has no equivalent", t.text)
			case "->", "->>", "#>", "#>>":
				return fmt.Errorf("mariadb: json operator %q has no equivalent; use JSON_EXTRACT via a dialect branch", t.text)
			}
		}

		if t.kind == tkWord {
			lower := strings.ToLower(t.text)
			// 실제로 호출되는 이름만 걸러낸다. 우연히 같은 이름을 가진 컬럼은
			// 건드리지 않는다.
			if reason, bad := pgOnlyFunctions[lower]; bad {
				if n := nextCode(toks, i+1); n >= 0 && isPunct(toks[n], "(") {
					return fmt.Errorf("mariadb: %s() is PostgreSQL-only (%s)", lower, reason)
				}
			}
			// `col = ANY($1)`은 배열을 IN 목록으로 풀어야 하는데, 슬라이스를
			// 쥐고 있는 호출부만 할 수 있는 일이다.
			if strings.EqualFold(t.text, "ANY") {
				if n := nextCode(toks, i+1); n >= 0 && isPunct(toks[n], "(") {
					return fmt.Errorf("mariadb: = ANY(array) has no equivalent; build an IN list via a dialect branch")
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ON CONFLICT -> ON DUPLICATE KEY UPDATE
// ---------------------------------------------------------------------------

// rewriteOnConflict는 Postgres 업서트 문법을 변환한다.
//
// DO NOTHING은 INSERT IGNORE가 아니라 아무 일도 하지 않는 자기 대입
// (`ON DUPLICATE KEY UPDATE c = c`)이 된다. IGNORE는 *모든* 오류를 경고로
// 낮춘다. 외래 키 위반, 잘림, 잘못된 enum 값까지 전부. 그러면 소리 내어
// 실패했어야 할 행이 대신 사라져 버린다. 자기 대입은 중복 키만 삼키는데,
// 그것이 DO NOTHING이 약속하는 전부다.
func rewriteOnConflict(toks []token) ([]token, error) {
	for {
		start := -1
		for i := 0; i < len(toks); i++ {
			if !isWord(toks[i], "ON") {
				continue
			}
			if j := nextCode(toks, i+1); j >= 0 && isWord(toks[j], "CONFLICT") {
				start = i
				break
			}
		}
		if start < 0 {
			return toks, nil
		}

		cursor := nextCode(toks, nextCode(toks, start+1)+1) // token after CONFLICT
		if cursor < 0 {
			return nil, fmt.Errorf("mariadb: malformed ON CONFLICT clause")
		}

		conflictCol := ""
		switch {
		case isPunct(toks[cursor], "("):
			close := matchOpen(toks, cursor)
			if close < 0 {
				return nil, fmt.Errorf("mariadb: unbalanced ON CONFLICT target list")
			}
			if c := nextCode(toks, cursor+1); c >= 0 && c < close {
				conflictCol = toks[c].text
			}
			cursor = nextCode(toks, close+1)
		case isWord(toks[cursor], "ON"):
			// ON CONFLICT ON CONSTRAINT <name>
			c := nextCode(toks, cursor+1)
			if c < 0 || !isWord(toks[c], "CONSTRAINT") {
				return nil, fmt.Errorf("mariadb: malformed ON CONFLICT ON CONSTRAINT clause")
			}
			cursor = nextCode(toks, nextCode(toks, c+1)+1)
		}

		// `ON CONFLICT (col) WHERE <술어> DO ...`는 PostgreSQL이 어느 부분
		// 유니크 인덱스에 맞춰야 하는지를 지정한다. MySQL 계열은 위반된 유니크
		// 키가 무엇이든 그것에 반응하고, 001_init.sql은 모든 부분 유니크
		// 인덱스를 생성 컬럼 위의 진짜 유니크 키로 재현한다. 따라서 여기서 그
		// 술어는 추가 의미가 없으므로 버린다.
		if cursor >= 0 && isWord(toks[cursor], "WHERE") {
			for cursor < len(toks) && !isWord(toks[cursor], "DO") {
				cursor++
			}
			if cursor >= len(toks) {
				cursor = -1
			}
		}

		if cursor < 0 || !isWord(toks[cursor], "DO") {
			return nil, fmt.Errorf("mariadb: malformed ON CONFLICT clause: expected DO")
		}
		action := nextCode(toks, cursor+1)
		if action < 0 {
			return nil, fmt.Errorf("mariadb: malformed ON CONFLICT clause: missing action")
		}

		switch {
		case isWord(toks[action], "NOTHING"):
			col := conflictCol
			if col == "" {
				col = firstInsertColumn(toks)
			}
			if col == "" {
				return nil, fmt.Errorf("mariadb: cannot translate ON CONFLICT DO NOTHING without a conflict target or column list")
			}
			replacement := []token{
				kw("ON"), space(),
				kw("DUPLICATE"), space(),
				kw("KEY"), space(),
				kw("UPDATE"), space(),
				kw(col), space(), raw("="), space(),
				kw(col),
			}
			toks = splice(toks, start, action, replacement)

		case isWord(toks[action], "UPDATE"):
			set := nextCode(toks, action+1)
			if set < 0 || !isWord(toks[set], "SET") {
				return nil, fmt.Errorf("mariadb: malformed ON CONFLICT DO UPDATE clause: expected SET")
			}
			if err := checkUpsertTail(toks, set); err != nil {
				return nil, err
			}
			replacement := []token{
				kw("ON"), space(),
				kw("DUPLICATE"), space(),
				kw("KEY"), space(),
				kw("UPDATE"),
			}
			toks = splice(toks, start, set, replacement)
			toks = rewriteExcluded(toks)

		default:
			return nil, fmt.Errorf("mariadb: unsupported ON CONFLICT action %q", toks[action].text)
		}
	}
}

// checkUpsertTail은 표현할 수 없는 두 가지 업서트 형태를 거부한다. 조건부
// DO UPDATE(... WHERE ...)와, 행까지 돌려주는 업서트다.
func checkUpsertTail(toks []token, set int) error {
	depth := 0
	for i := set + 1; i < len(toks); i++ {
		switch {
		case isPunct(toks[i], "("):
			depth++
		case isPunct(toks[i], ")"):
			depth--
		case depth == 0 && isWord(toks[i], "WHERE"):
			return fmt.Errorf("mariadb: conditional upsert (ON CONFLICT DO UPDATE ... WHERE) is unsupported")
		case depth == 0 && isWord(toks[i], "RETURNING"):
			return fmt.Errorf("mariadb: INSERT ... ON DUPLICATE KEY UPDATE cannot be combined with RETURNING")
		}
	}
	return nil
}

// rewriteExcluded는 EXCLUDED 유사 행을 MySQL의 VALUES()로 바꾼다.
func rewriteExcluded(toks []token) []token {
	for i := 0; i < len(toks); i++ {
		if !isWord(toks[i], "EXCLUDED") {
			continue
		}
		dot := nextCode(toks, i+1)
		if dot < 0 || !isPunct(toks[dot], ".") {
			continue
		}
		col := nextCode(toks, dot+1)
		if col < 0 || (toks[col].kind != tkWord && toks[col].kind != tkQuotedName) {
			continue
		}
		toks = splice(toks, i, col, []token{
			kw("VALUES"), raw("("), toks[col], raw(")"),
		})
	}
	return toks
}

// firstInsertColumn은 `INSERT INTO t (a, b, ...)`에서 첫 컬럼을 꺼낸다.
// DO NOTHING의 무의미 대입 대상으로 쓴다.
func firstInsertColumn(toks []token) string {
	i := nextCode(toks, 0)
	if i < 0 || !isWord(toks[i], "INSERT") {
		return ""
	}
	// INTO와 (수식됐을 수 있는) 테이블 이름을 건너뛰고 컬럼 목록으로 간다.
	for i = nextCode(toks, i+1); i >= 0; i = nextCode(toks, i+1) {
		if isPunct(toks[i], "(") {
			if c := nextCode(toks, i+1); c >= 0 && (toks[c].kind == tkWord || toks[c].kind == tkQuotedName) {
				return toks[c].text
			}
			return ""
		}
		if isWord(toks[i], "VALUES") || isWord(toks[i], "SELECT") {
			return ""
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// 집계 함수의 FILTER (WHERE ...)
// ---------------------------------------------------------------------------

// rewriteAggregateFilter는 `AGG(expr) FILTER (WHERE cond)`를
// `AGG(CASE WHEN (cond) THEN expr END)`로 바꾼다. 이것이 SQL 표준의 FILTER가
// 뜻하는 바 그대로다. COUNT(*)는 COUNT(CASE WHEN cond THEN 1 END)가 된다.
// 상수를 세는 것은 COUNT(*)가 세는 것과 같은 행을 세는 일이고, ELSE가 없어서
// 생기는 NULL이 나머지를 제외한다.
//
// 오른쪽에서 왼쪽으로 훑는다. 앞선 재작성이 뒤쪽 인덱스를 무효화하지 않게
// 하기 위해서다.
func rewriteAggregateFilter(toks []token) []token {
	for i := len(toks) - 1; i >= 0; i-- {
		if !isWord(toks[i], "FILTER") {
			continue
		}
		open := nextCode(toks, i+1)
		if open < 0 || !isPunct(toks[open], "(") {
			continue
		}
		close := matchOpen(toks, open)
		if close < 0 {
			continue
		}
		where := nextCode(toks, open+1)
		if where < 0 || !isWord(toks[where], "WHERE") {
			continue
		}

		aggClose := prevCode(toks, i-1)
		if aggClose < 0 || !isPunct(toks[aggClose], ")") {
			continue
		}
		aggOpen := matchClose(toks, aggClose)
		if aggOpen < 0 {
			continue
		}
		name := prevCode(toks, aggOpen-1)
		if name < 0 || toks[name].kind != tkWord {
			continue
		}

		condStart := nextCode(toks, where+1)
		if condStart < 0 || condStart >= close {
			continue
		}
		cond := trimNoise(append([]token(nil), toks[condStart:close]...))

		args := trimNoise(append([]token(nil), toks[aggOpen+1:aggClose]...))
		if len(args) == 1 && isPunct(args[0], "*") {
			args = []token{num("1")}
		}

		replacement := []token{raw("("), kw("CASE"), space(), kw("WHEN"), space(), raw("(")}
		replacement = append(replacement, cond...)
		replacement = append(replacement, raw(")"), space(), kw("THEN"), space())
		replacement = append(replacement, args...)
		replacement = append(replacement, space(), kw("END"), raw(")"))

		toks = splice(toks, aggOpen, close, replacement)
	}
	return toks
}

// ---------------------------------------------------------------------------
// 식 수준 재작성
// ---------------------------------------------------------------------------

var intervalUnits = map[string]string{
	"microsecond": "MICROSECOND", "microseconds": "MICROSECOND",
	"millisecond": "MICROSECOND", "milliseconds": "MICROSECOND",
	"second": "SECOND", "seconds": "SECOND", "sec": "SECOND", "secs": "SECOND",
	"minute": "MINUTE", "minutes": "MINUTE", "min": "MINUTE", "mins": "MINUTE",
	"hour": "HOUR", "hours": "HOUR",
	"day": "DAY", "days": "DAY",
	"week": "WEEK", "weeks": "WEEK",
	"month": "MONTH", "months": "MONTH",
	"year": "YEAR", "years": "YEAR",
}

var dateTruncFormats = map[string]string{
	"minute": "%Y-%m-%d %H:%i:00",
	"hour":   "%Y-%m-%d %H:00:00",
	"day":    "%Y-%m-%d 00:00:00",
	"month":  "%Y-%m-01 00:00:00",
	"year":   "%Y-01-01 00:00:00",
}

// 두 번째 단어까지가 타입 이름인 경우들. `::double precision`이 두 단어를 모두
// 먹어서 `precision`이 식별자로 남지 않게 한다.
var twoWordCastTypes = map[string]string{
	"character": "varying",
	"double":    "precision",
	"bit":       "varying",
}

func rewriteExpressions(toks []token) ([]token, error) {
	for i := 0; i < len(toks); i++ {
		t := toks[i]

		switch {
		case t.kind == tkPunct && t.text == "::":
			var err error
			toks, i, err = rewriteCast(toks, i)
			if err != nil {
				return nil, err
			}

		case isWord(t, "ILIKE"):
			toks = rewriteILike(toks, i)

		case isWord(t, "INTERVAL"):
			var err error
			toks, err = rewriteInterval(toks, i)
			if err != nil {
				return nil, err
			}

		case isWord(t, "FOR"):
			toks = stripForUpdateOf(toks, i)

		case t.kind == tkWord:
			var err error
			toks, err = rewriteFunctionCall(toks, i)
			if err != nil {
				return nil, err
			}
		}
	}
	return toks, nil
}

// rewriteCast는 Postgres의 `::타입` 캐스트를 제거한다. 제거하면 결과가 달라지는
// 경우에는 변환한다. 스캔을 이어갈 인덱스를 돌려준다.
func rewriteCast(toks []token, i int) ([]token, int, error) {
	typeStart := nextCode(toks, i+1)
	if typeStart < 0 || (toks[typeStart].kind != tkWord && toks[typeStart].kind != tkQuotedName) {
		return toks, i, fmt.Errorf("mariadb: malformed cast after ::")
	}

	typeName := strings.ToLower(toks[typeStart].text)
	typeEnd := typeStart

	if second, ok := twoWordCastTypes[typeName]; ok {
		if n := nextCode(toks, typeEnd+1); n >= 0 && isWord(toks[n], second) {
			typeEnd = n
		}
	}
	// timestamp/time [with|without] time zone
	if typeName == "timestamp" || typeName == "time" {
		if n := nextCode(toks, typeEnd+1); n >= 0 && (isWord(toks[n], "with") || isWord(toks[n], "without")) {
			if z := nextCode(toks, nextCode(toks, n+1)+1); z >= 0 && isWord(toks[z], "zone") {
				typeEnd = z
			}
		}
	}
	// 선택적 정밀도/길이: numeric(12,2), varchar(255).
	if n := nextCode(toks, typeEnd+1); n >= 0 && isPunct(toks[n], "(") {
		if close := matchOpen(toks, n); close >= 0 {
			typeEnd = close
		}
	}
	// 배열 접미사.
	for {
		n := nextCode(toks, typeEnd+1)
		if n < 0 || !isPunct(toks[n], "[") {
			break
		}
		c := nextCode(toks, n+1)
		if c < 0 || !isPunct(toks[c], "]") {
			break
		}
		typeEnd = c
	}

	switch typeName {
	case "interval":
		// 이 코드베이스는 보존 기간을 `($1 || ' days')::interval`로
		// 파라미터화한다. MySQL 계열에는 interval *값*이 없고 INTERVAL n UNIT
		// 문법만 있지만, 여기서 단위는 언제나 리터럴이다. 따라서 수량은 바인딩
		// 파라미터로 남기고 단위만 SQL로 끌어올리면 된다.
		start := operandStart(toks, i-1)
		if start >= 0 {
			if qty, unit, ok := parseConcatInterval(toks, start, i-1); ok {
				replacement := []token{kw("INTERVAL"), space(), qty, space(), kw(unit)}
				toks = splice(toks, start, typeEnd, replacement)
				return toks, start + len(replacement) - 1, nil
			}
		}
		return toks, i, fmt.Errorf(
			"mariadb: cast to interval is unsupported unless written as ($n || ' <unit>')::interval")

	case "date":
		// 이것만은 제거하면 GROUP BY가 조용히 망가진다. 컬럼이 시각 부분을
		// 그대로 유지해서 모든 행이 제각각의 버킷으로 흩어진다.
		start := operandStart(toks, i-1)
		if start < 0 {
			return toks, i, fmt.Errorf("mariadb: cannot find operand for ::date")
		}
		operand := append([]token(nil), toks[start:i]...)
		replacement := append([]token{kw("DATE"), raw("(")}, operand...)
		replacement = append(replacement, raw(")"))
		toks = splice(toks, start, typeEnd, replacement)
		return toks, start + len(replacement) - 1, nil
	}

	// 나머지는 전부 제거한다. MySQL 계열은 어차피 주변 문맥의 타입을 값에
	// 적용하고, 이 코드베이스의 캐스트는 Postgres에게 어느 오버로드를 고를지
	// 알려주려고(text/uuid/inet/jsonb/enum) 존재하는데 MySQL 계열에는 그런
	// 문제가 없다.
	toks = splice(toks, i, typeEnd, nil)
	return toks, i - 1, nil
}

// parseConcatInterval은 toks[start:end]에 걸친 `($n || ' days')`를 인식하고,
// 수량 토큰과 단위 키워드를 돌려준다.
func parseConcatInterval(toks []token, start, end int) (token, string, bool) {
	open := nextCode(toks, start)
	if open < 0 || open > end || !isPunct(toks[open], "(") {
		return token{}, "", false
	}
	qty := nextCode(toks, open+1)
	if qty < 0 || (toks[qty].kind != tkParam && toks[qty].kind != tkNumber) {
		return token{}, "", false
	}
	pipe := nextCode(toks, qty+1)
	if pipe < 0 || !isPunct(toks[pipe], "||") {
		return token{}, "", false
	}
	lit := nextCode(toks, pipe+1)
	if lit < 0 || toks[lit].kind != tkString {
		return token{}, "", false
	}
	closing := nextCode(toks, lit+1)
	if closing < 0 || closing > end || !isPunct(toks[closing], ")") {
		return token{}, "", false
	}

	unit, ok := intervalUnits[strings.ToLower(strings.TrimSpace(strings.Trim(toks[lit].text, "'")))]
	if !ok {
		return token{}, "", false
	}
	return toks[qty], unit, true
}

// rewriteILike는 `a ILIKE b`를 `a LIKE b COLLATE utf8mb4_general_ci`로 바꾼다.
//
// 스키마는 Postgres처럼 `=`가 대소문자를 구분하도록 utf8mb4_bin을 쓰는데, 그러면
// 평범한 LIKE도 대소문자를 구분하게 된다. 패턴 쪽에 대소문자 무시 콜레이션을
// 명시하면 강제성이 가장 높은 콜레이션이 되어 비교 전체가 대소문자 무시로
// 평가된다. 그것이 정확히 ILIKE의 의미다.
func rewriteILike(toks []token, i int) []token {
	toks[i] = kw("LIKE")
	end := operandEnd(toks, i+1)
	if end < 0 {
		return toks
	}
	tail := []token{space(), kw("COLLATE"), space(), kw("utf8mb4_general_ci")}
	return splice(toks, end, end, append([]token{toks[end]}, tail...))
}

// rewriteInterval은 `INTERVAL '7 days'`를 `INTERVAL 7 DAY`로 바꾼다.
func rewriteInterval(toks []token, i int) ([]token, error) {
	lit := nextCode(toks, i+1)
	if lit < 0 || toks[lit].kind != tkString {
		// 이미 대상 엔진 형태인 `INTERVAL 7 DAY`이거나 interval 컬럼 참조다.
		// 할 일이 없다.
		return toks, nil
	}

	body := strings.TrimSpace(strings.Trim(toks[lit].text, "'"))
	fields := strings.Fields(body)
	if len(fields) != 2 {
		return nil, fmt.Errorf("mariadb: cannot translate INTERVAL %s", toks[lit].text)
	}
	qty, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("mariadb: cannot translate INTERVAL %s", toks[lit].text)
	}
	unit, ok := intervalUnits[strings.ToLower(fields[1])]
	if !ok {
		return nil, fmt.Errorf("mariadb: unknown interval unit in %s", toks[lit].text)
	}
	if strings.HasPrefix(strings.ToLower(fields[1]), "milli") {
		qty *= 1000
	}

	return splice(toks, i, lit, []token{
		kw("INTERVAL"), space(),
		num(strconv.Itoa(qty)), space(),
		kw(unit),
	}), nil
}

// stripForUpdateOf는 FOR UPDATE에서 `OF <테이블>` 한정자를 제거한다. MariaDB는
// SKIP LOCKED는 지원하지만 조인 중 어느 테이블을 잠글지 지정하는 것은 지원하지
// 않는다. 어차피 여기 쓰임새는 모두 주도 테이블을 잠근다.
func stripForUpdateOf(toks []token, i int) []token {
	upd := nextCode(toks, i+1)
	if upd < 0 || !isWord(toks[upd], "UPDATE") {
		return toks
	}
	of := nextCode(toks, upd+1)
	if of < 0 || !isWord(toks[of], "OF") {
		return toks
	}
	last := of
	for {
		name := nextCode(toks, last+1)
		if name < 0 || (toks[name].kind != tkWord && toks[name].kind != tkQuotedName) {
			break
		}
		if isWord(toks[name], "SKIP") || isWord(toks[name], "NOWAIT") {
			break
		}
		last = name
		comma := nextCode(toks, last+1)
		if comma < 0 || !isPunct(toks[comma], ",") {
			break
		}
		last = comma
	}
	return splice(toks, of, last, nil)
}

// rewriteFunctionCall은 의미는 같고 표기만 다른 소수의 내장 함수 이름을 바꾼다.
func rewriteFunctionCall(toks []token, i int) ([]token, error) {
	name := strings.ToLower(toks[i].text)

	// CURRENT_TIMESTAMP는 키워드라 괄호가 있어도 없어도 유효하다.
	if name == "current_timestamp" {
		if n := nextCode(toks, i+1); n < 0 || !isPunct(toks[n], "(") {
			toks[i] = kw("CURRENT_TIMESTAMP(6)")
		}
		return toks, nil
	}

	open := nextCode(toks, i+1)
	if open < 0 || !isPunct(toks[open], "(") {
		return toks, nil
	}
	close := matchOpen(toks, open)
	if close < 0 {
		return toks, nil
	}

	// CREATE INDEX의 `col(191)`은 호출이 아니라 접두사 길이다. 그리고 그것이
	// 붙는 컬럼 중 하나의 이름이 말 그대로 `host`인데, 이는 이 규칙들이
	// 재작성하는 함수이기도 하다. 정수 하나만 인자로 받는 호출은 이 함수들
	// 어디에도 없으므로, 둘을 구분하는 믿을 만한 기준이 된다.
	if isIndexPrefix(toks, open, close) {
		return toks, nil
	}

	switch name {
	case "gen_random_uuid", "uuid_generate_v4":
		// UUID()는 버전 4가 아니라 1이다. 둘 다 36자 RFC 4122 문자열이고 이
		// 프로젝트에서 버전을 들여다보는 곳은 없다.
		return splice(toks, i, close, []token{kw("UUID"), raw("("), raw(")")}), nil

	case "random":
		return splice(toks, i, close, []token{kw("RAND"), raw("("), raw(")")}), nil

	case "current_database":
		return splice(toks, i, close, []token{kw("DATABASE"), raw("("), raw(")")}), nil

	case "host":
		// PostgreSQL의 host(inet)은 넷마스크를 뺀 주소를 만든다. MySQL 계열은
		// 그 컬럼들을 VARCHAR(45)로 저장하므로 뗄 마스크가 없고, 호출 결과는
		// 그냥 그 값이다. 호출만 재작성한다. `host`는 로그 테이블의 컬럼
		// 이름이기도 하다.
		arg := trimNoise(toks[open+1 : close])
		if len(arg) == 0 {
			return nil, fmt.Errorf("mariadb: host() with no argument")
		}
		return splice(toks, i, close, arg), nil

	case "split_part":
		// split_part(s, delim, n)과 SUBSTRING_INDEX(s, delim, n)은 n = 1일
		// 때만 일치한다. 그 이상에서는 PostgreSQL이 n번째 필드를 돌려주는 반면
		// MySQL 계열은 앞의 n개 필드를 이어 붙여 돌려준다.
		args := splitTopLevel(toks[open+1 : close])
		if len(args) != 3 {
			return nil, fmt.Errorf("mariadb: split_part expects three arguments")
		}
		nth := trimNoise(args[2])
		if len(nth) != 1 || nth[0].kind != tkNumber || nth[0].text != "1" {
			return nil, fmt.Errorf(
				"mariadb: split_part is only translatable for the first field; use SUBSTRING_INDEX via a dialect branch")
		}
		replacement := []token{kw("SUBSTRING_INDEX"), raw("(")}
		replacement = append(replacement, trimNoise(args[0])...)
		replacement = append(replacement, raw(","), space())
		replacement = append(replacement, trimNoise(args[1])...)
		replacement = append(replacement, raw(","), space(), num("1"), raw(")"))
		return splice(toks, i, close, replacement), nil

	case "now":
		// 컬럼이 DATETIME(6)이다. 정밀도 인자가 없으면 NOW()가 초 단위로
		// 잘려서, 같은 초에 쓰인 행들이 ORDER BY created_at DESC에서 동률이
		// 된다.
		if nextCode(toks, open+1) == close {
			return splice(toks, i, close, []token{kw("NOW"), raw("("), num("6"), raw(")")}), nil
		}
		return toks, nil

	case "date_trunc":
		unitTok := nextCode(toks, open+1)
		if unitTok < 0 || toks[unitTok].kind != tkString {
			return nil, fmt.Errorf("mariadb: date_trunc requires a literal unit")
		}
		unit := strings.ToLower(strings.Trim(toks[unitTok].text, "'"))
		format, ok := dateTruncFormats[unit]
		if !ok {
			return nil, fmt.Errorf("mariadb: unsupported date_trunc unit %q", unit)
		}
		comma := nextCode(toks, unitTok+1)
		if comma < 0 || !isPunct(toks[comma], ",") {
			return nil, fmt.Errorf("mariadb: malformed date_trunc call")
		}
		arg := trimNoise(append([]token(nil), toks[comma+1:close]...))

		// DATE_FORMAT은 문자열을 돌려주는데 호출자들은 결과를 time.Time으로
		// 스캔하므로 DATETIME으로 되돌린다.
		replacement := []token{kw("CAST"), raw("("), kw("DATE_FORMAT"), raw("(")}
		replacement = append(replacement, arg...)
		replacement = append(replacement,
			raw(","), space(), str("'"+format+"'"), raw(")"),
			space(), kw("AS"), space(), kw("DATETIME"), raw(")"))
		return splice(toks, i, close, replacement), nil

	case "extract":
		// EXTRACT(EPOCH FROM x) -> UNIX_TIMESTAMP(x). 나머지 필드 이름은 두
		// 엔진에서 표기가 같다.
		field := nextCode(toks, open+1)
		if field < 0 || !isWord(toks[field], "EPOCH") {
			return toks, nil
		}
		from := nextCode(toks, field+1)
		if from < 0 || !isWord(toks[from], "FROM") {
			return nil, fmt.Errorf("mariadb: malformed EXTRACT call")
		}
		arg := trimNoise(append([]token(nil), toks[from+1:close]...))
		replacement := []token{kw("UNIX_TIMESTAMP"), raw("(")}
		replacement = append(replacement, arg...)
		replacement = append(replacement, raw(")"))
		return splice(toks, i, close, replacement), nil
	}

	return toks, nil
}

// isIndexPrefix는 괄호 안에 정수 리터럴 하나만 들어 있는지 판별한다.
func isIndexPrefix(toks []token, open, close int) bool {
	inner := trimNoise(toks[open+1 : close])
	return len(inner) == 1 && inner[0].kind == tkNumber && !strings.Contains(inner[0].text, ".")
}

// ---------------------------------------------------------------------------
// 방출
// ---------------------------------------------------------------------------

func emit(toks []token) (string, []int, error) {
	var b strings.Builder
	var order []int
	sawParam := false

	for _, t := range toks {
		switch t.kind {
		case tkParam:
			if t.num < 1 {
				return "", nil, fmt.Errorf("mariadb: invalid placeholder %s", t.text)
			}
			sawParam = true
			order = append(order, t.num-1)
			b.WriteByte('?')

		case tkSynth:
			sawParam = true
			order = append(order, ArgSynthesisedUUID)
			b.WriteByte('?')

		case tkString:
			b.WriteString(escapeLiteral(t))

		default:
			b.WriteString(t.text)
		}
	}

	if !sawParam {
		return b.String(), nil, nil
	}
	return b.String(), order, nil
}

// escapeLiteral은 두 엔진의 백슬래시 규칙을 맞춘다.
//
// Postgres는(9.1부터 기본인 standard_conforming_strings가 켜진 상태) '...' 안의
// 백슬래시를 평범한 문자로 다루지만 MySQL 계열은 이스케이프로 다룬다. E'...'로
// 쓰인 리터럴은 이미 MySQL 계열과 같은 의미라 그대로 내보내지만, 평범한
// 리터럴은 백슬래시를 두 배로 늘려야 한다. 그러지 않으면 '\d+' 같은 정규식
// 패턴이 조용히 백슬래시를 잃는다.
func escapeLiteral(t token) string {
	if t.escaped || !strings.Contains(t.text, `\`) {
		return t.text
	}
	return strings.ReplaceAll(t.text, `\`, `\\`)
}

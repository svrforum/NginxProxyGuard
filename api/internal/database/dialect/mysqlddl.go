package dialect

import "strings"

// MySQL에만 적용하는 DDL 재작성.
//
// MariaDB는 MySQL이 받아주지 않는 편의 문법 몇 가지를 허용하고, 생성된 스키마는
// 그것들을 쓴다. 마이그레이션 파일을 멱등하고 재실행 가능하게 만들어 주는 게
// 바로 그 문법들이기 때문이다. 1600줄짜리 스키마를 두 벌 유지하는 대신, 같은
// 파일을 MySQL로 보내는 길에 재작성하고, 그 결과로 나오는 "이미 존재함" 오류는
// 마이그레이션 러너가 정상으로 취급한다. dialect.IsAlreadyApplied 참고.

// ddlIfExistsKeepers는 MySQL이 IF [NOT] EXISTS 절을 허용하는 문장들이다.
// 나머지에서는 이 절을 제거한다.
//
// 문장을 여는 두 단어를 키로 쓴다. `CREATE TABLE IF NOT EXISTS`(허용)와
// `CREATE INDEX IF NOT EXISTS`(거부)를 가르는 게 바로 그 두 단어이기 때문이다.
var ddlIfExistsKeepers = map[[2]string]bool{
	{"CREATE", "TABLE"}:    true,
	{"DROP", "TABLE"}:      true,
	{"CREATE", "DATABASE"}: true,
	{"DROP", "DATABASE"}:   true,
	{"CREATE", "SCHEMA"}:   true,
	{"DROP", "SCHEMA"}:     true,
	{"DROP", "VIEW"}:       true,
}

// stripUnsupportedIfExists는 MySQL이 거부하는 IF NOT EXISTS / IF EXISTS 절을
// 제거한다. CREATE INDEX, ADD COLUMN, ADD ... FOREIGN KEY, DROP INDEX가 대상이다.
//
// 이 절이 문장을 재실행 가능하게 만들어 주므로, 제거하면 두 번째 실행이
// no-op이 아니라 중복 객체 오류가 된다. 마이그레이션 러너가 그 오류들을 성공으로
// 분류하는 이유다.
func stripUnsupportedIfExists(toks []token) []token {
	if keepsIfExists(toks) {
		return toks
	}

	for i := 0; i < len(toks); i++ {
		if !isWord(toks[i], "IF") {
			continue
		}
		next := nextCode(toks, i+1)
		if next < 0 {
			continue
		}

		last := -1
		if isWord(toks[next], "NOT") {
			if e := nextCode(toks, next+1); e >= 0 && isWord(toks[e], "EXISTS") {
				last = e
			}
		} else if isWord(toks[next], "EXISTS") {
			// `IF EXISTS (SELECT ...)`는 DDL 절이 아니라 술어다.
			if p := nextCode(toks, next+1); p >= 0 && isPunct(toks[p], "(") {
				continue
			}
			last = next
		}
		if last < 0 {
			continue
		}

		toks = splice(toks, i, last, nil)
		i--
	}
	return toks
}

// keepsIfExists는 이 문장의 선두 키워드가 MySQL이 해당 절을 허용하는 형태인지
// 판별한다.
func keepsIfExists(toks []token) bool {
	first := nextCode(toks, 0)
	if first < 0 || toks[first].kind != tkWord {
		return false
	}
	second := nextCode(toks, first+1)
	if second < 0 || toks[second].kind != tkWord {
		return false
	}
	key := [2]string{
		strings.ToUpper(toks[first].text),
		strings.ToUpper(toks[second].text),
	}
	return ddlIfExistsKeepers[key]
}

// rewriteTableCompression은 MariaDB의 페이지 압축 속성을 MySQL 것으로 바꾼다.
//
// 하는 일은 같다. 페이지를 압축하고 남는 공간만큼 파일에 hole punch를 한다.
// 다만 MariaDB는 PAGE_COMPRESSED=1에 zlib 레벨을 따로 적고, MySQL은 레벨 선택
// 없이 COMPRESSION='zlib'으로 적는다.
func rewriteTableCompression(toks []token) []token {
	for i := 0; i < len(toks); i++ {
		if toks[i].kind != tkWord {
			continue
		}
		switch strings.ToUpper(toks[i].text) {
		case "PAGE_COMPRESSED":
			end, ok := assignmentEnd(toks, i)
			if !ok {
				continue
			}
			toks = splice(toks, i, end, []token{kw("COMPRESSION"), raw("="), str("'zlib'")})

		case "PAGE_COMPRESSION_LEVEL":
			// MySQL에는 대응하는 설정이 없다. 속성을 그냥 없앤다.
			end, ok := assignmentEnd(toks, i)
			if !ok {
				continue
			}
			toks = splice(toks, i, end, nil)
			i--
		}
	}
	return toks
}

// assignmentEnd는 name에서 시작하는 `NAME = value` 테이블 옵션에서 값의 인덱스를
// 돌려준다.
func assignmentEnd(toks []token, name int) (int, bool) {
	eq := nextCode(toks, name+1)
	if eq < 0 || !isPunct(toks[eq], "=") {
		return 0, false
	}
	value := nextCode(toks, eq+1)
	if value < 0 {
		return 0, false
	}
	return value, true
}

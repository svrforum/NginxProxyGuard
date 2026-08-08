package dialect

import "strings"

// 최소한의 SQL 렉서. translate.go의 재작성기가 코드와 절대 손대면 안 되는 것들
// — 문자열 리터럴, 주석, 인용 식별자, 달러 인용 블록 — 을 구분할 수 있게 하는
// 용도로만 존재한다. 의도적으로 파서가 아니다. 어휘 형태만 인식하고 문장 문법은
// 전혀 모른다.

type tokKind int

const (
	tkSpace tokKind = iota
	tkComment
	tkString     // '...' — escaped는 E'...' 형태로 쓰였는지를 나타낸다
	tkDollarStr  // $tag$ ... $tag$
	tkQuotedName // "..."
	tkWord       // 맨 식별자 또는 키워드
	tkNumber
	tkPunct
	tkParam // $N
	// tkSynth는 호출자가 아니라 드라이버가 채우는 값이다. 방출기가 `?`를 쓰고
	// ArgOrder에 해당 슬롯을 표시한다. MySQL은 INSERT한 행의 기본 키를 돌려줄
	// 수 없으므로, 그 키를 미리 넘겨주는 데 쓴다(returning.go 참고).
	tkSynth
)

type token struct {
	kind tokKind
	text string
	// num은 tkParam 토큰의 순번이다($3 -> 3).
	num int
	// escaped는 Postgres의 E'' 접두사로 쓰인 tkString을 표시한다. 그 안에서
	// 백슬래시는 이스케이프 문자이며, 이는 MySQL 계열의 기본 동작과 정확히 같다.
	// 반면 평범한 '' 리터럴은 두 엔진에서 의미가 반대라 내보낼 때 다시
	// 이스케이프해야 한다.
	escaped bool
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// multiCharOperators는 탐욕적으로 읽는다. 재작성 규칙이 연산자의 첫 글자가
// 아니라 전체를 보고 매칭할 수 있게 하기 위해서다. 긴 것부터 나열한다.
var multiCharOperators = []string{"#>>", "->>", "#>", "->", "::", "||", "<>", "!=", ">=", "<=", ":=", "@>", "<@"}

func lex(sql string) []token {
	var toks []token
	i := 0
	n := len(sql)

	for i < n {
		c := sql[i]

		switch {
		case isSpace(c):
			j := i
			for j < n && isSpace(sql[j]) {
				j++
			}
			toks = append(toks, token{kind: tkSpace, text: sql[i:j]})
			i = j

		case c == '-' && i+1 < n && sql[i+1] == '-':
			j := i
			for j < n && sql[j] != '\n' {
				j++
			}
			toks = append(toks, token{kind: tkComment, text: sql[i:j]})
			i = j

		case c == '/' && i+1 < n && sql[i+1] == '*':
			// Postgres 블록 주석은 중첩된다. /* /* */ */ 구간을 통째로 먹도록
			// 깊이를 추적한다.
			depth := 1
			j := i + 2
			for j < n && depth > 0 {
				if j+1 < n && sql[j] == '/' && sql[j+1] == '*' {
					depth++
					j += 2
					continue
				}
				if j+1 < n && sql[j] == '*' && sql[j+1] == '/' {
					depth--
					j += 2
					continue
				}
				j++
			}
			toks = append(toks, token{kind: tkComment, text: sql[i:j]})
			i = j

		case (c == 'E' || c == 'e') && i+1 < n && sql[i+1] == '\'':
			body, next := scanSingleQuoted(sql, i+1)
			toks = append(toks, token{kind: tkString, text: body, escaped: true})
			i = next

		case c == '\'':
			body, next := scanSingleQuoted(sql, i)
			toks = append(toks, token{kind: tkString, text: body})
			i = next

		case c == '"':
			j := i + 1
			for j < n {
				if sql[j] == '"' {
					if j+1 < n && sql[j+1] == '"' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			toks = append(toks, token{kind: tkQuotedName, text: sql[i:j]})
			i = j

		case c == '$':
			if tag, end, ok := scanDollarQuote(sql, i); ok {
				toks = append(toks, token{kind: tkDollarStr, text: tag})
				i = end
				continue
			}
			if i+1 < n && isDigit(sql[i+1]) {
				j := i + 1
				num := 0
				for j < n && isDigit(sql[j]) {
					num = num*10 + int(sql[j]-'0')
					j++
				}
				toks = append(toks, token{kind: tkParam, text: sql[i:j], num: num})
				i = j
				continue
			}
			toks = append(toks, token{kind: tkPunct, text: "$"})
			i++

		case isIdentStart(c):
			j := i
			for j < n && isIdentPart(sql[j]) {
				j++
			}
			toks = append(toks, token{kind: tkWord, text: sql[i:j]})
			i = j

		case isDigit(c) || (c == '.' && i+1 < n && isDigit(sql[i+1])):
			j := i
			for j < n && (isDigit(sql[j]) || sql[j] == '.') {
				j++
			}
			toks = append(toks, token{kind: tkNumber, text: sql[i:j]})
			i = j

		default:
			matched := false
			for _, op := range multiCharOperators {
				if strings.HasPrefix(sql[i:], op) {
					toks = append(toks, token{kind: tkPunct, text: op})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				toks = append(toks, token{kind: tkPunct, text: string(c)})
				i++
			}
		}
	}

	return toks
}

// scanSingleQuoted는 start에서 시작하는 '...' 리터럴을 읽어 양쪽 따옴표를
// 포함한 구간을 돌려준다. 인정하는 이스케이프는 작은따옴표 두 개뿐이며, 이는
// standard_conforming_strings가 켜진 Postgres와 일치한다. 그쪽에서 백슬래시는
// 평범한 문자이고, MySQL 계열용으로는 나중에 다시 이스케이프한다.
func scanSingleQuoted(sql string, start int) (string, int) {
	n := len(sql)
	j := start + 1
	for j < n {
		if sql[j] == '\\' {
			// E'' 리터럴 안에서만 의미가 있지만, 평범한 리터럴에서 다음
			// 바이트를 건너뛰어도 무해하다. 닫는 따옴표 앞의 홀로 있는
			// 백슬래시는 어느 엔진에서도 올바른 SQL이 아니다.
			j += 2
			continue
		}
		if sql[j] == '\'' {
			if j+1 < n && sql[j+1] == '\'' {
				j += 2
				continue
			}
			j++
			break
		}
		j++
	}
	if j > n {
		j = n
	}
	return sql[start:j], j
}

// scanDollarQuote는 $$...$$와 $tag$...$tag$ 본문(PL/pgSQL DO 블록)을 인식한다.
// 재작성기가 통째로 불투명하게 다루도록 구간 전체를 돌려준다.
func scanDollarQuote(sql string, start int) (string, int, bool) {
	n := len(sql)
	j := start + 1
	for j < n && isIdentPart(sql[j]) && sql[j] != '$' {
		j++
	}
	if j >= n || sql[j] != '$' {
		return "", 0, false
	}
	tag := sql[start : j+1]
	end := strings.Index(sql[j+1:], tag)
	if end < 0 {
		return sql[start:], n, true
	}
	stop := j + 1 + end + len(tag)
	return sql[start:stop], stop, true
}

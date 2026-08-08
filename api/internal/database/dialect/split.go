package dialect

import "strings"

// SplitStatements는 SQL 스크립트를 최상위 세미콜론 기준으로 개별 문장으로 나눈다.
// 문자열 리터럴, 주석, 달러 인용 블록, 괄호 안의 세미콜론은 무시한다.
//
// MySQL 계열 경로에 이 함수가 필요한 이유는 두 가지다. 번역기가 한 번에 한
// 문장씩만 다루고(ON CONFLICT와 RETURNING 규칙이 단일 문장의 형태를 전제로
// 한다), 서비스용 커넥션은 의도적으로 다중 문장 질의를 켜두지 않기 때문이다.
// 서버에 맡기지 않고 Go에서 나누면 두 성질이 모두 유지된다.
//
// 빈 문장(`;;`이나 끝에 남은 세미콜론)은 버린다.
func SplitStatements(script string) []string {
	toks := lex(script)

	var (
		out     []string
		current strings.Builder
		depth   int
		hasCode bool
	)

	// 주석만 들어 있는 덩어리는 문장이 아니므로 서버로 보내면 안 된다.
	// 생성된 마이그레이션 파일에는 "-- skipped (...)" 메모가 잔뜩 들어 있다.
	flush := func() {
		if s := strings.TrimSpace(current.String()); s != "" && hasCode {
			out = append(out, s)
		}
		current.Reset()
		hasCode = false
	}

	for _, t := range toks {
		if t.kind != tkSpace && t.kind != tkComment {
			hasCode = true
		}
		if t.kind == tkPunct {
			switch t.text {
			case "(":
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			case ";":
				if depth == 0 {
					flush()
					continue
				}
			}
		}
		current.WriteString(t.text)
	}
	flush()

	return out
}

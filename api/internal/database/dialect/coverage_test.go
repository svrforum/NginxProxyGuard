package dialect

import (
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestEveryQueryTranslates는 internal/ 아래의 SQL 리터럴을 훑으며 번역기가
// 전부 받아들이는지 확인한다.
//
// MySQL 계열 지원이 썩지 않게 지켜 주는 장치다. 설계 전체가 "리포지토리는
// PostgreSQL을 쓰고 드라이버가 재작성한다"에 기대고 있으므로, 번역 불가 구문을
// 쓰는 새 질의는 어떤 PostgreSQL 테스트로도 잡히지 않는 장애가 된다. 그런 질의를
// 추가하면 작성하는 그 순간 여기서 실패한다.
//
// 정말로 기계적 번역이 불가능한 질의는 dialect.ActiveIsMySQLFamily() 분기 뒤에
// 대응 구현과 함께 두고, 그 파일을 아래 postgresOnlyBranches에 올린다.
func TestEveryQueryTranslates(t *testing.T) {
	root := repositoryRoot(t)

	var failures []string
	for _, path := range goFilesUnder(t, root) {
		rel, _ := filepath.Rel(root, path)
		if postgresOnlyBranches[filepath.ToSlash(rel)] || notSQL[filepath.ToSlash(rel)] {
			continue
		}
		for _, lit := range sqlLiterals(t, path) {
			if _, err := Translate(lit.text); err != nil {
				failures = append(failures, fmt.Sprintf("%s:%d: %v\n    %s",
					filepath.ToSlash(rel), lit.line, err, snippet(lit.text)))
			}
		}
	}

	sort.Strings(failures)
	if len(failures) > 0 {
		t.Fatalf("%d SQL literal(s) cannot be translated for MariaDB:\n\n%s",
			len(failures), strings.Join(failures, "\n"))
	}
}

// postgresOnlyBranches는 호출부가 먼저 dialect를 확인하고 다른 경로를 타기
// 때문에 MySQL 계열에서는 도달하지 않는 SQL을 담은 파일들이다. 각 항목에 대응
// 구현을 적어 두어 짝이 눈에 보이게 한다.
var postgresOnlyBranches = map[string]bool{
	// TimescaleDB 전환, 하이퍼테이블 복구, 레거시 로그 백필.
	// MySQL 계열은 대신 migration_mysqlfamily.go를 실행한다.
	"database/migration.go": true,

	// PL/pgSQL 파티션 헬퍼와 pg_class 통계.
	// MySQL 계열: scheduler/partition_mariadb.go.
	"scheduler/partition.go": true,

	// 시간별 국가 맵을 jsonb_each_text로 집계하는 부분.
	// MySQL 계열: DashboardRepository.getTopCountriesMariaDB.
	"repository/dashboard.go": true,

	// UNNEST 기반 도메인 교집합.
	// MySQL 계열: ProxyHostRepository.checkDomainExistsMariaDB.
	"repository/proxy_host_queries.go": true,

	// TimescaleDB 압축 지표.
	// MySQL 계열: GetHypertableStats가 아무것도 돌려주지 않는다(하이퍼테이블이
	// 없다).
	"repository/health_detailed.go": true,

	// PL/pgSQL 보존 헬퍼인 drop_old_partitions().
	// MySQL 계열: 여기서는 행 단위 DELETE를 하고, 파티션 단위 보존은
	// scheduler/partition_mariadb.go가 맡는다.
	"repository/log_cleanup.go": true,
}

// notSQL은 아래 휴리스틱에만 SQL처럼 보이는 리터럴을 가진 파일들이다.
// `::`와 "select"라는 단어가 들어 있는 nginx 설정 템플릿이다.
var notSQL = map[string]bool{
	"nginx/main_config.go":           true,
	"nginx/default_server_config.go": true,
}

type sqlLiteral struct {
	text string
	line int
}

// looksLikeSQL은 일부러 느슨하다. 오탐은 허용 목록 한 줄이면 되지만, 미탐은
// 운영 장애가 된다.
var looksLikeSQL = regexp.MustCompile(`(?is)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|WITH)\b`)

func sqlLiterals(t *testing.T, path string) []sqlLiteral {
	t.Helper()
	fset := gotoken.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil
	}

	var out []sqlLiteral
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != gotoken.STRING {
			return true
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			text = strings.Trim(lit.Value, "`")
		}
		if len(text) < 25 || !looksLikeSQL.MatchString(text) {
			return true
		}
		out = append(out, sqlLiteral{text: text, line: fset.Position(lit.Pos()).Line})
		return true
	})
	return out
}

func goFilesUnder(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		// 테스트 파일에는 일부러 번역 불가한 예시가 들어 있고, 이 패키지의
		// 오류 메시지 자체가 거부하는 문법을 인용한다.
		if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/database/dialect/") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

// repositoryRoot는 이 패키지 위치를 기준으로 internal/을 찾는다.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	internal := filepath.Join(root, "internal")
	if _, err := os.Stat(internal); err != nil {
		t.Skipf("cannot locate internal/ from the test's working directory: %v", err)
	}
	return internal
}

func snippet(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

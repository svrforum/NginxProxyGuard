// dialect 패키지는 NginxProxyGuard가 "지금 어느 SQL 백엔드와 이야기하는가"를
// 신경 써야 하는 지점을 한곳에 모은다.
//
// 지원 백엔드는 셋이다. PostgreSQL/TimescaleDB, MariaDB, MySQL.
//
// 이 프로젝트는 PostgreSQL을 전제로 작성됐고, 2만 줄이 넘는 리포지토리 코드가
// Postgres를 모국어로 쓴다. $N 플레이스홀더, ON CONFLICT, RETURNING, text[]
// 컬럼, jsonb, COUNT(*) FILTER (WHERE ...) 같은 것들이다. 리포지토리 63개
// 파일을 갈라내는 대신, 나머지 두 엔진은 한 층 아래에서 지원한다. 각 문장을
// 서버로 보내는 길에 재작성하는 database/sql 드라이버다(translate.go와
// driver.go 참고). 리포지토리는 계속 Postgres SQL을 쓰고 dialect를 모른 채로
// 남는다. 기계적 대응물이 없는 소수의 구문(배열 연산자, jsonb 함수, COPY)만
// Kind로 분기한다.
//
// MariaDB와 MySQL은 생성된 스키마 한 벌을 포함해 거의 모든 것을 공유한다.
// 갈라지는 지점 — MySQL은 RETURNING 절이 없고, 대부분의 DDL에서 IF NOT EXISTS를
// 거부하며, 페이지 압축 표기가 다르다 — 은 번역기가 처리한다. 그리고 반대편에
// 어떤 서버가 있는지는 접속 URL의 스킴을 믿는 대신 서버에 직접 물어서 정한다.
package dialect

import (
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

// Kind는 지원하는 데이터베이스 백엔드를 식별한다.
type Kind string

const (
	Postgres Kind = "postgres"
	MariaDB  Kind = "mariadb"
	MySQL    Kind = "mysql"
)

func (k Kind) String() string { return string(k) }

// IsMySQLFamily는 이 백엔드가 MySQL 프로토콜과 방언을 쓰는지 — 즉 MariaDB이거나
// MySQL인지 — 판별한다.
//
// 리포지토리가 분기할 때 쓰는 기준이다. 둘은 충분히 가까워서 배열과 JSON 처리,
// information_schema 조회, ILIKE 흉내내기를 한 번만 작성해도 양쪽에서 동작한다.
// 진짜로 다른 부분 — RETURNING 지원 여부, DDL의 IF NOT EXISTS, 압축 문법 — 은
// 호출부가 아니라 번역기가 구분한다(translate.go 참고).
func (k Kind) IsMySQLFamily() bool { return k == MariaDB || k == MySQL }

// Detect는 DATABASE_URL이 가리키는 백엔드를 판별한다.
//
// 알아보지 못한 값은 전부 Postgres로 본다. 이 프로젝트는 지금까지 줄곧
// Postgres 전용이었으므로, 파싱되지 않거나 낯선 URL은 MySQL 계열 지원이 생기기
// 전과 정확히 같게 동작해야 한다.
func Detect(databaseURL string) Kind {
	scheme, _, hasScheme := strings.Cut(databaseURL, "://")
	if !hasScheme {
		// go-sql-driver의 순수 DSN에는 스킴이 아예 없다
		// ("user:pass@tcp(host:3306)/db"). 운영자가 네이티브 DSN을 그대로
		// DATABASE_URL에 붙여넣을 수 있도록 네트워크 접두사를 인식한다.
		if strings.Contains(databaseURL, "@tcp(") || strings.Contains(databaseURL, "@unix(") {
			return MariaDB
		}
		return Postgres
	}
	switch strings.ToLower(scheme) {
	case "mysql", "mariadb":
		// 두 스킴 모두 같은 드라이버와 같은 DSN으로 이어진다. 실제로 어느
		// 서버가 떠 있는지는 접속 후 DetectFlavor가 정한다. 접속 URL의 스킴은
		// 선언이 아니라 습관이고, 잘못 적었다고 동작이 달라져서는 안 된다.
		return MariaDB
	default:
		return Postgres
	}
}

// DetectFlavor는 서버에 MySQL 계열 두 엔진 중 어느 쪽인지 직접 묻는다.
//
// MariaDB는 버전 문자열에 이름을 넣는다("11.4.12-MariaDB-ubu2404"). MySQL은
// 넣지 않는다("8.4.11"). 이를 구분해야 하는 이유는 MySQL이 RETURNING 절을
// 지원하지 않고, 대부분의 DDL에서 IF NOT EXISTS를 거부하며, 페이지 압축 표기가
// 다르기 때문이다.
//
// 버전을 읽지 못하면 둘 중 더 관대한 쪽인 MariaDB로 본다. MariaDB만 허용하는
// 구문은 어차피 전부 흉내내기가 준비돼 있으므로 이쪽으로 잘못 짚으면 효율만
// 조금 손해지만, 반대로 짚으면 아무 이유 없이 MySQL 모양의 SQL을 MariaDB
// 서버로 보내게 된다.
func DetectFlavor(queryRow func(string) *sql.Row) Kind {
	var version string
	if err := queryRow("SELECT VERSION()").Scan(&version); err != nil {
		return MariaDB
	}
	if strings.Contains(strings.ToLower(version), "mariadb") {
		return MariaDB
	}
	return MySQL
}

// DriverName은 이 백엔드에 대해 열어야 할 database/sql 드라이버 이름을 돌려준다.
// MySQL 계열의 이름은 driver.go에 등록된 번역 래퍼이며, 맨 "mysql" 드라이버가
// 아니다. 그쪽을 직접 열면 날것의 Postgres SQL이 서버로 나간다.
func DriverName(k Kind) string {
	if k.IsMySQLFamily() {
		return TranslatingDriverName
	}
	return "postgres"
}

// forcedMySQLParams는 선호가 아니라 필수인 DSN 파라미터들이다. 각각이
// Postgres와의 동작 차이를 메우므로, 운영자가 DATABASE_URL에 적어 넣은 값보다
// 우선한다. 여기서 "친절하게" 값을 존중해 주면 조용한 데이터 손상이나, 일부
// 행에서만 실패하는 질의로 나타난다.
var forcedMySQLParams = map[string]string{
	// DATETIME 컬럼을 time.Time으로 스캔한다. 리포지토리들은 time.Time 필드로
	// 곧바로 스캔하므로, 이게 없으면 []byte를 받아 실패한다.
	"parseTime": "true",

	// 모든 DATETIME을 UTC로 읽고 쓴다. Postgres 컬럼은
	// `timestamp with time zone`이고 앱은 UTC로 정규화한다. MySQL 계열의
	// DATETIME에는 시간대가 없으므로 드라이버가 대신 정해 줘야 한다. 아래의
	// 세션 time_zone과 합쳐지면, 컨테이너 TZ가 UTC가 아니어도 NOW()와 Go 쪽
	// 타임스탬프가 어긋나지 않는다.
	"loc": "UTC",

	// UPDATE가 (실제로 바뀐 행이 아니라) 매칭된 행 수를 보고하게 한다.
	// Postgres는 WHERE에 걸린 모든 행을 세지만, MySQL은 기본적으로 값이 실제로
	// 바뀐 행만 센다. 리포지토리들은 RowsAffected()==0을 "없음"으로 취급하므로,
	// 이게 없으면 같은 값을 다시 쓰는 멱등 업데이트가 404로 잘못 보고된다.
	"clientFoundRows": "true",

	// 전체 utf8mb4, 바이너리 콜레이션. Postgres의 텍스트 비교는 대소문자를
	// 구분하지만 MySQL 계열의 기본 *_general_ci 콜레이션은 구분하지 않는다.
	// 그대로 두면 users.username이나 proxy_hosts 도메인 등의 유니크 인덱스에서
	// "Admin"과 "admin"이 조용히 같은 값이 된다. 대소문자 무시 매칭은 Postgres가
	// 원래 요구한 자리에서만, ILIKE를 명시적 콜레이션이 붙은 LIKE로 번역하는
	// 방식으로 되살린다(translate.go 참고).
	"collation": "utf8mb4_bin",
}

// sessionSQLMode는 모든 커넥션에 적용된다.
//
//   - ANSI_QUOTES는 "따옴표"로 감싼 구간을 문자열 리터럴이 아니라 식별자로
//     만든다. 덕분에 예약어인 컬럼명을 인용한 Postgres SQL — 가장 눈에 띄는
//     것은 로그 테이블의 "timestamp" 컬럼 — 이 그대로 파싱된다.
//   - PIPES_AS_CONCAT은 ||를 논리 OR가 아니라 문자열 연결로 되돌린다. 없으면
//     ||로 문자열을 만드는 질의가 0/1을 돌려준다.
//   - STRICT_TRANS_TABLES는 조용한 잘림과 범위 초과 변환을 오류로 만든다.
//     쓰기 시 값을 훼손하지 않는 Postgres의 태도와 맞춘다.
//   - NO_ENGINE_SUBSTITUTION은 스키마가 지정한 스토리지 엔진을 몰래 바꾸는 대신
//     소리 내어 실패하게 한다.
//
// ONLY_FULL_GROUP_BY는 의도적으로 뺐다. 대시보드 집계 몇 개가 Postgres의 더
// 느슨한 함수 종속성 분석에 기대고 있어 거부당한다.
const sessionSQLMode = "ANSI_QUOTES,PIPES_AS_CONCAT,STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION"

// MySQLDSN은 DATABASE_URL을 go-sql-driver가 기대하는 DSN 형식으로 바꾸고 위에
// 나열한 파라미터를 강제한다.
//
// 이미 네이티브 DSN인 값(스킴 없음)도 같은 파라미터 강제를 거쳐 통과하므로 두
// 표기가 동일하게 동작한다.
func MySQLDSN(databaseURL string, multiStatements bool) (string, error) {
	base, params, err := splitMySQLDSN(databaseURL)
	if err != nil {
		return "", err
	}

	translatePostgresParams(params)

	for k, v := range forcedMySQLParams {
		params.Set(k, v)
	}
	// 따옴표를 씌우는 이유: 드라이버는 알아보지 못한 파라미터를 핸드셰이크 중
	// `SET <name>=<value>` 형태로 그대로 재생하는데, 쉼표로 나열한 맨 목록은
	// 거기서 올바른 값이 아니다.
	params.Set("sql_mode", "'"+sessionSQLMode+"'")
	params.Set("time_zone", "'+00:00'")

	// 다중 문장 권한은 마이그레이션 커넥션에만 준다. 초기 스키마와 몇몇
	// 업그레이드 단계가 문장 덩어리로 들어오기 때문이다. 서비스용 풀은 단일
	// 문장으로 유지해서, 만에 하나 질의에 인젝션이 생겨도 두 번째 문장을 이어
	// 붙일 수 없게 한다.
	if multiStatements {
		params.Set("multiStatements", "true")
	} else {
		params.Del("multiStatements")
	}

	if enc := params.Encode(); enc != "" {
		return base + "?" + enc, nil
	}
	return base, nil
}

// sslmodeToTLS는 libpq의 sslmode를 go-sql-driver의 tls 파라미터로 대응시킨다.
//
// "prefer"와 "allow"에는 정확한 대응물이 없다. MySQL 드라이버는 TLS를 요구하거나
// 쓰지 않거나 둘 중 하나다. 그래서 인증서 검증 없이 기회주의적으로 암호화하는
// 쪽으로 보낸다. 둘 중에는 이쪽이 더 가깝다.
var sslmodeToTLS = map[string]string{
	"disable":     "false",
	"allow":       "skip-verify",
	"prefer":      "skip-verify",
	"require":     "skip-verify",
	"verify-ca":   "true",
	"verify-full": "true",
}

// postgresOnlyParams는 MySQL 계열에서 아무 의미가 없는 libpq 접속
// 파라미터들이다.
//
// 무시가 아니라 제거해야 한다. go-sql-driver는 알아보지 못한 파라미터를
// 핸드셰이크 중 `SET <name>=<value>`로 재생하므로, 하나라도 남아 있으면
// "Unknown system variable"로 접속 자체가 실패한다. 잘 돌아가던 PostgreSQL URL을
// 복사해 스킴만 바꾸는 것이 MySQL 계열을 시험해 보는 가장 자연스러운 방법인데,
// 그대로 두면 진짜 원인을 전혀 알려주지 않는 오류로 실패한다.
var postgresOnlyParams = []string{
	"search_path", "application_name", "fallback_application_name",
	"target_session_attrs", "options", "connect_timeout", "client_encoding",
	"sslcert", "sslkey", "sslrootcert", "sslcrl", "sslpassword", "channel_binding",
	"gssencmode", "krbsrvname", "service", "passfile", "requiressl",
}

// translatePostgresParams는 옮겨갈 수 있는 것은 바꿔 적고 나머지는 버린다.
func translatePostgresParams(params url.Values) {
	if mode := params.Get("sslmode"); mode != "" {
		params.Del("sslmode")
		// 운영자가 명시한 tls=가 우선한다. sslmode는 보조 수단일 뿐이다.
		if params.Get("tls") == "" {
			if tls, ok := sslmodeToTLS[strings.ToLower(mode)]; ok {
				params.Set("tls", tls)
			}
		}
	}

	// libpq는 접속 타임아웃을 초 단위로 적지만, go-sql-driver는 다른 이름으로
	// Go duration을 원한다.
	if timeout := params.Get("connect_timeout"); timeout != "" && params.Get("timeout") == "" {
		if _, err := strconv.Atoi(timeout); err == nil {
			params.Set("timeout", timeout+"s")
		}
	}

	for _, name := range postgresOnlyParams {
		params.Del(name)
	}
}

// splitMySQLDSN은 두 표기 중 어느 쪽이든 go-sql-driver의
// "user:pass@proto(addr)/dbname" 접두사와 질의 값들로 정규화한다.
func splitMySQLDSN(databaseURL string) (string, url.Values, error) {
	if !strings.Contains(databaseURL, "://") {
		base, rawQuery, _ := strings.Cut(databaseURL, "?")
		params, err := url.ParseQuery(rawQuery)
		if err != nil {
			return "", nil, fmt.Errorf("invalid DSN parameters: %w", err)
		}
		if base == "" {
			return "", nil, fmt.Errorf("empty database DSN")
		}
		return base, params, nil
	}

	u, err := url.Parse(databaseURL)
	if err != nil {
		return "", nil, fmt.Errorf("invalid DATABASE_URL: %w", err)
	}

	var creds string
	if u.User != nil {
		user := u.User.Username()
		if pass, ok := u.User.Password(); ok {
			creds = user + ":" + pass + "@"
		} else if user != "" {
			creds = user + "@"
		}
	}

	// "mariadb://user:pw@db/npg" 형태가 동작하도록 기본 포트를 채운다.
	// 드라이버는 tcp(...) 안에 명시적인 주소를 요구한다.
	host := u.Host
	if host != "" && !strings.Contains(host, ":") {
		host += ":3306"
	}

	network := "tcp(" + host + ")"
	if host == "" {
		return "", nil, fmt.Errorf("DATABASE_URL is missing a host")
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" {
		return "", nil, fmt.Errorf("DATABASE_URL is missing a database name")
	}

	return creds + network + "/" + dbName, u.Query(), nil
}

// Redact는 로그에 남길 수 있도록 데이터베이스 URL에서 비밀번호를 지운다.
func Redact(databaseURL string) string {
	u, err := url.Parse(databaseURL)
	if err != nil || u.User == nil {
		return "(redacted)"
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		u.User = url.UserPassword(u.User.Username(), "****")
	}
	return u.String()
}

// ---------------------------------------------------------------------------
// 프로세스 전역 dialect
// ---------------------------------------------------------------------------

// active는 이 프로세스가 이야기하는 백엔드다. 커넥션이 열리는 즉시
// database.New()가 공표한다.
//
// 패키지 수준 값이 맞는 형태인 이유는 이 값이 실제로 프로세스 전역이기
// 때문이다. NginxProxyGuard는 데이터베이스를 정확히 하나만 연다. 이게 필요한
// 이유는 일부 리포지토리가 dialect를 들고 다니는 래퍼가 아니라 맨 *sql.DB로
// 생성되고, 그중 몇몇 질의 — 배열과 JSON 컬럼을 건드리는 것들 — 는 두 백엔드가
// 모두 받아주는 단일 표기가 없기 때문이다. 나머지는 전부 번역 드라이버를 통해
// dialect 비의존으로 남는다.
var active atomic.Value

// SetActive는 이 프로세스 데이터베이스 커넥션의 dialect를 공표한다.
//
// 번역 결과는 문장 텍스트를 키로 캐시되고 재작성 규칙은 플레이버에 따라
// 달라지므로, 플레이버가 바뀔 때마다 캐시를 버린다. 실제로는 기동 시 두 번 —
// 한 번은 URL 스킴에서, 한 번은 서버 버전에서 — 일어나고 그 뒤로는 없다.
func SetActive(k Kind) {
	previous, _ := active.Load().(Kind)
	active.Store(k)
	if previous != k {
		clearTranslationCache()
	}
}

// Active는 SetActive가 공표한 dialect를 돌려준다. 커넥션이 열리기 전에는
// Postgres가 기본값이다.
func Active() Kind {
	if k, ok := active.Load().(Kind); ok {
		return k
	}
	return Postgres
}

// ActiveIsMySQLFamily는 리포지토리가 분기할 때 쓰는 축약형이다.
func ActiveIsMySQLFamily() bool { return Active().IsMySQLFamily() }

// targetFlavor는 재작성 규칙이 겨냥해야 할 플레이버다.
//
// 번역은 MySQL 계열 커넥션에서만 돌아간다. 따라서 active dialect가
// Postgres이거나 설정되지 않았다는 것은 아직 플레이버가 공표되기 전이라는
// 뜻이다. 버전 조회 자체를 수행하는 중이거나, 유닛 테스트 안이다. 그 상황의
// 기본값으로 MariaDB가 맞는 이유는 DetectFlavor가 그것을 쓰는 이유와 같다.
func targetFlavor() Kind {
	if Active() == MySQL {
		return MySQL
	}
	return MariaDB
}

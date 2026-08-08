package dialect

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// TranslatingDriverName은 NginxProxyGuard가 MariaDB와 MySQL에 대해 여는
// database/sql 드라이버다. go-sql-driver/mysql을 감싸고, 지나가는 모든 문장을
// PostgreSQL 문법에서 재작성한다(translate.go 참고).
//
// 재작성을 리포지토리마다가 아니라 드라이버 경계에서 하는 것이 이 작업을
// 감당 가능하게 만든다. 래퍼가 database/sql 아래에 있으므로 준비된 문장,
// 트랜잭션, 단발성 질의가 모두 같은 경로로 처리되고, 리포지토리 63개 파일은
// Postgres 방언 질의문 한 벌을 그대로 유지한다.
const TranslatingDriverName = "npg-mysql"

func init() {
	sql.Register(TranslatingDriverName, translatingDriver{})
}

// ---------------------------------------------------------------------------
// 번역 캐시
//
// 리포지토리는 같은 문장을 끊임없이 다시 발행하고, 상당수는 동적 필터 때문에
// fmt.Sprintf로 조립된다. 그래서 키 공간은 넓지만 반복이 심하다. 뮤텍스로
// 보호하는 평범한 맵이면 충분하다. 항목별로 쫓아내지 않고 통째로 비우는 이유는
// 워킹셋이 작아서, 가끔 한 번 비우는 비용이 질의마다 최근성을 추적하는 비용보다
// 싸기 때문이다.
// ---------------------------------------------------------------------------

const translationCacheLimit = 4096

type cacheEntry struct {
	stmt *Statement
	err  error
}

var (
	cacheMu sync.RWMutex
	cache   = map[string]cacheEntry{}
)

// clearTranslationCache는 캐시된 재작성 결과를 전부 버린다. 재작성 규칙이
// MariaDB와 MySQL에서 다르므로, active 플레이버가 바뀔 때 호출된다.
func clearTranslationCache() {
	cacheMu.Lock()
	cache = map[string]cacheEntry{}
	cacheMu.Unlock()
}

func translateCached(query string) (*Statement, error) {
	cacheMu.RLock()
	hit, ok := cache[query]
	cacheMu.RUnlock()
	if ok {
		return hit.stmt, hit.err
	}

	translated, err := Translate(query)

	cacheMu.Lock()
	if len(cache) >= translationCacheLimit {
		cache = make(map[string]cacheEntry, translationCacheLimit)
	}
	cache[query] = cacheEntry{stmt: translated, err: err}
	cacheMu.Unlock()

	return translated, err
}

// reorder는 호출자의 인자를 재작성된 문장이 기대하는 위치로 대응시킨다.
// Postgres 플레이스홀더는 순번 기반이고 반복될 수 있으므로, 같은 인자가 여러
// `?` 슬롯에 들어갈 수 있다.
//
// synthesised는 번역기가 ArgSynthesisedUUID로 표시한 슬롯에 넣을 값이다. 실행
// 한 번당 하나이며, 쓰기와 재조회가 같은 행을 가리키도록 둘이 공유한다.
func reorder(args []driver.NamedValue, order []int, synthesised string) ([]driver.NamedValue, error) {
	if order == nil {
		return args, nil
	}
	out := make([]driver.NamedValue, len(order))
	for i, src := range order {
		if src == ArgSynthesisedUUID {
			out[i] = driver.NamedValue{Ordinal: i + 1, Value: synthesised}
			continue
		}
		if src < 0 || src >= len(args) {
			return nil, errors.New("dialect: translated statement references a missing argument")
		}
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: args[src].Value}
	}
	return out, nil
}

// needsSynthesis는 계획의 어느 단계든 드라이버가 만든 값을 기대하는지
// 판별한다.
func needsSynthesis(s *Statement) bool {
	for ; s != nil; s = s.FollowUp {
		for _, src := range s.ArgOrder {
			if src == ArgSynthesisedUUID {
				return true
			}
		}
	}
	return false
}

// inputCount는 *호출자*가 넘기는 인자 개수다. 재작성된 문장의 `?` 개수와는
// 다르다. 두 번 쓰인 Postgres 플레이스홀더는 인자 하나에서 바인딩되는 `?` 두
// 개가 된다. database/sql은 순열을 적용하기 전에 호출자의 슬라이스를
// NumInput()과 대조하므로, 순열 이전의 개수를 알려줘야 한다. 2단계 계획에서는
// 호출자가 한 쌍에 대해 인자 목록 하나만 넘기므로 두 단계를 아울러 센다.
func inputCount(s *Statement) int {
	highest := -1
	for ; s != nil; s = s.FollowUp {
		for _, src := range s.ArgOrder {
			// 합성 슬롯은 드라이버가 채우는 것이지 호출자가 넘기는 것이
			// 아니다.
			if src != ArgSynthesisedUUID && src > highest {
				highest = src
			}
		}
	}
	return highest + 1
}

// ---------------------------------------------------------------------------
// 드라이버 / 커넥터
// ---------------------------------------------------------------------------

type translatingDriver struct{}

func (translatingDriver) Open(dsn string) (driver.Conn, error) {
	inner, err := mysql.MySQLDriver{}.Open(dsn)
	if err != nil {
		return nil, err
	}
	return &conn{inner: inner}, nil
}

func (d translatingDriver) OpenConnector(dsn string) (driver.Connector, error) {
	inner, err := mysql.MySQLDriver{}.OpenConnector(dsn)
	if err != nil {
		return nil, err
	}
	return &connector{inner: inner, drv: d}, nil
}

type connector struct {
	inner driver.Connector
	drv   translatingDriver
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	inner, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &conn{inner: inner}, nil
}

func (c *connector) Driver() driver.Driver { return c.drv }

// ---------------------------------------------------------------------------
// 커넥션
// ---------------------------------------------------------------------------

type conn struct {
	inner driver.Conn
}

func (c *conn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *conn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	plan, err := translateCached(query)
	if err != nil {
		return nil, err
	}
	inner, err := c.prepareTranslated(ctx, plan.SQL)
	if err != nil {
		return nil, err
	}
	return &stmt{owner: c, inner: inner, plan: plan}, nil
}

// prepareTranslated는 이미 재작성된 SQL을 번역기를 거치지 않고 준비한다.
// 2단계 계획의 두 번째 단계에 쓴다.
func (c *conn) prepareTranslated(ctx context.Context, sql string) (driver.Stmt, error) {
	if p, ok := c.inner.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, sql)
	}
	return c.inner.Prepare(sql)
}

func (c *conn) Close() error { return c.inner.Close() }

func (c *conn) Begin() (driver.Tx, error) { return c.inner.Begin() }

func (c *conn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.inner.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.inner.Begin()
}

func (c *conn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	e, ok := c.inner.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	plan, err := translateCached(query)
	if err != nil {
		return nil, err
	}
	if plan.FollowUp != nil || needsSynthesis(plan) {
		// 2단계 계획에는 트랜잭션과 준비된 두 번째 문장이 필요하다.
		// database/sql이 두 가지를 모두 처리하는 Prepare 경로로 되돌아가게
		// 둔다.
		return nil, driver.ErrSkip
	}
	mapped, err := reorder(args, plan.ArgOrder, "")
	if err != nil {
		return nil, err
	}
	return e.ExecContext(ctx, plan.SQL, mapped)
}

func (c *conn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := c.inner.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	plan, err := translateCached(query)
	if err != nil {
		return nil, err
	}
	if plan.FollowUp != nil || needsSynthesis(plan) {
		return nil, driver.ErrSkip
	}
	mapped, err := reorder(args, plan.ArgOrder, "")
	if err != nil {
		return nil, err
	}
	return q.QueryContext(ctx, plan.SQL, mapped)
}

func (c *conn) Ping(ctx context.Context) error {
	if p, ok := c.inner.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *conn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *conn) IsValid() bool {
	if v, ok := c.inner.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

// CheckNamedValue는 go-sql-driver에 위임한다. 그쪽이 추가로 받아주는 타입들
// (json.RawMessage, uint64 등)이 계속 동작하게 하기 위해서다. 이게 없으면 래퍼가
// database/sql의 더 엄격한 기본 변환기로 되돌아가, 하위 드라이버가 잘 처리하는
// 값을 거부하게 된다.
func (c *conn) CheckNamedValue(nv *driver.NamedValue) error {
	if ck, ok := c.inner.(driver.NamedValueChecker); ok {
		return ck.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

// ---------------------------------------------------------------------------
// 문장
// ---------------------------------------------------------------------------

type stmt struct {
	owner *conn
	inner driver.Stmt
	plan  *Statement
}

func (s *stmt) Close() error { return s.inner.Close() }

func (s *stmt) NumInput() int {
	if s.plan.ArgOrder == nil && s.plan.FollowUp == nil {
		return s.inner.NumInput()
	}
	return inputCount(s.plan)
}

func (s *stmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), valuesToNamed(args))
}

func (s *stmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), valuesToNamed(args))
}

// ExecContext는 2단계 계획의 쓰기 쪽만 실행한다. 호출자가 요청한 것은 행이
// 아니라 결과이므로 재조회는 헛일이 된다.
func (s *stmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	mapped, err := reorder(args, s.plan.ArgOrder, newSynthesisedID())
	if err != nil {
		return nil, err
	}
	return execStmt(ctx, s.inner, mapped)
}

func (s *stmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if s.plan.FollowUp != nil {
		return s.queryWriteThenRead(ctx, args)
	}
	mapped, err := reorder(args, s.plan.ArgOrder, newSynthesisedID())
	if err != nil {
		return nil, err
	}
	return queryStmt(ctx, s.inner, mapped)
}

// queryWriteThenRead는 쓰기와 그에 딸린 SELECT를 계획이 정한 순서대로 하나의
// 원자적 단위로 수행한다.
//
// 트랜잭션을 커밋하기 전에 행을 전부 메모리로 읽어 둔다. MySQL 드라이버는
// 결과를 커넥션에서 스트리밍하므로, 열린 커서를 돌려주고 나중에 커밋하면
// 커넥션이 교착되거나 그 행을 만든 트랜잭션 바깥에서 읽게 된다. 이 방식으로
// 번역되는 문장은 모두 행 하나를 쓰고 그 하나를 다시 읽으므로 버퍼는 한 행
// 깊이다.
func (s *stmt) queryWriteThenRead(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	// 실행 한 번당 값 하나를 두 단계가 공유한다. 재조회를 쓰기가 건드린 행에
	// 묶어 주는 것이 바로 이 값이다.
	synthesised := newSynthesisedID()

	writeArgs, err := reorder(args, s.plan.ArgOrder, synthesised)
	if err != nil {
		return nil, err
	}
	readArgs, err := reorder(args, s.plan.FollowUp.ArgOrder, synthesised)
	if err != nil {
		return nil, err
	}

	tx, err := s.owner.BeginTx(ctx, driver.TxOptions{})
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	read, err := s.owner.prepareTranslated(ctx, s.plan.FollowUp.SQL)
	if err != nil {
		return nil, err
	}
	defer read.Close()

	runRead := func() (*bufferedRows, error) {
		rows, err := queryStmt(ctx, read, readArgs)
		if err != nil {
			return nil, err
		}
		buffered, err := bufferRows(rows)
		closeErr := rows.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return buffered, nil
	}

	var buffered *bufferedRows

	// DELETE ... RETURNING은 먼저 읽어야 한다. 쓰기가 끝나면 조회할 것이 남지
	// 않는다.
	if s.plan.FollowUpFirst {
		if buffered, err = runRead(); err != nil {
			return nil, err
		}
	}

	if _, err := execStmt(ctx, s.inner, writeArgs); err != nil {
		return nil, err
	}

	if !s.plan.FollowUpFirst {
		if buffered, err = runRead(); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	committed = true

	return buffered, nil
}

// newSynthesisedID는 드라이버가 MySQL을 대신해 넣을 키를 만든다.
//
// 스키마가 이 컬럼들의 기본값을 UUID()로 두고 있으므로, 여기서 만든 값은 서버가
// 만들었을 값과 구별되지 않는다. 다만 INSERT 실행 전에 값을 알 수 있다는 이점이
// 있고, RETURNING 절이 없는 서버에서 그 행을 다시 찾는 방법은 그것뿐이다.
func newSynthesisedID() string {
	return uuid.NewString()
}

func (s *stmt) CheckNamedValue(nv *driver.NamedValue) error {
	if ck, ok := s.inner.(driver.NamedValueChecker); ok {
		return ck.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

func execStmt(ctx context.Context, st driver.Stmt, args []driver.NamedValue) (driver.Result, error) {
	if e, ok := st.(driver.StmtExecContext); ok {
		return e.ExecContext(ctx, args)
	}
	return st.Exec(namedToValues(args))
}

func queryStmt(ctx context.Context, st driver.Stmt, args []driver.NamedValue) (driver.Rows, error) {
	if q, ok := st.(driver.StmtQueryContext); ok {
		return q.QueryContext(ctx, args)
	}
	return st.Query(namedToValues(args))
}

func namedToValues(args []driver.NamedValue) []driver.Value {
	out := make([]driver.Value, len(args))
	for i, a := range args {
		out[i] = a.Value
	}
	return out
}

func valuesToNamed(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}

// ---------------------------------------------------------------------------
// 버퍼링된 행
// ---------------------------------------------------------------------------

type bufferedRows struct {
	columns []string
	values  [][]driver.Value
	pos     int
}

func bufferRows(src driver.Rows) (*bufferedRows, error) {
	columns := src.Columns()
	out := &bufferedRows{columns: append([]string(nil), columns...)}

	for {
		row := make([]driver.Value, len(columns))
		if err := src.Next(row); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, err
		}
		// MySQL 드라이버는 자기 읽기 버퍼를 가리키는 슬라이스를 돌려주고 다음
		// Next()에서 재사용하므로, 보관할 것은 반드시 복사해야 한다.
		for i, v := range row {
			if b, ok := v.([]byte); ok {
				row[i] = append([]byte(nil), b...)
			}
		}
		out.values = append(out.values, row)
	}
}

func (r *bufferedRows) Columns() []string { return r.columns }

func (r *bufferedRows) Close() error {
	r.values = nil
	return nil
}

func (r *bufferedRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.pos])
	r.pos++
	return nil
}

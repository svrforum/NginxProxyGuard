package dialect

import (
	"errors"

	"github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
)

// 리포지토리가 분기하는 조건들의 드라이버별 오류 코드.
const (
	pgUniqueViolation     = "23505"
	pgForeignKeyViolation = "23503"

	mysqlDupEntry         = 1062 // ER_DUP_ENTRY
	mysqlDupEntryWithKey  = 1586 // ER_DUP_ENTRY_WITH_KEY_NAME
	mysqlNoReferencedRow  = 1216 // ER_NO_REFERENCED_ROW
	mysqlNoReferencedRow2 = 1452 // ER_NO_REFERENCED_ROW_2
	mysqlRowIsReferenced  = 1217 // ER_ROW_IS_REFERENCED
	mysqlRowIsReferenced2 = 1451 // ER_ROW_IS_REFERENCED_2
)

// IsUniqueViolation은 기존 행과 충돌해서 데이터베이스가 행을 거부한 오류인지
// 판별한다. 어느 백엔드든 동작한다.
//
// 리포지토리는 유니크 인덱스 경합을 500 대신 "이미 존재합니다" 메시지로 바꾸는
// 데 이 함수를 쓴다. Kind 인자로 분기하지 않고 두 드라이버를 모두 확인하는
// 이유는 호출자를 dialect 비의존으로 두기 위해서다. 하나의 오류가 둘 다에
// 매칭되는 경우는 없다.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == pgUniqueViolation
	}

	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == mysqlDupEntry || myErr.Number == mysqlDupEntryWithKey
	}

	return false
}

// IsForeignKeyViolation은 외래 키 제약 위반인지 판별한다. 참조 대상 행이
// 없거나, 자식 행이 아직 가리키고 있어 삭제할 수 없는 경우 모두 해당한다.
func IsForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}

	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		return pqErr.Code == pgForeignKeyViolation
	}

	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		switch myErr.Number {
		case mysqlNoReferencedRow, mysqlNoReferencedRow2, mysqlRowIsReferenced, mysqlRowIsReferenced2:
			return true
		}
	}

	return false
}

// 멱등 DDL을 MySQL에서 다시 실행할 때 나오는 오류들. MariaDB와 달리 MySQL은
// 대부분의 DDL에 IF NOT EXISTS 절이 없다. stripUnsupportedIfExists 참고.
const (
	mysqlTableExists   = 1050 // ER_TABLE_EXISTS_ERROR
	mysqlDupFieldName  = 1060 // ER_DUP_FIELDNAME
	mysqlDupKeyName    = 1061 // ER_DUP_KEYNAME
	mysqlCantDropField = 1091 // ER_CANT_DROP_FIELD_OR_KEY
	mysqlDupForeignKey = 1826 // ER_FK_DUP_NAME
	mysqlDupCheck      = 3822 // ER_CHECK_CONSTRAINT_DUP_NAME
)

// IsAlreadyApplied는 해당 오류가 "이 스키마 변경은 이미 적용돼 있다"는 뜻인지,
// 아니면 진짜 문제인지 판별한다.
//
// 마이그레이션 파일은 부팅할 때마다 다시 실행된다. MariaDB에서는 각 문장에
// IF NOT EXISTS가 붙어 있어 재실행이 조용한 no-op이 된다. MySQL은 인덱스, 컬럼,
// 외래 키에 그 절을 허용하지 않으므로 번역기가 제거하고, 그 결과 재실행 시
// 중복 객체 오류가 난다. 이를 성공으로 취급해야 두 엔진의 마이그레이션 동작이
// 같아진다. 문장이 만들려던 객체가 이미 존재한다는 사실이 증명된 상황이므로
// 안전하다.
func IsAlreadyApplied(err error) bool {
	if err == nil {
		return false
	}
	var myErr *mysql.MySQLError
	if !errors.As(err, &myErr) {
		return false
	}
	switch myErr.Number {
	case mysqlTableExists, mysqlDupFieldName, mysqlDupKeyName,
		mysqlCantDropField, mysqlDupForeignKey, mysqlDupCheck:
		return true
	}
	return false
}

package repository

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
)

// A fresh install has no global_settings row, and the import only UPDATEd,
// so restoring a backup onto a new server reported success and dropped every
// global setting. The row is now created first, inside the restore's
// transaction; sqlmock checks the order.
func TestImportGlobalSettingsCreatesTheRowFirst(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`INSERT INTO global_settings \(id\)\s+SELECT gen_random_uuid\(\)\s+WHERE NOT EXISTS`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE global_settings SET`).WillReturnResult(sqlmock.NewResult(0, 1))

	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := NewBackupRepository(db).importGlobalSettings(context.Background(), tx, &model.GlobalSettingsExport{}); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Error(err)
	}
}

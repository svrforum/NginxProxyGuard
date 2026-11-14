package service

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/password"
	"nginx-proxy-guard/internal/repository"
)

const upgradeTestUserID = "00000000-0000-0000-0000-0000000000aa"

var upgradeTestPepper = []byte(strings.Repeat("k", 48))

// expectUserRow answers GetUserByUsername with one account holding storedHash.
func expectUserRow(mock sqlmock.Sqlmock, storedHash string) {
	now := time.Now()
	mock.ExpectQuery(`SELECT id, username, password_hash`).
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "username", "password_hash", "role", "language", "font_family",
			"is_initial_setup", "totp_enabled", "totp_secret", "totp_verified_at", "backup_codes",
			"last_login_at", "last_login_ip", "login_count",
			"created_at", "updated_at", "role_id", "must_change_password",
		}).AddRow(
			upgradeTestUserID, "alice", storedHash, "admin", "en", "system",
			false, false, nil, nil, nil,
			nil, nil, 0,
			now, now, nil, false,
		))
}

// expectSession answers the writes createSession makes after a good password.
func expectSession(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`INSERT INTO auth_sessions`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow("s1", time.Now()))
	mock.ExpectExec(`INSERT INTO login_attempts`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`UPDATE users\s+SET last_login_at`).WillReturnResult(sqlmock.NewResult(0, 1))
}

// pepperedHashOf matches a stored hash argument that is the peppered form of
// plaintext under the pepper installed when the matcher runs.
type pepperedHashOf string

func (p pepperedHashOf) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, password.PepperedPrefix) {
		return false
	}
	ok, rehash := password.Verify(s, string(p))
	return ok && !rehash
}

func loginForUpgradeTest(t *testing.T, setup func(sqlmock.Sqlmock)) (*model.LoginResponse, error) {
	t.Helper()
	t.Setenv("ENVIRONMENT", "test") // skip the lockout query
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	setup(mock)

	svc := NewAuthService(repository.NewAuthRepository(db), "test-secret")
	defer svc.Close()
	resp, err := svc.Login(context.Background(), &model.LoginRequest{Username: "alice", Password: "correct horse battery"}, "192.0.2.1", "test")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("queries: %v", err)
	}
	return resp, err
}

func TestLoginMovesPlainHashToPepper(t *testing.T) {
	password.Configure(password.Config{})
	plain, err := password.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	password.Configure(password.Config{Pepper: upgradeTestPepper})
	t.Cleanup(func() { password.Configure(password.Config{}) })

	resp, err := loginForUpgradeTest(t, func(mock sqlmock.Sqlmock) {
		expectUserRow(mock, plain)
		// Only password_hash, and only while the row still holds the hash
		// that was verified.
		mock.ExpectExec(`UPDATE users SET password_hash = \$3 WHERE id = \$1 AND password_hash = \$2`).
			WithArgs(upgradeTestUserID, plain, pepperedHashOf("correct horse battery")).
			WillReturnResult(sqlmock.NewResult(0, 1))
		expectSession(mock)
	})
	if err != nil || resp == nil || resp.Token == "" {
		t.Fatalf("Login = (%+v, %v), want a session", resp, err)
	}
}

func TestLoginLeavesHashAloneWithoutPepper(t *testing.T) {
	password.Configure(password.Config{})
	plain, err := password.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	// No UPDATE of password_hash is expected; sqlmock fails on one.
	resp, err := loginForUpgradeTest(t, func(mock sqlmock.Sqlmock) {
		expectUserRow(mock, plain)
		expectSession(mock)
	})
	if err != nil || resp == nil || resp.Token == "" {
		t.Fatalf("Login = (%+v, %v), want a session", resp, err)
	}
}

func TestLoginStillSucceedsWhenUpgradeWriteFails(t *testing.T) {
	password.Configure(password.Config{})
	plain, err := password.Hash("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	password.Configure(password.Config{Pepper: upgradeTestPepper})
	t.Cleanup(func() { password.Configure(password.Config{}) })

	resp, err := loginForUpgradeTest(t, func(mock sqlmock.Sqlmock) {
		expectUserRow(mock, plain)
		mock.ExpectExec(`UPDATE users SET password_hash`).WillReturnError(errors.New("database unavailable"))
		expectSession(mock)
	})
	if err != nil || resp == nil || resp.Token == "" {
		t.Fatalf("Login = (%+v, %v), want a session despite the failed upgrade", resp, err)
	}
}

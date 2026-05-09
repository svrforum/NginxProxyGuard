package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
)

const (
	resetPasswordMinLen      = 8
	resetPasswordMaxBytes    = 72 // bcrypt input limit; longer inputs are silently truncated
	resetPasswordRandomChars = 16
)

// runResetPasswordCommand handles `./server reset-password [flags]`.
// It connects directly to the database (no migrations, no scheduler boot),
// updates the chosen user's password_hash, optionally clears 2FA, always
// clears stale failed-login attempts, and invalidates every existing
// auth_session for the target user.
//
// Operator UX: invocation is only meaningful inside the api container, where
// DATABASE_URL is set by docker-compose. Any other auth state is left intact.
func runResetPasswordCommand(args []string) int {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	username := fs.String("username", "", "Target username. If omitted and exactly one role=admin user exists, that one is used.")
	password := fs.String("password", "", "New password. If omitted, a 16-character random password is generated.")
	clear2FA := fs.Bool("clear-2fa", false, "Also clear the user's TOTP secret and disable 2FA. Default keeps 2FA settings.")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ./server reset-password [flags]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Resets a user's password from the CLI. Run inside the api container:")
		fmt.Fprintln(os.Stderr, "  docker compose exec api ./server reset-password --username admin")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Side effects on success:")
		fmt.Fprintln(os.Stderr, "  - bcrypts and writes the new password_hash")
		fmt.Fprintln(os.Stderr, "  - clears failed login_attempts for the target username")
		fmt.Fprintln(os.Stderr, "  - invalidates every active auth_session for the target user")
		fmt.Fprintln(os.Stderr, "  - records an entry in system_logs (source=audit)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Distinguish "--password not given" from "--password ''" so we can reject
	// the empty form explicitly instead of silently hashing it.
	passwordExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "password" {
			passwordExplicit = true
		}
	})

	cleanUsername := strings.TrimSpace(*username)

	newPassword, err := resolvePassword(*password, passwordExplicit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] %v\n", err)
		return 1
	}

	cfg := config.Load()
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] database connect failed: %v\n", err)
		return 1
	}
	defer db.Close()

	user, err := selectTargetUser(db, cleanUsername)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] %v\n", err)
		return 1
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] hash failed: %v\n", err)
		return 1
	}

	result, err := applyReset(db, user, string(hashed), *clear2FA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] update failed: %v\n", err)
		return 1
	}

	printResult(user.username, user.role, newPassword, *clear2FA, result.sessionsInvalidated)
	return 0
}

type cliUser struct {
	id       string
	username string
	role     string
}

type resetResult struct {
	sessionsInvalidated int64
}

// resolvePassword returns either the operator-supplied password (after
// validation) or a freshly generated random password.
func resolvePassword(raw string, explicit bool) (string, error) {
	if !explicit {
		return generatePassword(resetPasswordRandomChars)
	}
	if raw == "" {
		return "", errors.New("--password cannot be empty (omit the flag to auto-generate a random password)")
	}
	// bcrypt silently truncates inputs longer than 72 bytes; reject upfront so
	// the operator never gets surprised by a password that "works" but only the
	// first 72 bytes actually do.
	if len(raw) > resetPasswordMaxBytes {
		return "", fmt.Errorf("--password is %d bytes; bcrypt only honours the first %d", len(raw), resetPasswordMaxBytes)
	}
	if len([]rune(raw)) < resetPasswordMinLen {
		return "", fmt.Errorf("--password must be at least %d characters", resetPasswordMinLen)
	}
	return raw, nil
}

func selectTargetUser(db *database.DB, requested string) (*cliUser, error) {
	if requested != "" {
		row := db.QueryRow(`SELECT id, username, role FROM users WHERE username = $1`, requested)
		u := &cliUser{}
		if err := row.Scan(&u.id, &u.username, &u.role); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("user not found: %s", requested)
			}
			return nil, fmt.Errorf("query user: %w", err)
		}
		return u, nil
	}

	rows, err := db.Query(`SELECT id, username, role FROM users WHERE role = 'admin' ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list admin users: %w", err)
	}
	defer rows.Close()

	var admins []cliUser
	for rows.Next() {
		var u cliUser
		if err := rows.Scan(&u.id, &u.username, &u.role); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		admins = append(admins, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	switch len(admins) {
	case 0:
		return nil, errors.New("no admin users found. Pass --username to target a specific account.")
	case 1:
		return &admins[0], nil
	default:
		var b strings.Builder
		b.WriteString("multiple admin users — pass --username to choose one:")
		for _, u := range admins {
			fmt.Fprintf(&b, "\n  - %s", u.username)
		}
		return nil, errors.New(b.String())
	}
}

func applyReset(db *database.DB, user *cliUser, passwordHash string, clear2FA bool) (*resetResult, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if clear2FA {
		_, err = tx.Exec(`
			UPDATE users
			SET password_hash = $1,
			    totp_secret = NULL,
			    totp_enabled = false,
			    totp_verified_at = NULL,
			    backup_codes = NULL,
			    updated_at = NOW()
			WHERE id = $2`, passwordHash, user.id)
	} else {
		_, err = tx.Exec(`
			UPDATE users
			SET password_hash = $1,
			    updated_at = NOW()
			WHERE id = $2`, passwordHash, user.id)
	}
	if err != nil {
		return nil, fmt.Errorf("update users: %w", err)
	}

	// Clear failed login attempts so a stale per-IP lockout cannot block the
	// recovery login.
	if _, err := tx.Exec(`DELETE FROM login_attempts WHERE username = $1 AND success = false`, user.username); err != nil {
		return nil, fmt.Errorf("clear login_attempts: %w", err)
	}

	// Invalidate every active session for this user. Resetting credentials is
	// a strong "current auth state is suspect" signal, so we drop all existing
	// session tokens — the operator (and any compromised holder) must re-auth
	// with the new password.
	sessionsRes, err := tx.Exec(`DELETE FROM auth_sessions WHERE user_id = $1`, user.id)
	if err != nil {
		return nil, fmt.Errorf("invalidate sessions: %w", err)
	}
	sessionsCount, _ := sessionsRes.RowsAffected()

	// Audit trail.
	details := map[string]interface{}{
		"username":             user.username,
		"cleared_2fa":          clear2FA,
		"sessions_invalidated": sessionsCount,
	}
	detailsJSON, _ := json.Marshal(details)
	if _, err := tx.Exec(`
		INSERT INTO system_logs (source, level, message, details, component)
		VALUES ('audit', 'warn', 'Password reset via CLI', $1::jsonb, 'reset-password')
	`, detailsJSON); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &resetResult{sessionsInvalidated: sessionsCount}, nil
}

// generatePassword returns a cryptographically random password of n characters
// drawn from an alphabet that excludes visually ambiguous glyphs (0/O, 1/l/I).
func generatePassword(n int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

func printResult(username, role, password string, cleared2FA bool, sessionsInvalidated int64) {
	bar := strings.Repeat("=", 60)
	fmt.Println()
	fmt.Println(bar)
	fmt.Printf("  Username : %s\n", username)
	fmt.Printf("  Role     : %s\n", role)
	fmt.Printf("  Password : %s\n", password)
	if cleared2FA {
		fmt.Println("  2FA      : cleared (TOTP disabled, backup codes wiped)")
	} else {
		fmt.Println("  2FA      : kept (use --clear-2fa to also reset)")
	}
	fmt.Printf("  Sessions : %d active session(s) invalidated\n", sessionsInvalidated)
	fmt.Println(bar)
	fmt.Println()
	fmt.Println("Save this password now. It will not be shown again.")
	fmt.Println("Sign in and change it from the UI immediately.")
}

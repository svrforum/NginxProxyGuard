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

// runResetPasswordCommand handles `./server reset-password [flags]`.
// It connects directly to the database (no migrations, no scheduler boot),
// updates the chosen user's password_hash, optionally clears 2FA and stale
// failed-login attempts, and prints the new password to stdout.
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
		fmt.Fprintln(os.Stderr, "Flags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := config.Load()
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] database connect failed: %v\n", err)
		return 1
	}
	defer db.Close()

	user, err := selectTargetUser(db, *username)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] %v\n", err)
		return 1
	}

	newPassword := *password
	if newPassword == "" {
		newPassword, err = generatePassword(16)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[reset-password] failed to generate password: %v\n", err)
			return 1
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] hash failed: %v\n", err)
		return 1
	}

	if err := applyReset(db, user.id, string(hashed), *clear2FA, user.username); err != nil {
		fmt.Fprintf(os.Stderr, "[reset-password] update failed: %v\n", err)
		return 1
	}

	printResult(user.username, user.role, newPassword, *clear2FA)
	return 0
}

type cliUser struct {
	id       string
	username string
	role     string
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
		b.WriteString("multiple admin users — pass --username to choose one:\n")
		for _, u := range admins {
			fmt.Fprintf(&b, "  - %s\n", u.username)
		}
		return nil, errors.New(b.String())
	}
}

func applyReset(db *database.DB, userID, passwordHash string, clear2FA bool, username string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
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
			WHERE id = $2`, passwordHash, userID)
	} else {
		_, err = tx.Exec(`
			UPDATE users
			SET password_hash = $1,
			    updated_at = NOW()
			WHERE id = $2`, passwordHash, userID)
	}
	if err != nil {
		return fmt.Errorf("update users: %w", err)
	}

	// Clear failed login attempts so the user is not locked out by prior failures.
	if _, err := tx.Exec(`DELETE FROM login_attempts WHERE username = $1 AND success = false`, username); err != nil {
		return fmt.Errorf("clear login_attempts: %w", err)
	}

	// Audit trail.
	details := map[string]interface{}{
		"username":    username,
		"cleared_2fa": clear2FA,
	}
	detailsJSON, _ := json.Marshal(details)
	if _, err := tx.Exec(`
		INSERT INTO system_logs (source, level, message, details, component)
		VALUES ('audit', 'warn', 'Password reset via CLI', $1::jsonb, 'reset-password')
	`, detailsJSON); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}

	return tx.Commit()
}

// generatePassword returns a cryptographically random password of n characters
// drawn from a URL-safe alphabet that avoids visually ambiguous glyphs (0/O, 1/l/I).
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

func printResult(username, role, password string, cleared2FA bool) {
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
	fmt.Println(bar)
	fmt.Println()
	fmt.Println("Save this password now. It will not be shown again.")
	fmt.Println("Sign in and change it from the UI immediately.")
}

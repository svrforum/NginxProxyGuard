package repository

import (
	"context"
	"database/sql"
	"fmt"

	"nginx-proxy-guard/internal/model"
)

// insertAccessListAuthUsers writes the basic auth accounts of list listID
// (#387), in tx. Each carries the hash to store: the handler hashed a new
// password, and the validator copied the stored hash of one left unchanged.
func insertAccessListAuthUsers(ctx context.Context, tx *sql.Tx, listID string, users []model.AccessListAuthUserRequest) error {
	for _, u := range users {
		if u.PasswordHash == "" {
			return fmt.Errorf("access list account %q has no password hash", u.Username)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO access_list_auth_users (access_list_id, username, password_hash)
			VALUES ($1, $2, $3)
		`, listID, u.Username, u.PasswordHash); err != nil {
			return err
		}
	}
	return nil
}

// accessListAuthUsers reads the accounts of list listID, hashes included.
func (r *AccessListRepository) accessListAuthUsers(ctx context.Context, listID string) ([]model.AccessListAuthUser, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, username, password_hash FROM access_list_auth_users
		WHERE access_list_id = $1 ORDER BY username
	`, listID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []model.AccessListAuthUser
	for rows.Next() {
		var u model.AccessListAuthUser
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate access list accounts: %w", err)
	}
	return users, nil
}

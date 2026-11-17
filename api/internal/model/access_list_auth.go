package model

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// AccessListAuthUser is a basic auth account of an access list (#387). A
// proxy host that uses the list asks for one of these accounts: with
// satisfy_any an address the list allows gets in without it, otherwise both
// are needed. The hash never leaves the API: nginx reads it from the htpasswd
// file the config generator writes.
type AccessListAuthUser struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
}

// AccessListAuthUserRequest is an account as a create or update sends it.
// Password is a new password; empty keeps the stored password of the
// account with this username, and a new account needs one.
type AccessListAuthUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	// PasswordHash is what the repository stores: the stored hash for an
	// account sent without a password (ValidateAccessListAuthUsers), the hash
	// of Password otherwise (set by the handler).
	PasswordHash string `json:"-"`
}

const (
	accessListAuthUsernameMax = 64
	accessListAuthPasswordMin = 8
	accessListAuthPasswordMax = 128
	accessListAuthUsersMax    = 200
)

// ValidateAccessListAuthUsers checks the accounts a request sends. stored are
// the list's accounts before the update (nil for a new list): an account sent
// without a password keeps its stored hash, copied into PasswordHash here.
//
// A username becomes the part before ":" of an htpasswd line, so it cannot
// hold a colon, a space or a control character.
func ValidateAccessListAuthUsers(users []AccessListAuthUserRequest, stored []AccessListAuthUser) error {
	if len(users) > accessListAuthUsersMax {
		return accessListItemError("auth_users", "", "auth_users: at most %d accounts per list", accessListAuthUsersMax)
	}
	storedHash := make(map[string]string, len(stored))
	for _, u := range stored {
		storedHash[u.Username] = u.PasswordHash
	}
	seen := make(map[string]bool, len(users))
	for i := range users {
		u := &users[i]
		field := fmt.Sprintf("auth_users[%d]", i)
		if u.Username == "" || utf8.RuneCountInString(u.Username) > accessListAuthUsernameMax {
			return accessListItemError(field+".username", "", "%s.username must be 1 to %d characters", field, accessListAuthUsernameMax)
		}
		if !utf8.ValidString(u.Username) || strings.ContainsFunc(u.Username, func(r rune) bool {
			return r == ':' || unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			return accessListItemError(field+".username", "", "%s.username cannot contain a colon, a space or a control character", field)
		}
		// nginx reads an htpasswd line that starts with # as a comment.
		if strings.HasPrefix(u.Username, "#") {
			return accessListItemError(field+".username", "", "%s.username cannot start with #", field)
		}
		if seen[u.Username] {
			return accessListItemError(field+".username", "", "%s.username: %s is already in this list", field, u.Username)
		}
		seen[u.Username] = true

		if u.Password == "" {
			hash, ok := storedHash[u.Username]
			if !ok {
				return accessListItemError(field+".password", "", "%s.password is required for a new account", field)
			}
			u.PasswordHash = hash
			continue
		}
		if utf8.RuneCountInString(u.Password) < accessListAuthPasswordMin || len(u.Password) > accessListAuthPasswordMax {
			return accessListItemError(field+".password", "", "%s.password must be at least %d characters and at most %d bytes", field, accessListAuthPasswordMin, accessListAuthPasswordMax)
		}
		// nginx hands the password to crypt() as a C string.
		if strings.ContainsRune(u.Password, 0) {
			return accessListItemError(field+".password", "", "%s.password must not contain a NUL character", field)
		}
		u.PasswordHash = ""
	}
	return nil
}

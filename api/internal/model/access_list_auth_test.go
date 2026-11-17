package model

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateAccessListAuthUsers(t *testing.T) {
	stored := []AccessListAuthUser{{Username: "alice", PasswordHash: "$6$old$hash"}}

	keep := []AccessListAuthUserRequest{{Username: "alice"}, {Username: "bob", Password: "a long password"}}
	if err := ValidateAccessListAuthUsers(keep, stored); err != nil {
		t.Fatalf("valid accounts refused: %v", err)
	}
	if keep[0].PasswordHash != "$6$old$hash" || keep[1].PasswordHash != "" {
		t.Errorf("hashes = %q, %q; want the stored one kept and the new one left to the handler", keep[0].PasswordHash, keep[1].PasswordHash)
	}

	for _, tc := range []struct {
		name  string
		users []AccessListAuthUserRequest
		field string
	}{
		{"new account without password", []AccessListAuthUserRequest{{Username: "carol"}}, "auth_users[0].password"},
		{"short password", []AccessListAuthUserRequest{{Username: "carol", Password: "short"}}, "auth_users[0].password"},
		{"colon", []AccessListAuthUserRequest{{Username: "a:b", Password: "a long password"}}, "auth_users[0].username"},
		{"space", []AccessListAuthUserRequest{{Username: "a b", Password: "a long password"}}, "auth_users[0].username"},
		{"newline", []AccessListAuthUserRequest{{Username: "a\nb", Password: "a long password"}}, "auth_users[0].username"},
		{"empty", []AccessListAuthUserRequest{{Username: "", Password: "a long password"}}, "auth_users[0].username"},
		{"too long", []AccessListAuthUserRequest{{Username: strings.Repeat("a", 65), Password: "a long password"}}, "auth_users[0].username"},
		{"twice", []AccessListAuthUserRequest{{Username: "alice"}, {Username: "alice", Password: "a long password"}}, "auth_users[1].username"},
		{"NUL in password", []AccessListAuthUserRequest{{Username: "carol", Password: "a long\x00password"}}, "auth_users[0].password"},
	} {
		err := ValidateAccessListAuthUsers(tc.users, stored)
		var ie *AccessListItemError
		if !errors.As(err, &ie) || !errors.Is(err, ErrInvalidInput) || ie.Field != tc.field {
			t.Errorf("%s: got %v, want an invalid-input error on %s", tc.name, err, tc.field)
		}
	}
}

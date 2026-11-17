package handler

import (
	"nginx-proxy-guard/internal/htpasswd"
	"nginx-proxy-guard/internal/model"
)

// hashAccessListAuthUsers hashes the new password of each account that sent
// one (#387). The validator already gave an account sent without a password
// its stored hash.
func hashAccessListAuthUsers(users []model.AccessListAuthUserRequest) error {
	for i := range users {
		if users[i].Password == "" {
			continue
		}
		hash, err := htpasswd.Hash(users[i].Password)
		if err != nil {
			return err
		}
		users[i].PasswordHash = hash
		users[i].Password = ""
	}
	return nil
}

// accessListAuthChanges describes for the audit log how the accounts changed:
// usernames added and removed, and those given a new password. A password or
// hash is never recorded.
func accessListAuthChanges(details map[string]interface{}, before, after *model.AccessList) {
	old := make(map[string]string, len(before.AuthUsers))
	for _, u := range before.AuthUsers {
		old[u.Username] = u.PasswordHash
	}
	var added, changed []string
	for _, u := range after.AuthUsers {
		hash, ok := old[u.Username]
		switch {
		case !ok:
			added = append(added, u.Username)
		case hash != u.PasswordHash:
			changed = append(changed, u.Username)
		}
		delete(old, u.Username)
	}
	var removed []string
	for _, u := range before.AuthUsers {
		if _, ok := old[u.Username]; ok {
			removed = append(removed, u.Username)
		}
	}
	if len(added) > 0 {
		details["accounts_added"] = added
	}
	if len(removed) > 0 {
		details["accounts_removed"] = removed
	}
	if len(changed) > 0 {
		details["passwords_changed"] = changed
	}
	if before.PassAuth != after.PassAuth {
		details["pass_auth"] = []bool{before.PassAuth, after.PassAuth}
	}
}

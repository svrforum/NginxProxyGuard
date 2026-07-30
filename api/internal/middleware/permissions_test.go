package middleware

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A typo in the registry ("proxy:reed") would compile, pass the coverage test,
// and then deny that route to everyone including the operator — the failure
// would look like a broken feature, not a bad mapping. Pin the strings to the
// area table. (#222)
func TestRoutePermissionsAreRealPermissions(t *testing.T) {
	valid := map[string]bool{}
	for _, p := range model.AllAreaPermissions {
		valid[p] = true
	}
	for route, perm := range routePermissions {
		if !valid[perm] {
			t.Errorf("%s maps to %q, which is not an area permission", route, perm)
		}
	}
}

// Every area the role editor offers should actually gate something. An area with
// no routes is a checkbox that does nothing — the "privilege illusion" this
// design set out to avoid.
func TestEveryAreaGatesAtLeastOneRoute(t *testing.T) {
	used := map[string]bool{}
	for _, perm := range routePermissions {
		area, _, ok := splitAreaVerb(perm)
		if ok {
			used[area] = true
		}
	}
	// user and role gate the management API that increment 2 adds; they are
	// deliberately unused here.
	pending := map[string]bool{"user": true, "role": true}
	for _, a := range model.PermissionAreas {
		if !used[a.Key] && !pending[a.Key] {
			t.Errorf("area %q gates no route", a.Key)
		}
	}
}

func splitAreaVerb(p string) (string, string, bool) {
	for i := 0; i < len(p); i++ {
		if p[i] == ':' {
			return p[:i], p[i+1:], true
		}
	}
	return "", "", false
}

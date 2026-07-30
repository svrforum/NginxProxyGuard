package model

import "testing"

// The 15 pre-existing permission strings must remain supersets of the new
// area permissions. If an already-issued API token loses reach, users'
// automation breaks silently. (#222)
func TestExpandPermissions_BackwardCompatible(t *testing.T) {
	for _, tc := range []struct {
		stored string
		want   []string
	}{
		{"*", []string{"proxy:read", "settings:write", "user:write", "role:write", "audit:read"}},
		{"settings:read", []string{"settings:read", "dashboard:read", "ddns:read", "audit:read", "apitoken:read", "logs:read"}},
		{"settings:write", []string{"settings:read", "settings:write", "ddns:write", "apitoken:write", "logs:write"}},
		{"proxy:read", []string{"proxy:read", "redirect:read", "access:read", "authprovider:read"}},
		{"proxy:write", []string{"proxy:read", "proxy:write", "redirect:write", "access:write", "authprovider:write"}},
		{"proxy:delete", []string{"proxy:delete", "redirect:delete"}},
		{"certificate:write", []string{"certificate:read", "certificate:write", "dnsprovider:read", "dnsprovider:write"}},
		{"waf:write", []string{"waf:read", "waf:write"}},
	} {
		got := ExpandPermissions([]string{tc.stored})
		for _, w := range tc.want {
			if !got[w] {
				t.Errorf("ExpandPermissions([%q]) missing %q", tc.stored, w)
			}
		}
	}
}

// The verb hierarchy runs one way only: write grants read, never the reverse.
func TestExpandPermissions_ReadDoesNotImplyWrite(t *testing.T) {
	got := ExpandPermissions([]string{"proxy:read"})
	for _, forbidden := range []string{"proxy:write", "proxy:delete", "settings:write", "user:write"} {
		if got[forbidden] {
			t.Errorf("proxy:read must not imply %q", forbidden)
		}
	}
}

// Areas that were split out of a catch-all must not be granted by a sibling.
// certificate:write must not reach live DNS records. The two areas were split
// precisely so a role could grant one without the other. (#222)
func TestExpandPermissions_CertificateDoesNotGrantDDNS(t *testing.T) {
	got := ExpandPermissions([]string{"certificate:write"})
	for _, forbidden := range []string{"ddns:read", "ddns:write"} {
		if got[forbidden] {
			t.Errorf("certificate:write must not imply %q", forbidden)
		}
	}
}

func TestExpandPermissions_NoAccidentalGrant(t *testing.T) {
	got := ExpandPermissions([]string{"logs:read"})
	if got["audit:read"] {
		t.Error("logs:read must not imply audit:read — the audit log is its own area")
	}
	if got["settings:read"] {
		t.Error("logs:read must not imply settings:read — implication runs coarse -> fine, not back")
	}
}

// Every area permission must be reachable from the superuser bypass equivalent,
// otherwise a role UI could offer a checkbox no principal can ever satisfy.
func TestAllAreaPermissions_CoveredByWildcard(t *testing.T) {
	got := ExpandPermissions([]string{PermissionAll})
	for _, p := range AllAreaPermissions {
		if !got[p] {
			t.Errorf("%q is not covered by %q", p, PermissionAll)
		}
	}
}

// The area table and the flat list must not drift apart.
func TestAreaPermissions_MatchesFlatList(t *testing.T) {
	seen := map[string]bool{}
	for _, area := range PermissionAreas {
		for _, verb := range area.Verbs {
			seen[area.Key+":"+verb] = true
		}
	}
	if len(seen) != len(AllAreaPermissions) {
		t.Fatalf("PermissionAreas yields %d permissions, AllAreaPermissions has %d", len(seen), len(AllAreaPermissions))
	}
	for _, p := range AllAreaPermissions {
		if !seen[p] {
			t.Errorf("%q in AllAreaPermissions but not derivable from PermissionAreas", p)
		}
	}
}

package model

// Permission areas for role-based access control (#222).
//
// The 15 permission strings in api_token.go are RESOURCE-shaped and predate
// this file. Three of them are catch-alls that do not line up with what the UI
// presents as separate menus: settings:* gates the dashboard, DDNS, the audit
// log and API-token management, while proxy:* gates redirects, access lists and
// auth providers. A role called "read the certificates menu" built on those
// strings would also hand over the audit log — the feature would lie to the
// operator.
//
// So the areas below are the permission axis roles are built from, and the old
// strings stay valid as SUPERSETS of them (see implications). That keeps every
// already-issued API token working: expansion only ever adds reach.
//
// Stored values are never rewritten. Implication is applied at CHECK time so
// that adding a new area later automatically extends the coarse strings that
// should contain it, without touching a single stored row.

// Permission verbs. delete implies write implies read, within one area.
const (
	VerbRead    = "read"
	VerbWrite   = "write"
	VerbDelete  = "delete"
	VerbCreate  = "create"  // backup only
	VerbRestore = "restore" // backup only
)

// PermissionArea is one row of the role editor: a menu area and the verbs it
// supports. Verbs differ per area because the underlying routes do — WAF has no
// separate delete, backup has create/restore instead of write.
type PermissionArea struct {
	Key   string
	Verbs []string
}

// PermissionAreas is the authoritative area table. Order is the order the role
// editor renders, which follows the UI's top navigation.
var PermissionAreas = []PermissionArea{
	{Key: "dashboard", Verbs: []string{VerbRead}},
	{Key: "proxy", Verbs: []string{VerbRead, VerbWrite, VerbDelete}},
	{Key: "redirect", Verbs: []string{VerbRead, VerbWrite, VerbDelete}},
	{Key: "waf", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "access", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "authprovider", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "certificate", Verbs: []string{VerbRead, VerbWrite, VerbDelete}},
	{Key: "ddns", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "logs", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "audit", Verbs: []string{VerbRead}},
	{Key: "settings", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "backup", Verbs: []string{VerbRead, VerbCreate, VerbRestore}},
	{Key: "apitoken", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "user", Verbs: []string{VerbRead, VerbWrite}},
	{Key: "role", Verbs: []string{VerbRead, VerbWrite}},
}

// AllAreaPermissions is the flat list of every area permission string, derived
// from PermissionAreas at init so the two can never drift.
var AllAreaPermissions = func() []string {
	out := make([]string, 0, 32)
	for _, a := range PermissionAreas {
		for _, v := range a.Verbs {
			out = append(out, a.Key+":"+v)
		}
	}
	return out
}()

// verbImplications expresses the one-way verb hierarchy inside an area. Without
// it a role with only "write" checked would 403 on the list endpoint, because
// HasPermission is an exact match (api_token.go). Granting read alongside write
// is strictly widening, so it cannot regress an existing token.
var verbImplications = map[string][]string{
	VerbWrite:   {VerbRead},
	VerbDelete:  {VerbWrite, VerbRead},
	VerbCreate:  {VerbRead},
	VerbRestore: {VerbRead, VerbCreate},
}

// implications maps a legacy resource permission to the area permissions it
// contains. This is the backward-compatibility contract: an API token holding
// settings:read must keep reaching everything settings:read reached before the
// areas were split out of it.
var implications = map[string][]string{
	PermissionSettingsRead: {
		"settings:read", "dashboard:read", "ddns:read", "audit:read",
		"apitoken:read", "logs:read",
	},
	PermissionSettingsWrite: {
		"settings:write", "ddns:write", "apitoken:write", "logs:write",
	},
	PermissionProxyRead: {
		"proxy:read", "redirect:read", "access:read", "authprovider:read",
	},
	PermissionProxyWrite: {
		"proxy:write", "redirect:write", "access:write", "authprovider:write",
	},
	PermissionProxyDelete: {
		"proxy:delete", "redirect:delete",
	},
	PermissionCertRead:   {"certificate:read", "ddns:read"},
	PermissionCertWrite:  {"certificate:write", "ddns:write"},
	PermissionCertDelete: {"certificate:delete"},
	PermissionWAFRead:    {"waf:read"},
	PermissionWAFWrite:   {"waf:write"},
	PermissionLogsRead:   {"logs:read"},
	PermissionBackupRead: {"backup:read"},
	// backup:create/restore are area permissions with the same spelling as the
	// legacy strings, so they need no translation — they fall through the
	// identity branch in ExpandPermissions.
	PermissionUserRead: {"user:read"},
}

// ExpandPermissions turns a principal's STORED permissions into the effective
// set to check against. It applies, in order: the "*" bypass, legacy-string
// implications, the identity of area permissions, and the verb hierarchy.
//
// Returns a set so callers do a map lookup rather than a linear scan on every
// request.
func ExpandPermissions(stored []string) map[string]bool {
	out := make(map[string]bool, len(AllAreaPermissions))

	for _, p := range stored {
		if p == PermissionAll {
			for _, a := range AllAreaPermissions {
				out[a] = true
			}
			// Legacy strings stay in the set too: in-handler checks and any
			// third-party caller may still test for them by name.
			for _, a := range AllPermissions {
				out[a] = true
			}
			return out
		}
		// Legacy resource string -> the areas it contains.
		if areas, ok := implications[p]; ok {
			for _, a := range areas {
				out[a] = true
			}
		}
		// An area permission (or a legacy string with no translation, e.g.
		// backup:create) is itself granted.
		out[p] = true
	}

	// Verb hierarchy, applied after expansion so it also lifts permissions that
	// arrived through an implication.
	for p := range out {
		key, verb, ok := splitPermission(p)
		if !ok {
			continue
		}
		for _, lesser := range verbImplications[verb] {
			out[key+":"+lesser] = true
		}
	}
	return out
}

// splitPermission splits "area:verb" once from the right-most colon. Returns
// ok=false for anything that is not exactly one colon-separated pair, so the
// "*" wildcard and malformed values never reach the verb hierarchy.
func splitPermission(p string) (area, verb string, ok bool) {
	for i := 0; i < len(p); i++ {
		if p[i] == ':' {
			if i == 0 || i == len(p)-1 {
				return "", "", false
			}
			// Reject a second colon rather than guessing.
			for j := i + 1; j < len(p); j++ {
				if p[j] == ':' {
					return "", "", false
				}
			}
			return p[:i], p[i+1:], true
		}
	}
	return "", "", false
}

package repository

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"testing"
)

// TestBackupSyncCriticalTables guards the invariant that for each backup-
// tracked table covered by this test, every column in the curated list
// appears in BOTH the export SELECT (backup_export_proxy.go) and the
// import INSERT (backup_import_proxy.go) function bodies. A column added
// to one path but not the other silently corrupts backup/restore
// round-trips — see root CLAUDE.md "Cross-Cutting Critical Rules" §2.
//
// SCOPE: Only the 3 highest-churn backup-tracked tables (proxy_hosts,
// redirect_hosts, certificates) are covered. Lower-churn backup structs
// (BackupGlobalSettings, BackupSystemSettings, etc.) are intentionally
// out of scope to keep curated lists small per the surgical-changes
// policy — adding 200+ db: tags or full reflection would touch every
// Backup*Export/Data struct. Add new curated entries below if drift
// surfaces in another table.
//
// Note on `id`: intentionally excluded from curated lists. Export SELECTs
// `id` but import generates a new id via `RETURNING id`, so `id` is not
// a "backed up" value in the round-trip sense. Including it would also
// produce a false positive in import (matched via RETURNING) that could
// mask real regressions if RETURNING is later refactored.
func TestBackupSyncCriticalTables(t *testing.T) {
	cases := []struct {
		name           string   // human-friendly label
		exportFile     string   // file containing the export func
		exportFunc     string   // export function with the SELECT
		importFile     string   // file containing the import func
		importFunc     string   // import function with the INSERT
		columns        []string // curated list of columns that MUST appear in both bodies
	}{
		{
			name:       "proxy_hosts",
			exportFile: "backup_export_proxy.go",
			exportFunc: "exportProxyHosts",
			importFile: "backup_import_proxy.go",
			importFunc: "importProxyHost",
			columns: []string{
				"access_list_id",
				"advanced_config",
				"allow_websocket_upgrade",
				"block_exploits",
				"block_exploits_exceptions",
				"bot_filter_enabled",
				"cache_enabled",
				"cache_static_only",
				"cache_ttl",
				"certificate_id",
				"client_max_body_size",
				"custom_locations",
				"domain_names",
				"enabled",
				"fail2ban_enabled",
				"forward_host",
				"forward_port",
				"forward_scheme",
				"is_favorite",
				"meta",
				"proxy_buffering",
				"proxy_connect_timeout",
				"proxy_max_temp_file_size",
				"proxy_read_timeout",
				"proxy_request_buffering",
				"proxy_send_timeout",
				"rate_limit_enabled",
				"security_headers_enabled",
				"ssl_enabled",
				"ssl_force_https",
				"ssl_http2",
				"ssl_http3",
				"waf_anomaly_threshold",
				"waf_enabled",
				"waf_mode",
				"waf_paranoia_level",
			},
		},
		{
			name:       "redirect_hosts",
			exportFile: "backup_export_proxy.go",
			exportFunc: "exportRedirectHosts",
			importFile: "backup_import_proxy.go",
			importFunc: "importRedirectHost",
			columns: []string{
				"block_exploits",
				"certificate_id",
				"domain_names",
				"enabled",
				"forward_domain_name",
				"forward_path",
				"forward_scheme",
				"meta",
				"preserve_path",
				"redirect_code",
				"ssl_enabled",
				"ssl_force_https",
			},
		},
		{
			name:       "certificates",
			exportFile: "backup_export_proxy.go",
			exportFunc: "exportCertificates",
			importFile: "backup_import_proxy.go",
			importFunc: "importCertificate",
			columns: []string{
				"auto_renew",
				"certificate_path",
				"certificate_pem",
				"dns_provider_id",
				"domain_names",
				"expires_at",
				"issuer_certificate_pem",
				"private_key_path",
				"private_key_pem",
				"provider",
				"status",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			exportBody := extractFuncBody(t, tc.exportFile, tc.exportFunc)
			importBody := extractFuncBody(t, tc.importFile, tc.importFunc)

			sort.Strings(tc.columns)
			for _, col := range tc.columns {
				if !sqlContainsColumn(exportBody, col) {
					t.Errorf("[%s] column %q in curated list but missing from %s:%s — backup will silently drop this column",
						tc.name, col, tc.exportFile, tc.exportFunc)
				}
				if !sqlContainsColumn(importBody, col) {
					t.Errorf("[%s] column %q in curated list but missing from %s:%s — restore will silently zero this column",
						tc.name, col, tc.importFile, tc.importFunc)
				}
			}
		})
	}
}

// extractFuncBody parses the given file and returns the source text of the
// named function's body (everything between { and the matching }).
func extractFuncBody(t *testing.T, fileName, funcName string) string {
	t.Helper()
	src, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf("read %s: %v", fileName, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", fileName, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != funcName || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return string(src[start:end])
	}
	t.Fatalf("function %s not found in %s", funcName, fileName)
	return ""
}

// sqlContainsColumn checks whether `col` appears as a word boundary inside
// the haystack (case-insensitive). Distinguishes between `host_id` and `id`,
// or `block_exploits` and `block_exploits_exceptions`, via `\b` boundaries.
func sqlContainsColumn(haystack, col string) bool {
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(col) + `\b`)
	return re.MatchString(haystack)
}

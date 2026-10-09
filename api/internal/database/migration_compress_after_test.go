package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// funcSource returns the source text of the named function or method declared
// in fileName (go test runs in the package directory).
func funcSource(t *testing.T, fileName, name string) string {
	t.Helper()
	src := mustReadFile(t, fileName)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", fileName, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == name {
			return src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]
		}
	}
	t.Fatalf("function %s not found in %s", name, fileName)
	return ""
}

// Logs are compressed after 1 day. New installs get that from
// setupTimescaleDBCompression; existing installs are moved once by an upgrade,
// and only while they still hold the old default of exactly 7 days, so a value
// an operator chose survives the upgrade and every boot after it. The
// documentation in 001_init.sql must be that block, line for line.
func TestLogsCompressAfterOneDayUpgrade(t *testing.T) {
	var blocks []string
	for _, sql := range mustExtractUpgradeSliceSQL(t, "migration.go") {
		if strings.Contains(sql, "logs_compress_after_1d_v1") {
			blocks = append(blocks, sql)
		}
	}
	if len(blocks) != 1 {
		t.Fatalf("found %d upgrades naming logs_compress_after_1d_v1, want 1", len(blocks))
	}
	block := blocks[0]

	for _, want := range []string{
		// Runs once: the marker is checked first and written in the same block.
		"IF EXISTS (SELECT 1 FROM schema_migrations WHERE version = 'logs_compress_after_1d_v1') THEN",
		"INSERT INTO schema_migrations (version) VALUES ('logs_compress_after_1d_v1') ON CONFLICT DO NOTHING;",
		// Only the old default moves; anything else is the operator's choice.
		"IF cur = interval '7 days' THEN",
		"alter_job(jid, config => jsonb_set(cfg, '{compress_after}', to_jsonb('" + logsCompressAfterDefault + "'::text)))",
		// A value that is not a valid interval must not fail the boot.
		"EXCEPTION WHEN others THEN",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the logs_compress_after_1d_v1 upgrade lost %q", want)
		}
	}
	if strings.Index(block, "RETURN;") > strings.Index(block, "alter_job(") {
		t.Error("the logs_compress_after_1d_v1 upgrade must return on its marker before it alters anything")
	}

	documented := "--   " + strings.ReplaceAll(block, "\n", "\n--   ") + ";"
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))
	if !strings.Contains(initSQL, documented) {
		t.Errorf("the 001_init.sql UPGRADE SECTION does not document the logs_compress_after_1d_v1 upgrade as it runs; want it to contain\n%s", documented)
	}
}

// setupTimescaleDBCompression runs on every boot. It must create the policy at
// the new default only when there is none: add_compression_policy given a
// different interval does not change an existing policy, it only warns, and it
// would warn on every boot of every install not on the new default.
func TestSetupTimescaleDBCompressionAddsOneDayPolicyOnlyWhenMissing(t *testing.T) {
	if logsCompressAfterDefault != "1 day" {
		t.Fatalf("logsCompressAfterDefault = %q, want \"1 day\"", logsCompressAfterDefault)
	}
	src := funcSource(t, "migration.go", "setupTimescaleDBCompression")
	if strings.Contains(src, "INTERVAL '7 days'") {
		t.Error("setupTimescaleDBCompression still creates the logs policy at 7 days")
	}
	for _, want := range []string{"logsCompressionPolicy()", "jobID == 0", "logsCompressAfterDefault"} {
		if !strings.Contains(src, want) {
			t.Errorf("setupTimescaleDBCompression lost %q: the policy must be read first and added only when missing", want)
		}
	}
	if strings.Count(src, "add_compression_policy(") != 1 {
		t.Errorf("setupTimescaleDBCompression must call add_compression_policy exactly once, behind the missing-policy check")
	}
}

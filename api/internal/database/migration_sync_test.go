package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestMigrationStructuralSync guards the invariant that every ADD COLUMN /
// ADD VALUE statement in the upgrades slice (executed on existing-install
// upgrades) has a matching definition reachable on fresh installs — either
// via the initial CREATE TABLE / CREATE TYPE, or via the executable
// UPGRADE SECTION at the bottom of 001_init.sql. And vice versa for the
// UPGRADE SECTION → upgrades direction.
//
// Other statement kinds (CREATE INDEX, DO $$, INSERT, COMMENT ON, etc.) are
// not subject to this parity rule — their fresh-install equivalents live
// elsewhere (separate Go migration functions, seed blocks earlier in
// init.sql, etc.) and are out of scope for this guard.
func TestMigrationStructuralSync(t *testing.T) {
	upgradesSQL := mustExtractUpgradeSliceSQL(t, "migration.go")
	initSQL := mustReadFile(t, filepath.Join("migrations", "001_init.sql"))

	// Parse init.sql once into:
	//   tableColumns[table] = set of columns declared in CREATE TABLE
	//                        (anywhere in the file — fresh installs run the
	//                        whole file including UPGRADE SECTION).
	//   enumValues[enum]    = set of values in CREATE TYPE AS ENUM
	//   upgradeAddColumns   = set of (table, col) found in UPGRADE SECTION
	//                        ALTER TABLE ADD COLUMN
	//   upgradeAddValues    = set of (enum, value) found in UPGRADE SECTION
	//                        ALTER TYPE ADD VALUE
	tableColumns, enumValues, upgradeAddColumns, upgradeAddValues := parseInitSQL(t, initSQL)

	// Extract structural references from upgrades slice.
	upgradesAddColumns, upgradesAddValues := parseUpgradeStatements(upgradesSQL)

	// Direction 1: every ADD COLUMN in upgrades must be reachable on fresh install.
	for ref := range upgradesAddColumns {
		inCreate := tableColumns[ref.table][ref.col]
		inUpgradeSection := upgradeAddColumns[ref]
		if !inCreate && !inUpgradeSection {
			t.Errorf("Column %s.%s present in upgrades (existing-install upgrade) but missing from init.sql (fresh install): neither CREATE TABLE %s nor UPGRADE SECTION declares it. Fresh users will not have this column.",
				ref.table, ref.col, ref.table)
		}
	}
	for ref := range upgradesAddValues {
		inCreate := enumValues[ref.table][ref.col]
		inUpgradeSection := upgradeAddValues[ref]
		if !inCreate && !inUpgradeSection {
			t.Errorf("Enum value %s.%s present in upgrades but missing from init.sql: neither CREATE TYPE %s nor UPGRADE SECTION declares it. Fresh users will not have this enum value.",
				ref.table, ref.col, ref.table)
		}
	}

	// Direction 2: every ADD COLUMN/VALUE in UPGRADE SECTION must also be in upgrades.
	for ref := range upgradeAddColumns {
		if !upgradesAddColumns[ref] {
			t.Errorf("Column %s.%s present in 001_init.sql UPGRADE SECTION (fresh-install path) but missing from upgrades slice in migration.go (existing-install path). Existing users will not get this column.",
				ref.table, ref.col)
		}
	}
	for ref := range upgradeAddValues {
		if !upgradesAddValues[ref] {
			t.Errorf("Enum value %s.%s present in 001_init.sql UPGRADE SECTION but missing from upgrades slice. Existing users will not get this value.",
				ref.table, ref.col)
		}
	}

	// For diagnostic logging: print summary if test passed.
	if !t.Failed() {
		t.Logf("structural sync check passed: upgrades has %d ADD COLUMN refs, %d ADD VALUE refs; init.sql has %d tables and %d enum types tracked; UPGRADE SECTION has %d ADD COLUMN and %d ADD VALUE statements",
			len(upgradesAddColumns), len(upgradesAddValues),
			len(tableColumns), len(enumValues),
			len(upgradeAddColumns), len(upgradeAddValues))
	}
}

// sqlRef identifies a structural element — either (table, column) or (enum, value).
type sqlRef struct {
	table string // table name or enum type name (lower-cased)
	col   string // column name or enum value (lower-cased, unquoted)
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// mustExtractUpgradeSliceSQL parses migration.go and returns the slice of SQL
// strings from the `upgrades` local in RunMigrations. Each element's `sql` field
// is extracted from the AST.
func mustExtractUpgradeSliceSQL(t *testing.T, fileName string) []string {
	t.Helper()
	src := mustReadFile(t, fileName)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", fileName, err)
	}
	var sqls []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Name.Name != "RunMigrations" {
			return true
		}
		// Inside RunMigrations: find AssignStmt with LHS "upgrades" and RHS slice literal.
		ast.Inspect(fn.Body, func(n2 ast.Node) bool {
			as, ok := n2.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok || id.Name != "upgrades" {
				return true
			}
			if len(as.Rhs) != 1 {
				return true
			}
			cl, ok := as.Rhs[0].(*ast.CompositeLit)
			if !ok {
				return true
			}
			// Each element is a struct literal with `sql: "..."`.
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, fld := range kv.Elts {
					pair, ok := fld.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					keyIdent, ok := pair.Key.(*ast.Ident)
					if !ok || keyIdent.Name != "sql" {
						continue
					}
					lit, ok := pair.Value.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					sqls = append(sqls, s)
				}
			}
			return false
		})
		return false
	})
	if len(sqls) == 0 {
		t.Fatalf("no SQL statements extracted from upgrades slice in %s; the AST extraction logic is out of sync with the code structure", fileName)
	}
	return sqls
}

// parseInitSQL extracts tableColumns + enumValues from CREATE TABLE / CREATE TYPE
// blocks (anywhere in the file — fresh installs execute the entire file), and
// ALTER TABLE ADD COLUMN / ALTER TYPE ADD VALUE statements from the UPGRADE
// SECTION at the bottom.
func parseInitSQL(t *testing.T, src string) (
	tableColumns map[string]map[string]bool,
	enumValues map[string]map[string]bool,
	upgradeAddColumns map[sqlRef]bool,
	upgradeAddValues map[sqlRef]bool,
) {
	tableColumns = map[string]map[string]bool{}
	enumValues = map[string]map[string]bool{}
	upgradeAddColumns = map[sqlRef]bool{}
	upgradeAddValues = map[sqlRef]bool{}

	// Strip line comments so they don't confuse the parsers (e.g., a column
	// regex matching a commented-out ALTER).
	stripped := stripLineComments(src)

	// Find UPGRADE SECTION boundary in the stripped text.
	bannerRE := regexp.MustCompile(`(?m)^--\s*UPGRADE SECTION`)
	// Banner regex needs to run on original src since stripLineComments removed it.
	// We'll find boundary on src and then map indices. Easier: split src first,
	// then strip comments from each part.
	origBannerLoc := bannerRE.FindStringIndex(src)
	var pre, post string
	if origBannerLoc == nil {
		t.Logf("warning: UPGRADE SECTION banner not found; treating entire file as pre-upgrade")
		pre = stripped
		post = ""
	} else {
		pre = stripLineComments(src[:origBannerLoc[0]])
		post = stripLineComments(src[origBannerLoc[1]:])
	}

	// Parse CREATE TABLE blocks from the entire file (pre + post). On fresh
	// install, the whole file is executed, so a CREATE TABLE inside the
	// UPGRADE SECTION (e.g., filter_subscriptions) is also a fresh-install
	// declaration source.
	whole := pre + "\n" + post
	parseCreateTables(whole, tableColumns)
	parseCreateEnums(whole, enumValues)

	// Parse UPGRADE SECTION for ALTER TABLE ADD COLUMN + ALTER TYPE ADD VALUE.
	addColumnRE := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:public\.)?(\w+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(\w+)`)
	for _, m := range addColumnRE.FindAllStringSubmatch(post, -1) {
		upgradeAddColumns[sqlRef{strings.ToLower(m[1]), strings.ToLower(m[2])}] = true
	}
	addValueRE := regexp.MustCompile(`(?i)ALTER\s+TYPE\s+(?:public\.)?(\w+)\s+ADD\s+VALUE\s+IF\s+NOT\s+EXISTS\s+'([^']+)'`)
	for _, m := range addValueRE.FindAllStringSubmatch(post, -1) {
		upgradeAddValues[sqlRef{strings.ToLower(m[1]), strings.ToLower(m[2])}] = true
	}
	return
}

// stripLineComments removes `-- ...` line comments from SQL while preserving
// line breaks for downstream regex line behavior.
func stripLineComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		b.WriteString(line)
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// parseCreateTables scans src for `CREATE TABLE [IF NOT EXISTS] [public.]name (...)`
// blocks and adds each column name to tableColumns[name].
func parseCreateTables(src string, tableColumns map[string]map[string]bool) {
	// We do paren-aware scanning rather than a single regex, because column
	// definitions contain parenthesized DEFAULT/CHECK expressions.
	headRE := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)\s*\(`)
	idxs := headRE.FindAllStringSubmatchIndex(src, -1)
	for _, m := range idxs {
		// m[0] = start of CREATE TABLE, m[1] = end of "CREATE TABLE ... (" (inclusive of opening paren)
		// m[2:4] = match indices for the table name capture group (1).
		table := strings.ToLower(src[m[2]:m[3]])
		// Find matching close paren starting from m[1] (which is just past `(`).
		bodyStart := m[1]
		depth := 1
		i := bodyStart
		for i < len(src) && depth > 0 {
			switch src[i] {
			case '\'':
				// skip string literal
				i++
				for i < len(src) {
					if src[i] == '\'' {
						// handle '' escape
						if i+1 < len(src) && src[i+1] == '\'' {
							i += 2
							continue
						}
						i++
						break
					}
					i++
				}
			case '(':
				depth++
				i++
			case ')':
				depth--
				if depth == 0 {
					break
				}
				i++
			default:
				i++
			}
			if depth == 0 {
				break
			}
		}
		if depth != 0 {
			continue // unterminated; skip
		}
		body := src[bodyStart:i]
		if tableColumns[table] == nil {
			tableColumns[table] = map[string]bool{}
		}
		for c := range extractColumnsFromCreateBody(body) {
			tableColumns[table][c] = true
		}
	}
}

// parseCreateEnums scans src for CREATE TYPE ... AS ENUM (...) blocks.
func parseCreateEnums(src string, enumValues map[string]map[string]bool) {
	createEnumRE := regexp.MustCompile(`(?is)CREATE\s+TYPE\s+(?:public\.)?(\w+)\s+AS\s+ENUM\s*\(([^)]*?)\)`)
	for _, m := range createEnumRE.FindAllStringSubmatch(src, -1) {
		enum := strings.ToLower(m[1])
		if enumValues[enum] == nil {
			enumValues[enum] = map[string]bool{}
		}
		for _, v := range extractEnumValues(m[2]) {
			enumValues[enum][v] = true
		}
	}
}

// parseUpgradeStatements scans the upgrades slice SQL strings for ADD COLUMN /
// ADD VALUE references — the structural facts the test enforces.
func parseUpgradeStatements(sqls []string) (
	addColumns map[sqlRef]bool, addValues map[sqlRef]bool,
) {
	addColumns = map[sqlRef]bool{}
	addValues = map[sqlRef]bool{}
	addColumnRE := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:public\.)?(\w+)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+(\w+)`)
	addValueRE := regexp.MustCompile(`(?i)ALTER\s+TYPE\s+(?:public\.)?(\w+)\s+ADD\s+VALUE\s+IF\s+NOT\s+EXISTS\s+'([^']+)'`)
	// Also pick up CREATE TABLE columns within upgrade SQLs — these are
	// equivalent to "this table+column will exist for existing installs."
	// We do NOT use these for the structural check (they're an upgrades-side
	// declaration, not a fresh-install declaration), so this comment is just
	// for clarity.
	for _, sql := range sqls {
		for _, m := range addColumnRE.FindAllStringSubmatch(sql, -1) {
			addColumns[sqlRef{strings.ToLower(m[1]), strings.ToLower(m[2])}] = true
		}
		for _, m := range addValueRE.FindAllStringSubmatch(sql, -1) {
			addValues[sqlRef{strings.ToLower(m[1]), strings.ToLower(m[2])}] = true
		}
	}
	return
}

// extractColumnsFromCreateBody scans a CREATE TABLE body (without the wrapping
// parens), splitting on commas at the top level, and grabs the first identifier
// of each item. PRIMARY KEY / CONSTRAINT / FOREIGN KEY etc. are skipped.
func extractColumnsFromCreateBody(body string) map[string]bool {
	out := map[string]bool{}
	items := splitTopLevelCommas(body)
	skipPrefix := regexp.MustCompile(`(?i)^(primary\s+key|constraint|foreign\s+key|unique|check|exclude|like)\b`)
	nameRE := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if skipPrefix.MatchString(s) {
			continue
		}
		m := nameRE.FindString(s)
		if m == "" {
			continue
		}
		out[strings.ToLower(m)] = true
	}
	return out
}

// splitTopLevelCommas splits s on commas that are at paren-depth 0,
// treating single-quoted strings as opaque.
func splitTopLevelCommas(s string) []string {
	var out []string
	depth := 0
	start := 0
	i := 0
	for i < len(s) {
		switch s[i] {
		case '\'':
			// skip string literal (handle '' escape)
			i++
			for i < len(s) {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case '(':
			depth++
			i++
		case ')':
			depth--
			i++
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
			i++
		default:
			i++
		}
	}
	out = append(out, s[start:])
	return out
}

// extractEnumValues parses `'a', 'b', 'c'` from a CREATE TYPE body.
func extractEnumValues(body string) []string {
	var out []string
	re := regexp.MustCompile(`'([^']+)'`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.ToLower(m[1]))
	}
	sort.Strings(out)
	return out
}

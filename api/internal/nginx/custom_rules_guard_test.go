package nginx

// The shipped static nginx/modsec/custom-rules.conf carries two path-scoped
// engine exemptions: the health check (id 1000) and Socket.IO (id 1002). Keyed
// on the raw REQUEST_URI they switched the WAF engine off for any request whose
// path merely STARTED like one of those endpoints, dot segments and all:
// "/health/../?id=..." was handed the full exemption and reached the upstream
// with no inspection, and a backend that resolves "/health/../" to "/" served
// it. That is the same class of bypass the v2.60.0 fix closed for the generated
// per-host exclusions (waf_config.go / request_path_map.go).
//
// The rules now match REQUEST_FILENAME after t:none,t:normalizePath and chain
// the SAME guard the generated exclusions use, so a path a backend may resolve
// elsewhere keeps the engine on. A static conf file cannot call into Go, so the
// guard regex is written out by hand. This test reads the file and pins it to
// that contract: every path-keyed engine exemption must match REQUEST_FILENAME,
// carry t:normalizePath, and chain a guard whose regex equals unsafePathGuard()
// exactly. If unsafeRequestPathPattern changes and the file is not regenerated,
// or an exemption is reintroduced on the raw path, this fails. It runs against
// the OLD file too (REQUEST_URI, no normalizePath, no chain) and fails it.

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// customRulesPath is the shipped file, relative to this package
// (api/internal/nginx -> repo root/nginx/modsec/custom-rules.conf).
var customRulesPath = filepath.Join("..", "..", "..", "nginx", "modsec", "custom-rules.conf")

var customRuleIDPattern = regexp.MustCompile(`\bid:(\d+)\b`)

// customRulesDirectives reconstructs the logical ModSecurity directives from
// the file: a physical line ending in "\" continues onto the next, so a SecRule
// and its action list collapse into one logical line. Comment and blank lines
// are dropped. No directive in this file contains a '"' or '#' in its regex, so
// splitting the result on '"' recovers the operator and action-list arguments.
func customRulesDirectives(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(customRulesPath)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not present in this checkout", customRulesPath)
	}
	if err != nil {
		t.Fatalf("read %s: %v", customRulesPath, err)
	}
	var directives []string
	var cur strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if cur.Len() == 0 {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue // comment or blank between directives
			}
		}
		if strings.HasSuffix(line, `\`) {
			cur.WriteString(strings.TrimSuffix(line, `\`))
			continue
		}
		cur.WriteString(line)
		if s := strings.TrimSpace(cur.String()); s != "" {
			directives = append(directives, s)
		}
		cur.Reset()
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		directives = append(directives, s)
	}
	return directives
}

func directiveRelaxesEngine(d string) bool {
	return strings.Contains(d, "ctl:ruleEngine=Off") || strings.Contains(d, "ctl:ruleRemoveById")
}

func TestCustomRulesPathExemptionsUseNormalizedGuard(t *testing.T) {
	directives := customRulesDirectives(t)
	if len(directives) == 0 {
		t.Fatalf("no SecRule directives parsed from %s", customRulesPath)
	}

	// unsafePathGuard() in the func map returns exactly this; both read the one
	// package const, so a change to the pattern changes what the file must say.
	guard := `(?i)(?:` + unsafeRequestPathPattern + `)`

	// No exemption may be decided on the raw, un-normalized request path again.
	// REQUEST_URI is what "/health/../" rode through; REQUEST_FILENAME after
	// t:normalizePath is the decoded, normalized path nginx actually routed.
	for _, d := range directives {
		if strings.HasPrefix(d, "SecRule REQUEST_URI") {
			t.Errorf("rule keyed on the raw REQUEST_URI (defeated by a dot segment such as /health/../): %s", d)
		}
	}

	// Walk the directives as ModSecurity chains: a directive whose actions carry
	// "chain" is joined with the directives that follow it, up to and including
	// the first one that does not carry "chain".
	foundIDs := map[string]bool{}
	for i := 0; i < len(directives); {
		group := []string{directives[i]}
		for strings.Contains(directives[i], "chain") && i+1 < len(directives) {
			i++
			group = append(group, directives[i])
		}
		i++

		starter := group[0]
		fields := strings.Fields(starter)
		if len(fields) < 2 || fields[0] != "SecRule" {
			continue
		}
		variable := fields[1]

		relaxes := false
		for _, d := range group {
			if directiveRelaxesEngine(d) {
				relaxes = true
			}
		}
		// Only path-keyed engine exemptions must carry the guard. Rule 1003
		// (REQUEST_HEADERS:Upgrade) and 1010 (REQUEST_PROTOCOL) relax the engine
		// on a header / protocol, not on the path, so there is no path to guard.
		if variable != "REQUEST_FILENAME" || !relaxes {
			continue
		}

		id := "?"
		if m := customRuleIDPattern.FindStringSubmatch(starter); m != nil {
			id = m[1]
		}
		foundIDs[id] = true

		// The starter decides on the normalized path and only opens the chain.
		for _, want := range []string{"t:none", "t:normalizePath", "chain"} {
			if !strings.Contains(starter, want) {
				t.Errorf("rule id %s: chain starter is missing %q (decide on the normalized path): %s", id, want, starter)
			}
		}
		if directiveRelaxesEngine(starter) {
			t.Errorf("rule id %s: the engine-relaxing ctl is on the chain starter, so it fires before the guard runs: %s", id, starter)
		}

		// A later member must refuse the unsafe paths with the exact guard, and
		// carry the ctl, so the exemption is withheld for a path a backend may
		// resolve elsewhere.
		guarded := false
		for _, d := range group[1:] {
			parts := strings.Split(d, `"`)
			if len(parts) < 2 || !strings.HasPrefix(parts[1], "!@rx ") {
				continue
			}
			if got := strings.TrimPrefix(parts[1], "!@rx "); got != guard {
				t.Errorf("rule id %s: chained guard regex has drifted from unsafePathGuard().\n got: %s\nwant: %s", id, got, guard)
				continue
			}
			if !directiveRelaxesEngine(d) {
				t.Errorf("rule id %s: guard member does not carry the engine-relaxing ctl: %s", id, d)
			}
			guarded = true
		}
		if !guarded {
			t.Errorf("rule id %s: path exemption has no chained guard matching unsafePathGuard()", id)
		}
	}

	// The health check and Socket.IO exemptions must still be present (and, by
	// the checks above, guarded). This keeps the test from passing vacuously if
	// the rules are deleted, and it is a second way the old file fails: there
	// they key on REQUEST_URI, so they are never recognised here.
	for _, id := range []string{"1000", "1002"} {
		if !foundIDs[id] {
			t.Errorf("expected a guarded REQUEST_FILENAME path exemption with id %s in %s", id, customRulesPath)
		}
	}
}

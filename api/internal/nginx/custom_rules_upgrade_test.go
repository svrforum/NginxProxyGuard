package nginx

// docker-entrypoint.sh runs nginx/scripts/upgrade-custom-rules.sh on every
// start. custom-rules.conf lives in the nginx volume and is never refreshed
// from the image, because operators add their own rules to it, so without the
// script the v2.60.1 fixes to NPG's rules 1000 (health check), 1002 (Socket.IO)
// and 1003 (WebSocket) would reach fresh installs only. These tests run the
// real script against fixture files: with the sh and awk on PATH, and again
// under busybox when it is installed, because the nginx image runs busybox sh
// and awk.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	upgradeScriptPath = filepath.Join("..", "..", "..", "nginx", "scripts", "upgrade-custom-rules.sh")
	// The custom-rules.conf installs from v1.0.1 through v2.60.0 started with.
	shippedRulesV2600Path = filepath.Join("..", "..", "..", "nginx", "scripts", "custom-rules.conf.v2.60.0")
)

// The script recognises an untouched file by comparing it byte for byte with
// custom-rules.conf.v2.60.0, so that copy must stay exactly what was shipped.
const shippedRulesV2600SHA256 = "f2d7a4d99df4bdd68a15d35dd3a544e5e7a6d7c1569c23e875023dc4c840570f"

// NPG's rules as v1.0.1 through v2.60.0 shipped them, i.e. as old installs
// still have them.
var oldShippedRules = map[string]string{
	"1000": `SecRule REQUEST_URI "@beginsWith /health" \
    "id:1000,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleEngine=Off"
`,
	"1002": `SecRule REQUEST_URI "@beginsWith /socket.io" \
    "id:1002,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleEngine=Off"
`,
	"1003": `SecRule REQUEST_HEADERS:Upgrade "@streq websocket" \
    "id:1003,\
    phase:1,\
    pass,\
    nolog,\
    ctl:ruleEngine=Off"
`,
}

type upgradeShell struct {
	name string
	argv []string // interpreter, the script and its arguments follow
	env  []string // nil inherits the test's environment
}

// upgradeShells returns the shells to run the script with, or skips the test
// when there is no script or no shell to run it.
func upgradeShells(t *testing.T) []upgradeShell {
	t.Helper()
	if _, err := os.Stat(upgradeScriptPath); errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not present in this checkout", upgradeScriptPath)
	}
	var shells []upgradeShell
	if sh, err := exec.LookPath("sh"); err == nil {
		if _, err := exec.LookPath("awk"); err == nil {
			shells = append(shells, upgradeShell{name: "sh", argv: []string{sh}})
		}
	}
	// PATH holds nothing but busybox applets, as in the nginx image, so a
	// command the script needs that busybox lacks fails here, not on upgrade.
	if bb, err := exec.LookPath("busybox"); err == nil {
		applets, _ := exec.Command(bb, "--list").Output()
		have := map[string]bool{}
		for _, a := range strings.Fields(string(applets)) {
			have[a] = true
		}
		dir := t.TempDir()
		ok := true
		for _, a := range []string{"sh", "awk", "cmp", "cp", "mv", "cat", "rm"} {
			if !have[a] {
				ok = false
				break
			}
			if err := os.Symlink(bb, filepath.Join(dir, a)); err != nil {
				t.Fatal(err)
			}
		}
		if ok {
			shells = append(shells, upgradeShell{name: "busybox", argv: []string{bb, "sh"}, env: []string{"PATH=" + dir}})
		}
	}
	if len(shells) == 0 {
		t.Skip("no sh+awk or busybox to run the script with")
	}
	return shells
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runUpgrade runs the script on cur with the shipped files as the new and the
// old default, and returns what it printed.
func runUpgrade(t *testing.T, sh upgradeShell, cur string) string {
	t.Helper()
	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	args := append([]string{}, sh.argv[1:]...)
	args = append(args, abs(upgradeScriptPath), cur, abs(customRulesPath), abs(shippedRulesV2600Path))
	cmd := exec.Command(sh.argv[0], args...)
	if sh.env != nil {
		cmd.Env = sh.env
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: upgrade script failed: %v\n%s", sh.name, err, out)
	}
	return string(out)
}

// ruleText returns the rule carrying id in conf exactly as written there: the
// line holding the id with the lines around it joined by trailing backslashes
// and, when the rule chains, the statement chained to it.
func ruleText(t *testing.T, conf, id string) string {
	t.Helper()
	lines := strings.SplitAfter(conf, "\n")
	continues := func(i int) bool { return strings.HasSuffix(strings.TrimRight(lines[i], "\r\n"), `\`) }
	start := -1
	for i, l := range lines {
		if strings.Contains(l, `"id:`+id+`,`) {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no rule with id %s", id)
	}
	for start > 0 && continues(start-1) {
		start--
	}
	end := start
	for {
		first := end
		for continues(end) {
			end++
		}
		if !strings.Contains(strings.Join(lines[first:end+1], ""), `chain"`) {
			break
		}
		end++
	}
	return strings.Join(lines[start:end+1], "")
}

func TestShippedCustomRulesV2600IsUnchanged(t *testing.T) {
	b, err := os.ReadFile(shippedRulesV2600Path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s is not present in this checkout", shippedRulesV2600Path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != shippedRulesV2600SHA256 {
		t.Fatalf("%s changed (sha256 %x): it must stay byte-identical to the custom-rules.conf v1.0.1-v2.60.0 shipped, or untouched installs are no longer recognised", shippedRulesV2600Path, sum)
	}
	for id, rule := range oldShippedRules {
		if !strings.Contains(string(b), rule) {
			t.Errorf("old rule %s is not in %s as written in oldShippedRules", id, shippedRulesV2600Path)
		}
	}
}

func TestUpgradeCustomRules(t *testing.T) {
	shells := upgradeShells(t)
	oldDefault := readTestFile(t, shippedRulesV2600Path)
	newDefault := readTestFile(t, customRulesPath)

	// The expected surgical upgrade: the exact text of each listed old rule is
	// swapped for the exact text of the shipped rule, nothing else changes.
	upgraded := func(s string, oldText map[string]string, ids ...string) string {
		for _, id := range ids {
			if strings.Count(s, oldText[id]) != 1 {
				t.Fatalf("fixture must hold old rule %s exactly once", id)
			}
			s = strings.Replace(s, oldText[id], ruleText(t, newDefault, id), 1)
		}
		return s
	}

	// An old install with the operator's own rules around and between NPG's:
	// one keyed on a /health path, one on the Upgrade header, one that
	// continues over two lines.
	withUserRules := "# Operator rules\n" +
		`SecRule REQUEST_URI "@beginsWith /healthcheck-internal" "id:9001,phase:1,deny,status:403"` + "\n\n" +
		strings.NewReplacer(
			"# Note: localhost", `SecRule REQUEST_HEADERS:X-Debug "@streq 1" \`+"\n    \"id:9002,phase:1,deny,status:403\"\n\n# Note: localhost",
			"# Allow common WebSocket", `SecRule REQUEST_HEADERS:Upgrade "@streq h2c" "id:9003,phase:1,deny,status:403"`+"\n# Allow common WebSocket",
		).Replace(oldDefault) +
		"\n# Keep the WAF on for the admin API\n" + `SecRule REQUEST_FILENAME "@beginsWith /admin" "id:9004,phase:1,pass,nolog,ctl:ruleEngine=On"` + "\n"

	// The same rules with only their layout changed: 1002 on one line, 1003
	// indented with tabs, the whole file with CRLF line endings.
	reformatted := map[string]string{
		"1000": oldShippedRules["1000"],
		"1002": `SecRule REQUEST_URI "@beginsWith /socket.io" "id:1002,phase:1,pass,nolog,ctl:ruleEngine=Off"` + "\n",
		"1003": strings.ReplaceAll(oldShippedRules["1003"], "    ", "\t"),
	}
	crlf := map[string]string{}
	for id, s := range reformatted {
		crlf[id] = strings.ReplaceAll(s, "\n", "\r\n")
	}
	reformattedFile := strings.ReplaceAll(strings.NewReplacer(
		oldShippedRules["1002"], reformatted["1002"],
		oldShippedRules["1003"], reformatted["1003"],
	).Replace(oldDefault), "\n", "\r\n")

	edited1000Old := strings.Replace(oldDefault, `"@beginsWith /health"`, `"@beginsWith /healthz"`, 1)
	edited1000New := strings.Replace(newDefault, `"@rx \A/health"`, `"@rx \A/healthz"`, 1)

	cases := []struct {
		name    string
		file    string // "" = there is no custom-rules.conf
		backup  string // pre-existing custom-rules.conf.pre-v2.60.1, "" = none
		want    string
		changed bool   // the script rewrote the file (and keeps a backup)
		warn    string // the rule ids a WARN must name, "" = no WARN
	}{
		{name: "untouched old default becomes the new default", file: oldDefault, want: newDefault, changed: true},
		{name: "operator rules kept, only NPG rules replaced", file: withUserRules,
			want: upgraded(withUserRules, oldShippedRules, "1000", "1002", "1003"), changed: true},
		{name: "old rules recognised whatever their layout", file: reformattedFile,
			want: upgraded(reformattedFile, crlf, "1000", "1002", "1003"), changed: true},
		{name: "already upgraded file is left alone", file: newDefault, want: newDefault},
		{name: "locally edited rule is left alone with a WARN", file: edited1000New, want: edited1000New, warn: "1000"},
		{name: "unedited rules upgraded next to an edited one", file: edited1000Old,
			want: upgraded(edited1000Old, oldShippedRules, "1002", "1003"), changed: true, warn: "1000"},
		{name: "an earlier backup is never overwritten", file: oldDefault, backup: "an earlier backup\n", want: newDefault, changed: true},
		{name: "no file, nothing to do"},
	}

	for _, sh := range shells {
		for _, tc := range cases {
			t.Run(sh.name+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				cur := filepath.Join(dir, "custom-rules.conf")
				backup := cur + ".pre-v2.60.1"
				if tc.file != "" {
					if err := os.WriteFile(cur, []byte(tc.file), 0o644); err != nil {
						t.Fatal(err)
					}
					// The v2.60.0 image shipped the file 0666: the mode must survive.
					if err := os.Chmod(cur, 0o666); err != nil {
						t.Fatal(err)
					}
				}
				if tc.backup != "" {
					if err := os.WriteFile(backup, []byte(tc.backup), 0o644); err != nil {
						t.Fatal(err)
					}
				}

				out := runUpgrade(t, sh, cur)

				if tc.warn != "" {
					if !strings.Contains(out, "WARN") || !strings.Contains(out, " "+tc.warn+" ") {
						t.Errorf("want a WARN naming rule %s, got:\n%s", tc.warn, out)
					}
				} else if strings.Contains(out, "WARN") {
					t.Errorf("unexpected WARN:\n%s", out)
				}
				if !tc.changed && tc.warn == "" && out != "" {
					t.Errorf("nothing to do, but the script printed:\n%s", out)
				}

				wantFiles := map[string]bool{}
				if tc.file != "" {
					wantFiles["custom-rules.conf"] = true
					if got := readTestFile(t, cur); got != tc.want {
						t.Errorf("custom-rules.conf after the upgrade:\n%s\nwant:\n%s", got, tc.want)
					}
					if fi, err := os.Stat(cur); err != nil || fi.Mode().Perm() != 0o666 {
						t.Errorf("custom-rules.conf mode changed: %v %v", fi.Mode(), err)
					}
				}
				wantBackup := tc.backup
				if tc.changed && wantBackup == "" {
					wantBackup = tc.file
				}
				if wantBackup != "" {
					wantFiles["custom-rules.conf.pre-v2.60.1"] = true
					if got := readTestFile(t, backup); got != wantBackup {
						t.Errorf("backup holds:\n%s\nwant:\n%s", got, wantBackup)
					}
				}
				// Nothing else is left behind (temp file).
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if !wantFiles[e.Name()] {
						t.Errorf("unexpected file left in the directory: %s", e.Name())
					}
				}
				if len(entries) != len(wantFiles) {
					t.Errorf("files in the directory: %d, want %v", len(entries), wantFiles)
				}

				// A second start changes nothing and, unless a rule is still
				// edited, prints nothing.
				out = runUpgrade(t, sh, cur)
				if tc.warn == "" && out != "" {
					t.Errorf("second run printed:\n%s", out)
				}
				if tc.file != "" {
					if got := readTestFile(t, cur); got != tc.want {
						t.Errorf("second run changed custom-rules.conf")
					}
				}
				if wantBackup != "" && readTestFile(t, backup) != wantBackup {
					t.Errorf("second run changed the backup")
				}
			})
		}
	}
}

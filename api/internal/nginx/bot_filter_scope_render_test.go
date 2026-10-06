package nginx

// A custom_allowed_agents line may limit its exemption to paths (#313). These
// tests pin the rendered shape: the path is decided on $npg_request_path (not
// $uri, not $request_uri), the exemption is set before any bot-filter check
// reads it, each line costs one `if` whatever its path count, unusable lines
// never reach the config, and a value with no such line renders exactly as
// before.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func scopedBotFilterData(allowed string, ssl bool) ProxyHostConfigData {
	host := baseHost("00000000-0000-0000-0000-0000000000b8", "192.0.2.20", true)
	if ssl {
		certID := "00000000-0000-0000-0000-00000000cert"
		host.SSLEnabled, host.CertificateID = true, &certID
	}
	return ProxyHostConfigData{
		Host:                  host,
		BotFilter:             &model.BotFilter{Enabled: true, BlockSuspiciousClients: true, CustomAllowedAgents: allowed},
		SuspiciousClientsList: "curl\nokhttp\npython-requests",
	}
}

func TestScopedAllowedAgentRender(t *testing.T) {
	const allowed = "GoodBot\nokhttp @ /api /v2/\nokhttp @ api\nokhttp @ /a;b\nMy Bot @ /"
	for _, ssl := range []bool{false, true} {
		out := renderForTest(t, scopedBotFilterData(allowed, ssl))

		site := "    if ($http_user_agent ~* (GoodBot|My\\sBot)) {\n        set $priority_allow 1;\n    }"
		scoped := `    set $bot_scoped_subject "$npg_request_path\n$http_user_agent";
    # only under: /api /v2/
    if ($bot_scoped_subject ~ (\A(?:/api|/v2)(?:/[^\n]*)?\n.*(?i:okhttp))) {
        set $priority_allow 1;
    }`
		servers := 1
		if ssl {
			servers = 2 // the security partial is in the HTTP and the HTTPS server block
		}
		if n := strings.Count(out, site); n != servers {
			t.Errorf("ssl=%v: whole-host line rendered %d times, want %d", ssl, n, servers)
		}
		if n := strings.Count(out, scoped); n != servers {
			t.Errorf("ssl=%v: scoped block rendered %d times, want %d:\n%s", ssl, n, servers, out)
		}
		// $priority_allow is read by the checks that follow, so the scoped
		// exemption must be set before the first of them.
		if i, j := strings.Index(out, scoped), strings.Index(out, "set $block_suspicious 0;"); i < 0 || j < 0 || i > j {
			t.Errorf("ssl=%v: scoped exemption (at %d) must precede the suspicious-client check (at %d)", ssl, i, j)
		}
		// Unusable lines are dropped, never rendered as a user agent.
		for _, absent := range []string{`okhttp\s@\sapi`, `/a;b`, `/a\;b`, `\s@\s`, `@/`} {
			if strings.Contains(out, absent) {
				t.Errorf("ssl=%v: an unusable line reached the config: %q", ssl, absent)
			}
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "bot_scoped") && (strings.Contains(line, "$uri") || strings.Contains(line, "$request_uri")) {
				t.Errorf("ssl=%v: scoped path decided on a variable that changes or is raw: %s", ssl, line)
			}
		}
	}
}

// One pattern covers the line's paths and everything below them, nothing
// beside them, and never "" (what $npg_request_path is for a path a backend
// may read differently); the agent is matched case-insensitively, and only in
// the User-Agent part of the subject.
func TestScopedAllowedAgentPathBoundary(t *testing.T) {
	got := scopedAllowedAgents("okhttp @ /api /c++/ /my.app")
	if len(got) != 1 || len(got[0].Patterns) != 1 {
		t.Fatalf("scopedAllowedAgents = %+v", got)
	}
	re := regexp.MustCompile(got[0].Patterns[0])
	match := func(path, ua string) bool { return re.MatchString(path + "\n" + ua) }
	for _, path := range []string{"/api", "/api/", "/api/v1/x", "/api/my docs", "/c++", "/c++/x", "/my.app/x"} {
		if !match(path, "okhttp/4.12.0") {
			t.Errorf("%q should be covered", path)
		}
	}
	for _, path := range []string{"", "/", "/api-admin", "/apiv2", "/api x", "/API/v1", "/admin/api", "/c", "/myxapp", "/my.application"} {
		if match(path, "okhttp/4.12.0") {
			t.Errorf("%q should not be covered", path)
		}
	}
	if !match("/api/x", "Mozilla/5.0 OkHttp/5") {
		t.Errorf("the agent part must match case-insensitively, anywhere in the User-Agent")
	}
	for _, c := range [][2]string{{"/api/okhttp", "curl/8.5.0"}, {"/api/x", ""}} {
		if match(c[0], c[1]) {
			t.Errorf("path %q with User-Agent %q should not be covered", c[0], c[1])
		}
	}
}

// Every `if` costs nginx a location context (about 30 KB with ModSecurity) in
// each server block, and a global list renders into every inheriting host, so
// a path-limited line renders one `if`, however many paths it names (unless
// they do not fit one nginx token, TestScopedAllowedAgentFitsNginxToken).
func TestScopedAllowedAgentOneIfPerLine(t *testing.T) {
	var lines []string
	for i := 0; i < model.MaxScopedAllowedAgents; i++ {
		var paths []string
		for j := 0; j < model.MaxAllowedAgentPaths; j++ {
			paths = append(paths, fmt.Sprintf("/svc%d/p%d", i, j))
		}
		lines = append(lines, fmt.Sprintf("Client%d @ %s", i, strings.Join(paths, " ")))
	}
	base := renderForTest(t, scopedBotFilterData("GoodBot", true))
	full := renderForTest(t, scopedBotFilterData("GoodBot\n"+strings.Join(lines, "\n"), true))
	const servers = 2 // an SSL host renders the bot filter in its HTTP and HTTPS server block
	if got, want := strings.Count(full, "if (")-strings.Count(base, "if ("), model.MaxScopedAllowedAgents*servers; got != want {
		t.Errorf("%d path-limited lines of %d paths added %d `if` blocks, want %d (one per line per server block)",
			model.MaxScopedAllowedAgents, model.MaxAllowedAgentPaths, got, want)
	}
}

// nginx refuses a config token longer than 4094 bytes, which fails nginx -t
// for every host. The longest line the parser accepts (a 500-byte agent and ten
// 255-byte paths, every byte escaped to \xHH) is split into patterns that fit,
// and each of its paths is still covered by one of them.
func TestScopedAllowedAgentFitsNginxToken(t *testing.T) {
	agent := strings.Repeat(`\`, 500)
	var paths []string
	for j := 0; j < model.MaxAllowedAgentPaths; j++ {
		paths = append(paths, fmt.Sprintf("/%c%s", 'a'+j, strings.Repeat("@", 253)))
	}
	line := agent + " @ " + strings.Join(paths, " ")
	if err := model.ValidateAllowedAgents(line); err != nil {
		t.Fatalf("the longest line must be accepted, so the test covers it: %v", err)
	}
	got := scopedAllowedAgents(line)
	if len(got) != 1 || len(got[0].Patterns) < 2 || len(got[0].Patterns) > len(paths) {
		t.Fatalf("want the line split into 2..%d patterns, got %+v", len(paths), got)
	}
	for _, p := range got[0].Patterns {
		if len(p) > maxScopedPattern || len("("+p+"))") > 4094 {
			t.Errorf("a pattern of %d bytes does not fit one nginx token", len(p))
		}
	}
	for _, path := range paths {
		n := 0
		for _, p := range got[0].Patterns {
			if regexp.MustCompile(p).MatchString(path + "/x\n" + "okhttp " + agent) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("path %.8s... is covered by %d patterns, want 1", path, n)
		}
	}
}

// Dropping an unusable line leaves the output exactly as if it had never been
// there, and a value without scoped lines renders no scoped block at all.
func TestAllowedAgentsWithoutScopeRenderUnchanged(t *testing.T) {
	plain := renderForTest(t, scopedBotFilterData("GoodBot\nMy Monitor/1.0", true))
	withBad := renderForTest(t, scopedBotFilterData("GoodBot\nokhttp @ api\nMy Monitor/1.0\nokhttp @/api\nx @ //", true))
	if plain != withBad {
		t.Errorf("unusable lines changed the output")
	}
	if strings.Contains(plain, "bot_scoped") {
		t.Errorf("a value with no scoped line rendered a scoped block")
	}
	onlyBad := renderForTest(t, scopedBotFilterData("okhttp @ api", false))
	if strings.Contains(onlyBad, "Custom allowed agents") || strings.Contains(onlyBad, "bot_scoped") {
		t.Errorf("a value with only unusable lines rendered an exemption")
	}
}

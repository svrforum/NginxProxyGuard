package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renderDefaultServer(t *testing.T, action string) string {
	t.Helper()
	dir := t.TempDir()
	m := &Manager{configPath: dir, httpPort: "80", httpsPort: "443", apiURL: "http://127.0.0.1:9080"}
	if err := m.GenerateDefaultServerConfig(context.Background(), action); err != nil {
		t.Fatalf("generate(%s): %v", action, err)
	}
	out, err := os.ReadFile(filepath.Join(dir, "zzz_default.conf"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(out)
}

// Direct IP Access = block_444 promised "closes the connection with no
// response", but cleartext HTTP spoken to an `ssl` listener is finalized as
// nginx's internal 497 before the content phase, so `return 444` never saw it
// and the client got "400 Bad Request / The plain HTTP request was sent to
// HTTPS port". That was 52% of a week's unattributed 400s on one install (#280).
//
// Scoped to 497 on purpose: nginx also answers 400 for a request line it could
// not parse, but that decision happens before the Host header is read, so
// rescuing it would silently reset malformed requests aimed at a hostname the
// operator HAS configured. Those keep their diagnosable 400.
func TestDefaultServerBlock444RescuesPlainHTTPToTLSPort(t *testing.T) {
	cfg := renderDefaultServer(t, "block_444")

	if got := strings.Count(cfg, "error_page 497 =444 /_npg_close;"); got != 3 {
		t.Errorf("expected the 497 rescue in all 3 server blocks, found %d:\n%s", got, cfg)
	}
	if got := strings.Count(cfg, "location = /_npg_close"); got != 3 {
		t.Errorf("expected 3 named close locations, found %d", got)
	}
}

// The loopback block answers 444 unconditionally — it is not gated on the
// setting — so its rescue must be unconditional too. Cleartext sent to the
// HTTPS port with an IP-literal Host selects this block.
func TestDefaultServerLoopbackRescueIsUnconditional(t *testing.T) {
	for _, action := range []string{"allow", "block_403", "block_444"} {
		cfg := renderDefaultServer(t, action)
		loopback := cfg[strings.Index(cfg, "server_name localhost 127.0.0.1;"):]
		if !strings.Contains(loopback, "error_page 497 =444 /_npg_close;") {
			t.Errorf("action=%s: loopback block lost its rescue:\n%s", action, loopback)
		}
	}
}

// `allow` must keep nginx's stock behaviour: an operator who has not asked for
// anything to be blocked should still see a real 400 for a malformed request.
func TestDefaultServerAllowLeavesStatusesAlone(t *testing.T) {
	cfg := renderDefaultServer(t, "allow")
	// Only the unconditional loopback block may carry it.
	if got := strings.Count(cfg, "error_page 497 =444 /_npg_close;"); got != 1 {
		t.Errorf("allow should emit the rescue only in the loopback block, found %d:\n%s", got, cfg)
	}
}

// block_403 is deliberately NOT rescued: answering protocol garbage with the
// 10.8KB access-denied page is a ~72x amplification over nginx's 150-byte
// default and a new reflection surface. Pinned so a later "consistency" tidy
// does not quietly add it.
func TestDefaultServerBlock403IsNotRescued(t *testing.T) {
	cfg := renderDefaultServer(t, "block_403")
	if got := strings.Count(cfg, "error_page 497 =444 /_npg_close;"); got != 1 {
		t.Errorf("block_403 must not take the 444 rescue beyond the unconditional loopback block, found %d", got)
	}
	if !strings.Contains(cfg, "return 403;") {
		t.Error("block_403 should still answer 403 for matched-but-unknown hosts")
	}
}

// Paths the catch-all must keep answering whatever the action is.
func TestDefaultServerKeepsOperationalPaths(t *testing.T) {
	cfg := renderDefaultServer(t, "block_444")
	for _, want := range []string{
		"location /health",
		"location /.well-known/acme-challenge/",
		"location /api/v1/public/",
		"location = /__npg_canary",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("block_444 dropped %q", want)
		}
	}
}

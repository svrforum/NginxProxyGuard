package nginx

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// Without custom pages the configs keep the built-in pages exactly; with one,
// only that page moves to the custom directory, and it carries the CSP that
// keeps scripts from running on the proxied site's origin (#335).
func TestCustomErrorPagesRender(t *testing.T) {
	m, _ := newRequestPathTestManager(t)
	before := string(m.hostCommonIncludeContent())
	for _, want := range []string{
		"location = /error_502.html { internal; auth_request off; root /etc/nginx/html; try_files /502.html =502; }",
		"    root /etc/nginx/html;\n    default_type text/html;",
	} {
		if !strings.Contains(before, want) {
			t.Fatalf("built-in host_common lacks %q", want)
		}
	}
	if strings.Contains(before, "Content-Security-Policy") {
		t.Fatal("built-in pages carry the custom page CSP")
	}

	pages := []model.CustomErrorPage{{StatusCode: 403, HTML: "<h1>No</h1>"}, {StatusCode: 503, HTML: "<h1>Later</h1>"}}
	if err := m.ApplyCustomErrorPages(context.Background(), pages, "allow"); err != nil {
		t.Fatalf("ApplyCustomErrorPages: %v", err)
	}
	common, _ := os.ReadFile(filepath.Join(m.configPath, "includes", "host_common.conf"))
	csp := `add_header Content-Security-Policy "` + customErrorPageCSP + `" always;`
	for _, want := range []string{
		"location = /error_503.html { internal; auth_request off; root " + CustomErrorPageRenderDir + "; try_files /503.html =503; " + csp + " }",
		"location = /error_502.html { internal; auth_request off; root /etc/nginx/html; try_files /502.html =502; }",
		"    root " + CustomErrorPageRenderDir + ";\n    " + csp + "\n    default_type text/html;",
	} {
		if !strings.Contains(string(common), want) {
			t.Errorf("host_common.conf lacks %q:\n%s", want, common)
		}
	}
	def, _ := os.ReadFile(filepath.Join(m.configPath, "zzz_default.conf"))
	if !strings.Contains(string(def), "    location = /403.html {\n        root "+CustomErrorPageRenderDir+";\n        internal;\n        "+csp) ||
		!strings.Contains(string(def), "    location = /502.html {\n        root /etc/nginx/html;\n        internal;\n    }") {
		t.Errorf("default server error pages:\n%s", def)
	}
	if got, _ := os.ReadFile(filepath.Join(m.customErrorPageDiskDir(), "403.html")); string(got) != "<h1>No</h1>" {
		t.Errorf("403 page on disk = %q", got)
	}
	for _, s := range []string{"default-src 'none'", "sandbox", "frame-ancestors 'none'"} {
		if !strings.Contains(customErrorPageCSP, s) {
			t.Errorf("CSP lacks %q", s)
		}
	}

	// Resetting every page brings back the built-in configs byte for byte.
	if err := m.ApplyCustomErrorPages(context.Background(), nil, "allow"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if after := string(m.hostCommonIncludeContent()); after != before {
		t.Errorf("host_common after reset differs from the built-in one")
	}
	if _, err := os.Stat(filepath.Join(m.customErrorPageDiskDir(), "403.html")); !os.IsNotExist(err) {
		t.Errorf("403 page left on disk after reset: %v", err)
	}
}

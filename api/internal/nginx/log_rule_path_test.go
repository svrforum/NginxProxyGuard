package nginx

import "testing"

// A host's path prefix log rules (#347) apply only where nginx's request path
// guard would give a path-scoped exemption: the spellings it refuses never
// match a prefix, so a request cannot hide from the logs by them.
func TestLogRulePath(t *testing.T) {
	for target, want := range map[string]string{
		"/remote.php/dav/files/a.txt?x=1": "/remote.php/dav/files/a.txt",
		"/files/My%20File":                "/files/My File",
		"/static/x#frag":                  "/static/x",
		"/":                               "/",
		"/a;b/c":                          "/a;b/c",
		"/.well-known/x":                  "/.well-known/x",
		"/caf%C3%A9":                      "/café",
	} {
		if got, ok := LogRulePath(target); !ok || got != want {
			t.Errorf("%q = %q, %v; want %q", target, got, ok, want)
		}
	}
	for _, target := range []string{
		"/static/../admin", "/static/./x", "/static/%2E%2E/admin", "/static/%2e/x", // dot segments nginx resolves
		"/static/x#/../../admin",            // a fragment proxy_pass forwards
		"/static/..;/admin", "/static/.;/x", // Tomcat and Jetty path parameters
		"/static/%252e%252e/admin", "/static/..%252f/x", // encoded twice
		"/static/%u002e%u002e/admin",                     // IIS %u escapes
		"/static/%c0%ae%c0%ae/admin", "/static/..%c0%af", // overlong UTF-8
		"/static/%0a../admin", "/static/a%09b", // control bytes
		"/static/..%20/admin", "/static/..../admin", // Windows trailing spaces and dots
		"/static//x", `/static\x`, "/static/%5cx", // separators a backend may read
		"*", "http://example.com/static/x", "/a%zz",
	} {
		if got, ok := LogRulePath(target); ok {
			t.Errorf("%q = %q, want it refused", target, got)
		}
	}
}

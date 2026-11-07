package nginx

import "testing"

func TestParseNginxVersion(t *testing.T) {
	for out, want := range map[string]string{
		"nginx version: nginx/1.29.4\n":          "1.29.4",
		"nginx version: nginx/1.30.0 (Ubuntu)\n": "1.30.0",
		"nginx version: openresty/1.25.3.1\n":    "",
		"":                                       "",
	} {
		got, err := parseNginxVersion(out)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("parseNginxVersion(%q) = %q, %v; want %q", out, got, err, want)
		}
	}
}

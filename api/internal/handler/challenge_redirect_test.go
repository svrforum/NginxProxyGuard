package handler

import "testing"

func TestSanitizeReturnURL(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"relative path", "/dashboard?tab=logs", "/dashboard?tab=logs"},
		{"same host", "https://panel.example.com:81/dashboard", "https://panel.example.com:81/dashboard"},
		{"external host", "https://attacker.example/", "/"},
		{"userinfo and port", "https://panel.example.com:81@attacker.example/", "/"},
		{"scheme relative", "//attacker.example/", "/"},
		{"backslash", "/\\attacker.example/", "/"},
		{"encoded backslash", "/%5cattacker.example/", "/"},
		{"javascript scheme", "javascript:alert(1)", "/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeReturnURL(tc.input, "panel.example.com:81"); got != tc.want {
				t.Errorf("sanitizeReturnURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

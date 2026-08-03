package model

import "testing"

// A notification URL is operator-supplied and NPG will fetch it from inside the
// operator's own network, so it is an SSRF vector aimed at the LAN and at the
// cloud metadata address. These cases are the contract.
func TestValidateNotificationTarget(t *testing.T) {
	for _, tt := range []struct {
		url          string
		allowPrivate bool
		ok           bool
		name         string
	}{
		{"https://discord.com/api/webhooks/1/abc", false, true, "public https"},
		{"http://example.com/hook", false, true, "public http is allowed — plenty of receivers are plain"},
		{"https://192.168.1.50/hook", false, false, "LAN refused without opt-in"},
		{"https://192.168.1.50/hook", true, true, "LAN allowed with opt-in"},
		{"http://169.254.169.254/latest/meta-data/", false, false, "cloud metadata refused"},
		{"http://169.254.169.254/latest/meta-data/", true, true, "metadata reachable only on explicit opt-in"},
		{"http://ntfy/hook", false, false, "single-label container name is private"},
		{"http://gotify.local/message", false, false, ".local is private"},
		{"https://100.101.102.103/hook", false, false, "CGNAT refused"},
		{"http://127.0.0.1:8080/hook", false, false, "loopback refused"},
		{"ftp://example.com", false, false, "scheme must be http(s)"},
		{"not a url", false, false, "unparseable"},
		{"", false, false, "empty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNotificationTarget(tt.url, tt.allowPrivate)
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

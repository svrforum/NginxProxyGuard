package handler

import "testing"

// The panel shows its own translated wording keyed on this code. The server's
// message names JSON fields the form labels differently and is always English,
// so a Korean operator used to see "invalid chat_id: required" in an otherwise
// translated form.
func TestValidationCodeIsDerivedFromTheMessage(t *testing.T) {
	cases := map[string]string{
		"invalid chat_id: required — message the bot first": "invalid_chat_id",
		"invalid name: 1-64 characters required":            "invalid_name",
		"invalid url: 10.0.0.5 is on a private network":     "invalid_url",
		"invalid digest_hour: must be between 0 and 23":     "invalid_digest_hour",
		// Anything the deriver cannot read yields no code, and the panel falls
		// back to showing the raw message rather than swallowing it.
		"a channel with this name already exists": "",
		"invalid":                     "",
		"invalid events list: broken": "",
	}
	for msg, want := range cases {
		if got := validationCode(msg); got != want {
			t.Errorf("validationCode(%q) = %q, want %q", msg, got, want)
		}
	}
}

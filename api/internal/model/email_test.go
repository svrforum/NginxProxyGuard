package model

import "testing"

// The stored address is what SSO compares a provider's verified claim against,
// so normalisation is not cosmetic: an address stored with different case or
// stray whitespace would silently fail to link and the operator would have
// nothing to go on. (#240)
func TestNormalizeEmailStoresTheComparableForm(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Ada@Example.com", "ada@example.com"},
		{"  ada@example.com  ", "ada@example.com"},
		{"ADA@EXAMPLE.COM", "ada@example.com"},
		{"ada+npg@example.com", "ada+npg@example.com"},
		// Single-label domains are ordinary on a home network, which is who
		// runs this — requiring a TLD would reject real installs.
		{"admin@localhost", "admin@localhost"},
		{"me@lan", "me@lan"},
	} {
		got, err := NormalizeEmail(tc.in)
		if err != nil {
			t.Errorf("NormalizeEmail(%q) refused a usable address: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeEmailRejectsWhatCannotLink(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"whitespace only", "   "},
		{"no at sign", "ada.example.com"},
		{"no local part", "@example.com"},
		{"no domain", "ada@"},
		// mail.ParseAddress accepts this, and storing it whole would mean the
		// address never matches the provider's plain claim.
		{"display name", "Ada <ada@example.com>"},
		{"angle brackets", "<ada@example.com>"},
		{"two addresses", "ada@example.com, bob@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := NormalizeEmail(tc.in); err == nil {
				t.Errorf("accepted %q as %q", tc.in, got)
			}
		})
	}
}

// The error text reaches the operator through a 400, and the handler keys on
// this prefix to choose that status over a 500.
func TestNormalizeEmailErrorsAreReportable(t *testing.T) {
	_, err := NormalizeEmail("nope")
	if err == nil {
		t.Fatal("expected an error")
	}
	if len(err.Error()) < len("invalid email address") || err.Error()[:len("invalid email address")] != "invalid email address" {
		t.Errorf("handler maps 400 on this prefix; got %q", err)
	}
}

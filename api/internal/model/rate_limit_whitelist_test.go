package model

import (
	"reflect"
	"testing"
)

// Issue #263: the exception list was stored, echoed by the API and carried
// through backups for every release without ever reaching nginx. Now that it is
// rendered into a geo block, what this parser accepts is what nginx gets — so
// the shapes operators actually type have to work, and everything else has to
// be rejected rather than passed through.
func TestParseIPWhitelist(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantValid   []string
		wantInvalid []string
	}{
		{
			name: "empty",
			raw:  "",
		},
		{
			name: "whitespace only",
			raw:  "  \n\t ",
		},
		{
			// The per-host field's placeholder shows a comma-separated list.
			name:      "comma separated",
			raw:       "192.0.2.10, 198.51.100.0/24",
			wantValid: []string{"192.0.2.10", "198.51.100.0/24"},
		},
		{
			// The same field is a textarea, so operators paste one per line.
			name:      "newline separated",
			raw:       "192.0.2.10\n198.51.100.0/24\n",
			wantValid: []string{"192.0.2.10", "198.51.100.0/24"},
		},
		{
			name:      "mixed separators and stray whitespace",
			raw:       " 192.0.2.10 ,\n 198.51.100.0/24 ;\r\n203.0.113.7",
			wantValid: []string{"192.0.2.10", "198.51.100.0/24", "203.0.113.7"},
		},
		{
			// nginx refuses a geo prefix whose host bits are set, so a plausible
			// entry like this would otherwise be an [emerg] at reload time.
			name:      "cidr with host bits is normalized",
			raw:       "10.1.2.3/8",
			wantValid: []string{"10.0.0.0/8"},
		},
		{
			name:      "trailing comment stripped",
			raw:       "192.0.2.10 # office\n198.51.100.5 # monitoring",
			wantValid: []string{"192.0.2.10", "198.51.100.5"},
		},
		{
			name:      "duplicates collapse",
			raw:       "192.0.2.10,192.0.2.10,10.1.2.3/8,10.0.0.0/8",
			wantValid: []string{"192.0.2.10", "10.0.0.0/8"},
		},
		{
			name:      "ipv6",
			raw:       "2001:db8::1, 2001:db8::/32",
			wantValid: []string{"2001:db8::1", "2001:db8::/32"},
		},
		{
			name:        "garbage is reported, not rendered",
			raw:         "192.0.2.10, not-an-ip, 999.1.1.1, 192.0.2.0/99",
			wantValid:   []string{"192.0.2.10"},
			wantInvalid: []string{"not-an-ip", "999.1.1.1", "192.0.2.0/99"},
		},
		{
			// The value lands inside a geo block, so a caller who tries to close
			// it early must not get a working directive out of the far side.
			name:        "nginx injection attempt cannot escape the block",
			raw:         "192.0.2.10; } server { listen 9999",
			wantValid:   []string{"192.0.2.10"},
			wantInvalid: []string{"} server { listen 9999"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid, invalid := ParseIPWhitelist(tc.raw)
			if !reflect.DeepEqual(valid, tc.wantValid) {
				t.Errorf("valid = %#v, want %#v", valid, tc.wantValid)
			}
			if !reflect.DeepEqual(invalid, tc.wantInvalid) {
				t.Errorf("invalid = %#v, want %#v", invalid, tc.wantInvalid)
			}
		})
	}
}

func TestValidateIPWhitelist(t *testing.T) {
	if err := ValidateIPWhitelist("192.0.2.10, 10.0.0.0/8\n# comment"); err != nil {
		t.Errorf("a usable list must validate, got %v", err)
	}
	err := ValidateIPWhitelist("192.0.2.10, nope")
	if err == nil {
		t.Fatal("an unusable entry must be rejected")
	}
	// The operator has to be able to find the offending value in the message.
	if got := err.Error(); !contains(got, "nope") {
		t.Errorf("error must name the rejected entry, got %q", got)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

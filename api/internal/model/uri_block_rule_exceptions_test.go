package model

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// A rule's own exception IPs (#343) are saved normalized, each once, in the
// order given. An entry that is no IP address or CIDR range is refused, and so
// is a list longer than a rule takes.
func TestNormalizeURIBlockRuleExceptionIPs(t *testing.T) {
	rule := URIBlockRule{Pattern: "/user/login",
		ExceptionIPs: []string{" 203.0.113.5 ", "2001:DB8::1", "203.0.113.5", "198.51.100.7/24"}}
	if err := NormalizeURIBlockRuleExceptionIPs(&rule); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if want := []string{"203.0.113.5", "2001:db8::1", "198.51.100.0/24"}; !reflect.DeepEqual(rule.ExceptionIPs, want) {
		t.Errorf("exception IPs = %q, want %q", rule.ExceptionIPs, want)
	}

	empty := URIBlockRule{Pattern: "/admin", ExceptionIPs: []string{}}
	if err := NormalizeURIBlockRuleExceptionIPs(&empty); err != nil || empty.ExceptionIPs != nil {
		t.Errorf("an empty list = %q, %v; want none and no error", empty.ExceptionIPs, err)
	}

	for _, bad := range []string{"office.example.com", "203.0.113.300", ""} {
		r := URIBlockRule{Pattern: "/admin", ExceptionIPs: []string{"203.0.113.5", bad}}
		if err := NormalizeURIBlockRuleExceptionIPs(&r); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: err = %v, want ErrInvalidInput", bad, err)
		}
	}

	var many []string
	for i := 0; i < MaxURIBlockRuleExceptionIPs; i++ {
		many = append(many, fmt.Sprintf("198.51.100.%d", i))
	}
	full := URIBlockRule{Pattern: "/admin", ExceptionIPs: many}
	if err := NormalizeURIBlockRuleExceptionIPs(&full); err != nil {
		t.Errorf("%d addresses: %v, want them taken", MaxURIBlockRuleExceptionIPs, err)
	}
	over := URIBlockRule{Pattern: "/admin", ExceptionIPs: append(many, "203.0.113.1")}
	if err := NormalizeURIBlockRuleExceptionIPs(&over); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("%d addresses: err = %v, want ErrInvalidInput", MaxURIBlockRuleExceptionIPs+1, err)
	}
}

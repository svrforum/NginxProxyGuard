package model

import "testing"

// The banned-IP list's ?type= (#394) accepts the screen's filter values and
// nothing else, since an unknown value would otherwise list every ban.
func TestIsValidBannedIPType(t *testing.T) {
	for _, v := range []string{"", "all", "auto", "manual", "waf", "fail2ban", "rate_limit", "bot"} {
		if !IsValidBannedIPType(v) {
			t.Errorf("%q should be accepted", v)
		}
	}
	for _, v := range []string{"WAF", "geo", "waf'", "manual OR 1=1", " "} {
		if IsValidBannedIPType(v) {
			t.Errorf("%q should be refused", v)
		}
	}
}

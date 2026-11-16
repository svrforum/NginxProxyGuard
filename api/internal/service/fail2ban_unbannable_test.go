package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

// With the setting on, no jail bans a private or link-local address (#384).
// Off, the default, a LAN device stays bannable on purpose.
func TestUnbannableIgnorePrivateIPs(t *testing.T) {
	local := []string{"10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.77.50", "169.254.1.1", "fd00::1", "fe80::1"}
	public := []string{"192.0.2.10", "198.51.100.4", "172.32.0.1", "100.64.0.1", "2001:db8::1"}

	off := &Fail2banService{globalConfig: &model.GlobalFail2banConfig{}}
	for _, ip := range local {
		if why := off.unbannable(ip); why != "" {
			t.Errorf("setting off: %s should be bannable, refused with: %s", ip, why)
		}
	}

	noRow := &Fail2banService{}
	if why := noRow.unbannable("192.168.77.51"); why != "" {
		t.Errorf("no global row loaded: 192.168.77.51 should be bannable, refused with: %s", why)
	}

	on := &Fail2banService{globalConfig: &model.GlobalFail2banConfig{IgnorePrivateIPs: true}}
	for _, ip := range local {
		if on.unbannable(ip) == "" {
			t.Errorf("setting on: %s must not be banned", ip)
		}
	}
	for _, ip := range public {
		if why := on.unbannable(ip); why != "" {
			t.Errorf("setting on: public %s should stay bannable, refused with: %s", ip, why)
		}
	}
	if on.unbannable("127.0.0.1") == "" {
		t.Error("loopback must stay protected")
	}
}

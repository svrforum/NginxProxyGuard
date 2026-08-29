package repository

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

// A restore regenerates nginx.conf and reloads, so anything the backup carries
// for the trusted-proxy settings reaches the same place the API's write path
// guards. A hand-edited backup must not be able to smuggle in a value the API
// itself refuses — 0.0.0.0/0 there would make the forwarded-address header
// forgeable by any client, defeating GeoIP, access lists, banned IPs, fail2ban
// and rate limiting at once.
//
// backup_sync_test.go deliberately scopes itself to proxy_hosts/redirect_hosts/
// certificates, so nothing else in the suite covers system_settings.
func TestBackupCoercesUnsafeTrustedProxyValues(t *testing.T) {
	cidrGuard := func(v string) (string, error) {
		if err := model.ValidateTrustedProxyCIDRs(v); err != nil {
			return "", err
		}
		return v, nil
	}

	t.Run("cidrs", func(t *testing.T) {
		for _, bad := range []string{
			"0.0.0.0/0",
			"::/0",
			"::/1",
			"240.0.0.0/4",
			"not-an-ip",
			"0.0.0.0/0\nnot-an-ip",
		} {
			v := bad
			if got := coerceBackupString(&v, cidrGuard); got != nil {
				t.Errorf("backup value %q survived coercion as %v; want nil so the live value is kept", bad, got)
			}
		}
		for _, ok := range []string{"203.0.113.0/24", "10.0.0.0/8", "2606:4700::/32", ""} {
			v := ok
			if got := coerceBackupString(&v, cidrGuard); got != ok {
				t.Errorf("valid list %q was dropped: got %v", ok, got)
			}
		}
	})

	t.Run("header", func(t *testing.T) {
		for _, bad := range []string{"X-Evil", "X-Real-IP; return 200"} {
			v := bad
			if got := coerceBackupString(&v, model.NormalizeRealIPHeader); got != nil {
				t.Errorf("header %q survived coercion as %v", bad, got)
			}
		}
		v := "cf-connecting-ip"
		if got := coerceBackupString(&v, model.NormalizeRealIPHeader); got != "CF-Connecting-IP" {
			t.Errorf("header normalization: got %v, want CF-Connecting-IP", got)
		}
	})

	t.Run("preset", func(t *testing.T) {
		v := "fastly"
		if got := coerceBackupString(&v, model.NormalizeTrustedProxyPreset); got != nil {
			t.Errorf("unknown preset survived coercion as %v", got)
		}
	})

	// An older backup omits the fields entirely; nil must stay nil so COALESCE
	// keeps whatever the install already had.
	t.Run("absent stays absent", func(t *testing.T) {
		if got := coerceBackupString(nil, cidrGuard); got != nil {
			t.Errorf("nil became %v; an older backup must not overwrite live values", got)
		}
	})
}

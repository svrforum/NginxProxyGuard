package bootstrap

import (
	"testing"
	"time"

	"nginx-proxy-guard/internal/service"
)

// The lines are environment-only; a typo must fall back to the shipped
// defaults rather than leave the guard with lines that can never fire.
func TestDiskThresholdsFromEnv(t *testing.T) {
	t.Setenv("NPG_DISK_WARN_PERCENT", "40")
	t.Setenv("NPG_DISK_CRITICAL_PERCENT", "50")
	t.Setenv("NPG_DISK_RECOVER_PERCENT", "30")
	if got := diskThresholdsFromEnv(); got != (service.DiskThresholds{Warn: 40, Critical: 50, Recover: 30}) {
		t.Fatalf("override = %+v", got)
	}
	t.Setenv("NPG_DISK_CRITICAL_PERCENT", "35") // below warn
	if got := diskThresholdsFromEnv(); got != service.DefaultDiskThresholds {
		t.Fatalf("unordered lines = %+v, want the defaults", got)
	}
	t.Setenv("NPG_DISK_CRITICAL_PERCENT", "ninety")
	t.Setenv("NPG_DISK_WARN_PERCENT", "")
	t.Setenv("NPG_DISK_RECOVER_PERCENT", "")
	if got := diskThresholdsFromEnv(); got != service.DefaultDiskThresholds {
		t.Fatalf("a non-number = %+v, want the defaults", got)
	}
}

func TestDiskGuardEnvSwitches(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "false": false, "1": true, "true": true, "TRUE": true, "yes": true} {
		t.Setenv("NPG_DISK_GUARD_DISABLED", v)
		if got := diskGuardDisabled(); got != want {
			t.Errorf("NPG_DISK_GUARD_DISABLED=%q -> %v, want %v", v, got, want)
		}
	}
	t.Setenv("NPG_DISK_GUARD_INTERVAL", "15s")
	if got := diskGuardInterval(); got != 15*time.Second {
		t.Errorf("interval = %v", got)
	}
	t.Setenv("NPG_DISK_GUARD_INTERVAL", "soon")
	if got := diskGuardInterval(); got != time.Minute {
		t.Errorf("a bad interval = %v, want the 1m default", got)
	}
}

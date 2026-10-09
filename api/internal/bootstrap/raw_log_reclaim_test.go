package bootstrap

import (
	"testing"
	"time"
)

func TestRawLogReclaimPauseFromEnvironment(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want time.Duration
	}{
		{"", 30 * time.Second},
		{"2m", 2 * time.Minute},
		{"0s", 0},
		{"soon", 30 * time.Second},
		{"-5s", 30 * time.Second},
	} {
		t.Setenv("NPG_RAW_RECLAIM_PAUSE", tc.env)
		if got := rawLogReclaimOptions().Pause; got != tc.want {
			t.Errorf("NPG_RAW_RECLAIM_PAUSE=%q: pause %s, want %s", tc.env, got, tc.want)
		}
	}
}

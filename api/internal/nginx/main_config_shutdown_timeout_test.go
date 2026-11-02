package nginx

import (
	"strings"
	"testing"
)

// Without worker_shutdown_timeout an old worker holding a WebSocket or a long
// download outlives every reload, and they pile up (#358). Unset takes the
// default, 0 keeps nginx's wait-for-every-connection behaviour, and the value
// is clamped. The directive belongs to the main context, before events {}.
func TestWorkerShutdownTimeout(t *testing.T) {
	ptr := func(v int) *int { return &v }
	for _, tt := range []struct {
		name string
		set  *int
		want string // "" = no directive
	}{
		{"unset takes the default", nil, "worker_shutdown_timeout 240s;"},
		{"custom", ptr(30), "worker_shutdown_timeout 30s;"},
		{"0 turns it off", ptr(0), ""},
		{"negative is off", ptr(-5), ""},
		{"capped at a day", ptr(999999), "worker_shutdown_timeout 86400s;"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := baselineSettings()
			s.WorkerShutdownTimeout = tt.set
			out := renderOnly(t, s)
			at := strings.Index(out, "worker_shutdown_timeout")
			if tt.want == "" {
				if at >= 0 {
					t.Fatalf("directive rendered for %v", *tt.set)
				}
				return
			}
			if !strings.Contains(out, "\n"+tt.want+"\n") || at > strings.Index(out, "events {") {
				t.Fatalf("want %q in the main context, got:\n%.900s", tt.want, out)
			}
		})
	}
}

package nginx

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestLogrotateConfigGolden(t *testing.T) {
	cases := []struct {
		golden string
		r      model.RawLogRotation
	}{
		{"logrotate_100M_7d_compress.conf", model.RawLogRotation{MaxSizeMB: 100, RetentionDays: 7, Compress: true}},
		{"logrotate_100M_3650d_compress.conf", model.RawLogRotation{MaxSizeMB: 100, RetentionDays: 3650, Compress: true}},
		{"logrotate_100M_30d_nocompress.conf", model.RawLogRotation{MaxSizeMB: 100, RetentionDays: 30}},
	}
	for _, tc := range cases {
		t.Run(tc.golden, func(t *testing.T) {
			compareGolden(t, tc.golden, []byte(RenderLogrotateConfig("/etc/nginx/logs", tc.r)))
		})
	}
}

// The properties the design depends on, for any rendering.
func TestLogrotateConfigProperties(t *testing.T) {
	sizeOnly := regexp.MustCompile(`(?m)^\s+size\s`)
	for _, r := range []model.RawLogRotation{
		{MaxSizeMB: 10, RetentionDays: 1, Compress: true},
		{MaxSizeMB: 100, RetentionDays: 7, Compress: false},
		{MaxSizeMB: 10240, RetentionDays: 3650, Compress: true},
	} {
		out := RenderLogrotateConfig("/etc/nginx/logs", r)
		// `size` makes the stanza size-only: the hourly non-forced run would
		// never cut on a new day.
		if sizeOnly.MatchString(out) {
			t.Errorf("%+v: rendered a `size` line:\n%s", r, out)
		}
		for _, want := range []string{
			"    daily\n",
			"    maxsize " + strconv.Itoa(r.MaxSizeMB) + "M\n",
			"    maxage " + strconv.Itoa(r.RetentionDays) + "\n",
			"    rotate " + strconv.Itoa(RotateSafetyCap(r.RetentionDays)) + "\n",
			"    notifempty\n",
			"    dateformat -%Y%m%d-%H%M%S\n",
			"kill -USR1 $(cat /var/run/nginx.pid)",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%+v: missing %q in:\n%s", r, want, out)
			}
		}
		hasCompress := strings.Contains(out, "    compress\n") && strings.Contains(out, "    delaycompress\n")
		if hasCompress != r.Compress {
			t.Errorf("%+v: compress/delaycompress rendered = %v", r, hasCompress)
		}
		if strings.Contains(out, "\n    \n") {
			t.Errorf("%+v: blank directive line left behind:\n%s", r, out)
		}
	}
}

func TestRotateSafetyCapBounds(t *testing.T) {
	for days, want := range map[int]int{1: 100, 2: 100, 3: 144, 7: 336, 3650: 175200, 4167: 200000, 9999: 200000} {
		if got := RotateSafetyCap(days); got != want {
			t.Errorf("RotateSafetyCap(%d) = %d, want %d", days, got, want)
		}
	}
}

func TestWriteLogrotateConfigReplacesTheFileWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".logrotate.conf")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	r := model.RawLogRotation{MaxSizeMB: 100, RetentionDays: 7, Compress: true}
	if err := WriteLogrotateConfig(path, "/etc/nginx/logs", r); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != RenderLogrotateConfig("/etc/nginx/logs", r) {
		t.Fatalf("written file differs from the rendering:\n%s", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0644 {
		t.Errorf("mode = %v, want 0644 (the nginx container reads it)", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary file left behind: %v", entries)
	}
}

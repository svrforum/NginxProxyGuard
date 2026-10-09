package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyCanaryFailure(t *testing.T) {
	cases := []struct {
		name                                            string
		reachable, inFile, pathMatch, accessFlushFresh bool
		want                                            string
	}{
		{"nginx unreachable", false, false, false, false, "nginx_unreachable"},
		{"nginx not writing file", true, false, true, false, "nginx_write"},
		{"tail reading wrong path", true, true, false, false, "path_mismatch"},
		{"tail stalled", true, true, true, false, "tail_stalled"},
		{"db insert failing", true, true, true, true, "db_insert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyCanaryFailure(tc.reachable, tc.inFile, tc.pathMatch, tc.accessFlushFresh)
			if got != tc.want {
				t.Errorf("classifyCanaryFailure = %q, want %q", got, tc.want)
			}
		})
	}
}

// With hourly size cuts the canary line can already be in the file logrotate
// just renamed. That is still "nginx wrote it"; only the newest rotated copy
// counts, and compressed or unrelated names are ignored.
func TestCanaryNonceFoundInTheNewestRotatedCopy(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "access_raw.log")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("access_raw.log", "GET /other\n")
	write("access_raw.log-20261010-120000.gz", "nonce-old")
	write("access_raw.log-20261010-130000", "GET /__npg_canary?n=nonce-rotated\n")
	write("access_raw.log-garbage", "nonce-garbage")

	if !fileOrNewestRotatedContains(live, "nonce-rotated") {
		t.Error("a nonce in the newest rotated copy was not found")
	}
	if fileOrNewestRotatedContains(live, "nonce-old") || fileOrNewestRotatedContains(live, "nonce-garbage") {
		t.Error("only the newest uncompressed rotated copy may count")
	}

	write("access_raw.log-20261010-140000", "GET /later\n")
	if fileOrNewestRotatedContains(live, "nonce-rotated") {
		t.Error("an older rotated copy must not count once a newer one exists")
	}
	if got := newestRotatedCopy(filepath.Join(dir, "missing.log")); got != "" {
		t.Errorf("no rotated copies: got %q", got)
	}
}

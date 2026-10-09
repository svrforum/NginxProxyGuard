package handler

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// The nginx entrypoint rebuilds 00-raw-logging.conf from .raw_log_config every
// time the nginx container starts, and removes it when that file is missing or
// does not say ENABLED=true. Every apply of the raw log settings — the one at
// API start-up included — must therefore leave both files in agreement, or
// restarting the nginx container alone turns raw logging, the log collector's
// source, off.
func TestApplyRawLogSettingsWritesTheEntrypointCopy(t *testing.T) {
	dir := t.TempDir()
	paths := rawLogPaths{
		nginxConf: filepath.Join(dir, "00-raw-logging.conf"),
		marker:    filepath.Join(dir, ".raw_log_config"),
		logrotate: filepath.Join(dir, ".logrotate.conf"),
		logsDir:   filepath.Join(dir, "logs"),
	}
	if err := os.Mkdir(paths.logsDir, 0755); err != nil {
		t.Fatal(err)
	}
	h := &SystemSettingsHandler{rawLogOverride: &paths}
	settings := &model.SystemSettings{RawLogEnabled: true, RawLogRetentionDays: 7, RawLogMaxSizeMB: 100, RawLogRotateCount: 5, RawLogCompressRotated: true}

	if err := h.applyRawLogSettings(settings); err != nil {
		t.Fatalf("apply: %v", err)
	}
	conf, err := os.ReadFile(paths.nginxConf)
	if err != nil || !strings.Contains(string(conf), "access_log /etc/nginx/logs/access_raw.log ") {
		t.Fatalf("00-raw-logging.conf = %q, %v", conf, err)
	}
	if got := entrypointRawLogEnabled(t, paths.marker); got != "true" {
		t.Fatalf("the nginx entrypoint would read ENABLED=%q from .raw_log_config, want true", got)
	}
	if _, err := os.Stat(paths.logrotate); err != nil {
		t.Fatalf("logrotate stanza: %v", err)
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left in conf.d: %v", leftovers)
	}

	settings.RawLogEnabled = false
	if err := h.applyRawLogSettings(settings); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := os.Stat(paths.nginxConf); !os.IsNotExist(err) {
		t.Fatalf("00-raw-logging.conf still there with raw logging off: %v", err)
	}
	if got := entrypointRawLogEnabled(t, paths.marker); got != "false" {
		t.Fatalf("the nginx entrypoint would read ENABLED=%q from .raw_log_config, want false", got)
	}
}

// entrypointRawLogEnabled reads path the way nginx/scripts/docker-entrypoint.sh
// does (TestNginxEntrypointReadsTheRawLogMarker): grep "^ENABLED=" | cut -d'=' -f2.
func entrypointRawLogEnabled(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read .raw_log_config: %v", err)
	}
	var vals []string
	for _, line := range regexp.MustCompile(`(?m)^ENABLED=.*$`).FindAllString(string(body), -1) {
		vals = append(vals, strings.Split(line, "=")[1])
	}
	return strings.Join(vals, "\n")
}

// entrypointRawLogEnabled reproduces how the entrypoint reads the file; this
// checks that the entrypoint still reads it that way, from that path.
// Skipped where only api/ is checked out.
func TestNginxEntrypointReadsTheRawLogMarker(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "..", "nginx", "scripts", "docker-entrypoint.sh"))
	if os.IsNotExist(err) {
		t.Skip("nginx/scripts/docker-entrypoint.sh is not in this checkout")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`RAW_LOG_CONFIG="` + rawLogConfigFile + `"`,
		// A missing marker (fresh volume, or nginx starting before the
		// upgraded API has written it) must mean "on", not "off".
		`local raw_log_enabled=true`,
		`raw_log_enabled=$(grep "^ENABLED=" "$RAW_LOG_CONFIG" | cut -d'=' -f2)`,
		`if [ "$raw_log_enabled" = "true" ]; then`,
		`rm -f /etc/nginx/conf.d/00-raw-logging.conf`,
	} {
		if !strings.Contains(string(script), want) {
			t.Errorf("the nginx entrypoint no longer contains %s; update writeRawLogMarker and this test with it", want)
		}
	}
}

func TestDefaultRawLogPathsAreTheSharedVolume(t *testing.T) {
	want := rawLogPaths{
		nginxConf: "/etc/nginx/conf.d/00-raw-logging.conf",
		marker:    "/etc/nginx/conf.d/.raw_log_config",
		logrotate: "/etc/nginx/conf.d/.logrotate.conf",
		logsDir:   "/etc/nginx/logs",
	}
	if got := (&SystemSettingsHandler{}).rawLogFiles(); got != want {
		t.Fatalf("raw log paths = %+v, want %+v", got, want)
	}
}

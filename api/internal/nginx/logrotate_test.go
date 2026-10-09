package nginx

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"nginx-proxy-guard/internal/metrics"
)

// "Rotate now" must not queue behind a scheduled run that may spend minutes
// compressing a large file: it answers busy at once.
func TestManualRotationAnswersBusyWhileARotationRuns(t *testing.T) {
	logrotateMutex.Lock()
	defer logrotateMutex.Unlock()

	busy := metrics.RawLogRotateRunsTotal.WithLabelValues("manual", "busy")
	before := testutil.ToFloat64(busy)

	m := &Manager{nginxContainer: "npg-test-never-called"}
	start := time.Now()
	err := m.RotateLogs(context.Background())
	if !errors.Is(err, ErrLogrotateBusy) {
		t.Fatalf("RotateLogs while a rotation holds the lock = %v, want ErrLogrotateBusy", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("RotateLogs waited %v instead of answering at once", waited)
	}
	if got := testutil.ToFloat64(busy); got != before+1 {
		t.Errorf("manual/busy counter = %v, want %v", got, before+1)
	}
}

// The scheduled run waits for a manual rotation instead of skipping the hour.
func TestScheduledRotationWaitsForTheLock(t *testing.T) {
	if _, err := os.Stat(LogrotateConfigPath); err == nil {
		t.Skipf("%s exists on this machine; the test relies on it being absent", LogrotateConfigPath)
	}
	logrotateMutex.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := (&Manager{}).RotateLogsScheduled(context.Background(), false)
		done <- err
	}()
	select {
	case err := <-done:
		logrotateMutex.Unlock()
		t.Fatalf("RotateLogsScheduled returned %v while the lock was held", err)
	case <-time.After(100 * time.Millisecond):
	}
	logrotateMutex.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, ErrLogrotateConfigMissing) {
			t.Fatalf("after the lock was released: %v, want ErrLogrotateConfigMissing (no config here)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RotateLogsScheduled never ran after the lock was released")
	}
}

func TestLogrotateScriptInstallsTheConfigAndDropsTheStaleCopy(t *testing.T) {
	forced := logrotateScript(true)
	ifDue := logrotateScript(false)
	for _, s := range []string{forced, ifDue} {
		if !strings.HasPrefix(s, "cp "+LogrotateConfigPath+" /etc/logrotate.d/nginx-guard && rm -f /etc/logrotate.d/nginx-proxy-guard && logrotate ") {
			t.Errorf("unexpected script %q", s)
		}
	}
	if !strings.HasSuffix(forced, "logrotate -f /etc/logrotate.d/nginx-guard") {
		t.Errorf("forced run must pass -f: %q", forced)
	}
	if strings.Contains(ifDue, "logrotate -f") {
		t.Errorf("the hourly run must not force: %q", ifDue)
	}
}

// A rotation is detected from the files themselves: the name now points at a
// new file (logrotate renamed the old one and created another).
func TestRawLogRotationIsDetectedByFileIdentity(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("access_raw.log", "line\n")
	write("error_raw.log", "")

	before := rawLogIdentities(dir)
	if rawLogsRotatedSince(dir, before) {
		t.Fatal("nothing happened, yet a rotation was reported")
	}

	// Appending is not a rotation.
	f, err := os.OpenFile(filepath.Join(dir, "access_raw.log"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("more\n")
	f.Close()
	if rawLogsRotatedSince(dir, before) {
		t.Fatal("an append was reported as a rotation")
	}

	// rename + create, as logrotate does.
	if err := os.Rename(filepath.Join(dir, "error_raw.log"), filepath.Join(dir, "error_raw.log-20261010-130000")); err != nil {
		t.Fatal(err)
	}
	write("error_raw.log", "")
	if !rawLogsRotatedSince(dir, before) {
		t.Fatal("a rename + create of error_raw.log was not detected")
	}

	// A name that did not exist before cannot have been rotated.
	empty := t.TempDir()
	if rawLogsRotatedSince(empty, rawLogIdentities(empty)) {
		t.Fatal("missing files were reported as rotated")
	}
}

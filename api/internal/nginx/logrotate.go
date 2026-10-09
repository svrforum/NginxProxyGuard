package nginx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/metrics"
)

// LogrotateConfigPath is the logrotate config the API generates for the raw
// nginx logs. The api and nginx containers mount the same nginx volume at
// /etc/nginx, so this path is identical on both sides: the api writes it, the
// nginx container reads it.
const LogrotateConfigPath = "/etc/nginx/conf.d/.logrotate.conf"

// logrotateInstallPath is where the generated config is installed inside the
// nginx container before logrotate is pointed at it. The nginx entrypoint
// uses the same path.
const logrotateInstallPath = "/etc/logrotate.d/nginx-guard"

// staleLogrotateInstallPath is where nginx images before the path was unified
// installed their own copy, with the old size/rotate rules. Every run removes
// it, so an old image cannot keep applying them.
const staleLogrotateInstallPath = "/etc/logrotate.d/nginx-proxy-guard"

// ErrLogrotateConfigMissing is returned by RotateLogs and RotateLogsScheduled
// when the generated config has not been written yet (raw log files never
// enabled). Callers that treat this as "nothing to do" — the hourly
// scheduler — match it with errors.Is.
var ErrLogrotateConfigMissing = errors.New("logrotate config not found")

// The three outcomes below are not failures. Each one means the rotation the
// caller asked for is already accounted for, so handlers answer 200 and the
// scheduler logs a skip — only a genuine logrotate fault stays an error.
var (
	// ErrLogrotateNothingToRotate: every raw log is empty. logrotate's
	// notifempty is not overridden by -f, so it would leave them alone and
	// still exit 0 — reporting success there would claim a cut that never
	// happened.
	ErrLogrotateNothingToRotate = errors.New("no raw log has anything to rotate")

	// ErrLogrotateAlreadyRotated: the archive logrotate would create is
	// already on disk. Rotated names carry the time to the second (#301), so
	// this can only mean a rotation ran inside this same second and the
	// current log really is freshly cut. Before the timestamp went in, this
	// same refusal was every "Rotate now" for the rest of the day.
	ErrLogrotateAlreadyRotated = errors.New("logs were already rotated")

	// ErrLogrotateBusy: a rotation is already running. Either "Rotate now"
	// found one of ours in progress (it does not queue), or logrotate holds
	// its state lock from outside our serialization — typically a run whose
	// docker exec timed out, which keeps going inside the nginx container.
	ErrLogrotateBusy = errors.New("another log rotation is in progress")
)

// logrotate prints these; it exits 1 and 3 respectively and gives nothing else
// machine-readable, so its wording is the only signal available.
const (
	logrotateCollisionMarker = "already exists, skipping rotation"
	logrotateLockedMarker    = "is already locked"
)

// rawLogDir holds the files the generated config rotates. The api and nginx
// containers mount the same nginx volume, so the api can read their sizes
// without another docker exec.
const rawLogDir = "/etc/nginx/logs"

var rawLogNames = []string{"access_raw.log", "error_raw.log"}

// logrotateMutex serializes our own rotations. logrotate locks its state file
// and refuses to run twice at once ("logrotate does not support parallel
// execution on the same set of logfiles", exit 3), which a double-clicked
// "Rotate now" — or a manual click landing on the hourly scheduler — reaches
// easily. Serializing here is also what makes the emptiness check below
// truthful: it is evaluated inside the lock, so it cannot describe a log that
// a concurrent rotation is about to cut. The scheduler waits for the lock;
// "Rotate now" does not (see RotateLogs).
var logrotateMutex sync.Mutex

// rawLogsHaveContent reports whether there is anything for logrotate to cut.
// Both files sit in one stanza but notifempty is evaluated per file, so a
// single non-empty log is enough for a rotation to happen.
func rawLogsHaveContent() bool {
	for _, name := range rawLogNames {
		if info, err := os.Stat(filepath.Join(rawLogDir, name)); err == nil && info.Size() > 0 {
			return true
		}
	}
	return false
}

// RotateLogs is "Rotate now": a forced rotation of the raw logs. It does not
// queue behind a rotation already running — a scheduled run can spend minutes
// compressing a large file — and answers ErrLogrotateBusy at once instead.
func (m *Manager) RotateLogs(ctx context.Context) error {
	if !logrotateMutex.TryLock() {
		metrics.RawLogRotateRunsTotal.WithLabelValues(rotateModeManual, rotateResultBusy).Inc()
		return ErrLogrotateBusy
	}
	defer logrotateMutex.Unlock()

	ctx, cancel := context.WithTimeout(ctx, config.NginxLogrotateManualTimeout)
	defer cancel()
	_, err := m.runLogrotate(ctx, true, rotateModeManual)
	return err
}

// RotateLogsScheduled is the hourly run (scheduler.LogRotateScheduler):
// forced at 00:00 so every day gets its own file, and otherwise non-forced,
// which cuts only a file past the size limit or one not yet rotated today.
// It waits for a manual rotation to finish. rotated reports whether a file
// was actually cut.
func (m *Manager) RotateLogsScheduled(ctx context.Context, force bool) (rotated bool, err error) {
	logrotateMutex.Lock()
	defer logrotateMutex.Unlock()

	mode := rotateModeIfDue
	if force {
		mode = rotateModeForced
	}
	ctx, cancel := context.WithTimeout(ctx, config.NginxLogrotateScheduledTimeout)
	defer cancel()
	return m.runLogrotate(ctx, force, mode)
}

// Labels of npg_raw_log_rotate_runs_total.
const (
	rotateModeForced = "forced"
	rotateModeIfDue  = "if_due"
	rotateModeManual = "manual"

	rotateResultRotated        = "rotated"
	rotateResultNotDue         = "not_due"
	rotateResultEmpty          = "empty"
	rotateResultAlreadyRotated = "already_rotated"
	rotateResultBusy           = "busy"
	rotateResultNoConfig       = "no_config"
	rotateResultError          = "error"
)

// runLogrotate installs the generated config into the nginx container and runs
// logrotate there. The logrotate binary only exists in the nginx image, so
// this has to go through docker exec like every other nginx-side command —
// running it in the api container fails at PATH lookup (#301). The caller
// holds logrotateMutex.
//
// A returned error carries both the exec error and the command's combined
// output: a failing docker exec often produces no output at all (unknown
// container, missing binary), so reporting only the output leaves the caller
// with an empty string and nothing to diagnose.
func (m *Manager) runLogrotate(ctx context.Context, force bool, mode string) (rotated bool, err error) {
	result := rotateResultError
	defer func() { metrics.RawLogRotateRunsTotal.WithLabelValues(mode, result).Inc() }()

	if _, err := os.Stat(LogrotateConfigPath); err != nil {
		if os.IsNotExist(err) {
			result = rotateResultNoConfig
			return false, fmt.Errorf("%w: %s", ErrLogrotateConfigMissing, LogrotateConfigPath)
		}
		return false, fmt.Errorf("logrotate config %s: %w", LogrotateConfigPath, err)
	}

	if !rawLogsHaveContent() {
		result = rotateResultEmpty
		return false, ErrLogrotateNothingToRotate
	}

	before := rawLogIdentities(rawLogDir)
	cmd := exec.CommandContext(ctx, "docker", "exec", m.nginxContainer, "sh", "-c", logrotateScript(force))
	output, err := cmd.CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(output))
		if strings.Contains(out, logrotateCollisionMarker) {
			result = rotateResultAlreadyRotated
			return false, ErrLogrotateAlreadyRotated
		}
		if strings.Contains(out, logrotateLockedMarker) {
			result = rotateResultBusy
			return false, ErrLogrotateBusy
		}
		if out == "" {
			out = "(no output)"
		}
		return false, fmt.Errorf("logrotate in container %q failed: %w: %s", m.nginxContainer, err, out)
	}

	if rawLogsRotatedSince(rawLogDir, before) {
		result = rotateResultRotated
		return true, nil
	}
	result = rotateResultNotDue
	return false, nil
}

// logrotateScript installs the generated config, drops the stale copy older
// images wrote, and runs logrotate — forced, or only where a file is due.
func logrotateScript(force bool) string {
	flag := ""
	if force {
		flag = "-f "
	}
	return fmt.Sprintf("cp %s %s && rm -f %s && logrotate %s%s",
		LogrotateConfigPath, logrotateInstallPath, staleLogrotateInstallPath, flag, logrotateInstallPath)
}

// rawLogIdentities records which file each raw log name points at. The api
// container sees the same volume, so no docker exec is needed.
func rawLogIdentities(dir string) map[string]os.FileInfo {
	ids := make(map[string]os.FileInfo, len(rawLogNames))
	for _, name := range rawLogNames {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil {
			ids[name] = fi
		}
	}
	return ids
}

// rawLogsRotatedSince reports whether logrotate cut any raw log: a name that
// existed before now points at a different file (rename + create), or is gone.
func rawLogsRotatedSince(dir string, before map[string]os.FileInfo) bool {
	for name, was := range before {
		now, err := os.Stat(filepath.Join(dir, name))
		if err != nil || !os.SameFile(was, now) {
			return true
		}
	}
	return false
}

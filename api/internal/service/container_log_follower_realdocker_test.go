package service

// Manual checks against the real docker CLI, skipped unless
// NPG_REAL_DOCKER_CONTAINER names a disposable nginx + ModSecurity container.
// Re-run them after a docker engine upgrade: the follower depends on how the
// daemon prints long lines with --timestamps and on --since/--tail semantics.
//
//	NPG_REAL_DOCKER_CONTAINER=<container> NPG_REAL_DOCKER_SECONDS=30s \
//	  go test ./internal/service/ -run TestRealDocker -v
//
// Generate WAF traffic against the container while the test runs (rule
// matches, ideally some on a large page so records exceed 1 MiB with the old
// audit parts). The follower is forced to reconnect every couple of seconds
// and must still deliver every audit record exactly once.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func realDockerContainer(t *testing.T) (string, time.Duration) {
	t.Helper()
	name := os.Getenv("NPG_REAL_DOCKER_CONTAINER")
	if name == "" {
		t.Skip("set NPG_REAL_DOCKER_CONTAINER to a disposable nginx+ModSecurity container")
	}
	dur := 20 * time.Second
	if v := os.Getenv("NPG_REAL_DOCKER_SECONDS"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			dur = d
		}
	}
	return name, dur
}

// auditGroundTruth returns the unique_id of every audit record docker holds
// for the container since start (stdout only).
func auditGroundTruth(t *testing.T, name string, start time.Time) map[string]bool {
	t.Helper()
	out, err := exec.Command("docker", "logs", "--since", formatDockerSince(start), name).Output()
	if err != nil {
		t.Fatal(err)
	}
	truth := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(l, `{"transaction"`) {
			continue
		}
		var a ModSecAuditLog
		if json.Unmarshal([]byte(l), &a) == nil {
			truth[a.Transaction.UniqueID] = true
		}
	}
	return truth
}

func TestRealDocker_FollowerDeliversEveryAuditRecordOnce(t *testing.T) {
	name, dur := realDockerContainer(t)
	var mu sync.Mutex
	seen := map[string]int{}
	maxLen, badJSON := 0, 0
	f := newContainerLogFollower("modsec", name, "stdout", func(line string, _ time.Time) {
		if !strings.HasPrefix(line, `{"transaction"`) {
			return
		}
		var a ModSecAuditLog
		mu.Lock()
		defer mu.Unlock()
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			badJSON++
			return
		}
		seen[a.Transaction.UniqueID]++
		maxLen = max(maxLen, len(line))
	})
	f.maxAge = 2 * time.Second
	start := time.Now()
	f.setCursor(start) // the first attach starts exactly where the ground truth does
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.run(ctx, nil); close(done) }()
	time.Sleep(dur)
	time.Sleep(3 * time.Second) // let the last records land
	cancel()
	<-done

	truth := auditGroundTruth(t, name, start)
	mu.Lock()
	defer mu.Unlock()
	dups, missing, extra := 0, 0, 0
	for id, n := range seen {
		if n > 1 {
			dups++
		}
		if !truth[id] {
			extra++
		}
	}
	for id := range truth {
		if seen[id] == 0 {
			missing++
		}
	}
	t.Logf("records in docker logs=%d delivered=%d missing=%d duplicated=%d extra=%d badJSON=%d largest=%d B docker-logs runs=%d",
		len(truth), len(seen), missing, dups, extra, badJSON, maxLen, f.runs.Load())
	if len(truth) == 0 {
		t.Fatal("no audit records: generate WAF traffic while the test runs")
	}
	if dups != 0 || missing != 0 || extra != 0 || badJSON != 0 {
		t.Fatal("the follower lost, duplicated or corrupted audit records")
	}
}

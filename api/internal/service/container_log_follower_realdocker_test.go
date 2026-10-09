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
// audit parts). The follower is forced to reconnect every
// NPG_REAL_DOCKER_MAXAGE (default 5s) and must still deliver every audit
// record exactly once. That interval must exceed the time the daemon takes
// for the replay (time `docker logs --since <now> --tail 100000 <container>`):
// a run killed before its replay arrives delivers nothing, every time.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// realDockerContainer returns the container, how long to follow it and the
// forced reconnect interval.
func realDockerContainer(t *testing.T) (name string, dur, maxAge time.Duration) {
	t.Helper()
	name = os.Getenv("NPG_REAL_DOCKER_CONTAINER")
	if name == "" {
		t.Skip("set NPG_REAL_DOCKER_CONTAINER to a disposable nginx+ModSecurity container")
	}
	env := func(key string, def time.Duration) time.Duration {
		if d, err := time.ParseDuration(os.Getenv(key)); err == nil {
			return d
		}
		return def
	}
	return name, env("NPG_REAL_DOCKER_SECONDS", 20*time.Second), env("NPG_REAL_DOCKER_MAXAGE", 5*time.Second)
}

// auditGroundTruth returns the unique_id of every audit record docker holds
// for the container since start (stdout only); withMessagesOnly keeps only
// records with rule messages, the ones the collector stores.
func auditGroundTruth(t *testing.T, name string, start time.Time, withMessagesOnly bool) map[string]bool {
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
		if json.Unmarshal([]byte(l), &a) == nil && (!withMessagesOnly || len(a.Transaction.Messages) > 0) {
			truth[a.Transaction.UniqueID] = true
		}
	}
	return truth
}

func TestRealDocker_FollowerDeliversEveryAuditRecordOnce(t *testing.T) {
	name, dur, maxAge := realDockerContainer(t)
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
	f.maxAge = maxAge
	start := time.Now()
	f.setCursor(start) // the first attach starts exactly where the ground truth does
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.run(ctx, nil); close(done) }()
	time.Sleep(dur)
	time.Sleep(3 * time.Second) // let the last records land
	cancel()
	<-done

	truth := auditGroundTruth(t, name, start, false)
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

// The whole WAF path on real output: follower -> handleModSecLine -> the
// rows the collector would insert, with forced reconnects. Every rule match
// is stored once, as the trimmed record (send example credentials with the
// generated traffic to make the credential check meaningful).
func TestRealDocker_ModSecPipelineStoresTrimmedRecords(t *testing.T) {
	name, dur, maxAge := realDockerContainer(t)
	c := NewLogCollector(nil, name, "", nil, nil)
	c.batchSize = 1 << 30 // keep every row in memory, no DB
	ctx, cancel := context.WithCancel(context.Background())
	f := newContainerLogFollower("modsec", name, "stdout", func(line string, at time.Time) {
		if strings.HasPrefix(strings.TrimSpace(line), `{"transaction"`) {
			c.handleModSecLine(ctx, line, at)
		}
	})
	f.maxAge = maxAge
	start := time.Now()
	f.setCursor(start)
	done := make(chan struct{})
	go func() { f.run(ctx, c.stopCh); close(done) }()
	time.Sleep(dur)
	time.Sleep(3 * time.Second)
	cancel()
	<-done

	truth := auditGroundTruth(t, name, start, true)
	got := map[string]int{}
	maxRaw := 0
	c.bufferMu.Lock()
	defer c.bufferMu.Unlock()
	for _, r := range c.buffer {
		if r.LogType != model.LogTypeModSec {
			continue
		}
		if !strings.HasPrefix(r.RawLog, storedModSecMarker) {
			t.Fatalf("stored raw_log is not the trimmed record: %.80s", r.RawLog)
		}
		var a ModSecAuditLog
		if err := json.Unmarshal([]byte(r.RawLog), &a); err != nil {
			t.Fatalf("stored raw_log does not decode: %v", err)
		}
		got[a.Transaction.UniqueID]++
		maxRaw = max(maxRaw, len(r.RawLog))
		for _, banned := range append([]string{`"body"`, `"Cookie"`, `"Authorization"`}, fakeCredentialValues...) {
			if strings.Contains(r.RawLog, banned) {
				t.Fatalf("stored raw_log contains %s: %.300s", banned, r.RawLog)
			}
		}
	}
	missing, dups, extra := 0, 0, 0
	for id := range truth {
		if got[id] == 0 {
			missing++
		}
	}
	for id, n := range got {
		if n > 1 {
			dups++
		}
		if !truth[id] {
			extra++
		}
	}
	t.Logf("rule-matched records in docker logs=%d, rows=%d, missing=%d, duplicated=%d, extra=%d, largest stored raw_log=%d B, docker-logs runs=%d",
		len(truth), len(got), missing, dups, extra, maxRaw, f.runs.Load())
	if len(truth) == 0 {
		t.Fatal("no rule matches: generate WAF traffic while the test runs")
	}
	if missing != 0 || dups != 0 || extra != 0 {
		t.Fatal("lost or duplicated WAF events")
	}
}

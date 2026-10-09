package service

// A fake `docker` CLI for the docker-logs readers. installFakeDocker puts a
// shell script named docker first on PATH; it re-executes this test binary in
// helper mode (TestFakeDockerHelper), so the child behaves like
// `docker logs --follow` without a daemon: it writes into a pipe, blocks when
// nobody reads it, and dies on SIGKILL.
//
// The tests at the bottom drive the production entry points
// (LogCollector.streamModSecLogs, DockerLogCollector.tailContainerLogs) and use
// nothing else, so they also run against the code from before the follower:
// there they fail, which is the 2026-09-27 production deadlock reproduced.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// fakeTSLayout is docker's RFC3339NanoFixed.
const fakeTSLayout = "2006-01-02T15:04:05.000000000Z07:00"

// fakeDockerChunk mirrors the daemon's 16 KiB partial-entry size: a longer
// line is stored in chunks sharing one timestamp, and `docker logs -t`
// prints the timestamp again before every chunk.
const fakeDockerChunk = 16 * 1024

func installFakeDocker(t *testing.T, mode string, extraEnv map[string]string) (invocationLog string) {
	t.Helper()
	dir := t.TempDir()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nexec \"" + bin + "\" -test.run='^TestFakeDockerHelper$' -- \"$@\"\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	invocationLog = filepath.Join(dir, "invocations.log")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NPG_FAKE_DOCKER", mode)
	t.Setenv("NPG_FAKE_DOCKER_LOG", invocationLog)
	for k, v := range extraEnv {
		t.Setenv(k, v)
	}
	return invocationLog
}

type fakeInvocation struct {
	pid  int
	args string
}

func readInvocations(path string) []fakeInvocation {
	b, _ := os.ReadFile(path)
	var out []fakeInvocation
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		pidStr, args, _ := strings.Cut(l, " ")
		pid, _ := strconv.Atoi(pidStr)
		out = append(out, fakeInvocation{pid, args})
	}
	return out
}

func followInvocations(path string) []fakeInvocation {
	var out []fakeInvocation
	for _, c := range readInvocations(path) {
		if strings.HasPrefix(c.args, "logs") && strings.Contains(c.args, "--follow") {
			out = append(out, c)
		}
	}
	return out
}

// followsReady counts store-mode follows that have finished their initial
// replay and are now waiting for new records ("<pid> ready" lines).
func followsReady(path string) int { return countFakeMarks(path, "ready") }

// followsStalled counts store-mode follows that have seen the stall file and
// stopped sending ("<pid> stalled" lines).
func followsStalled(path string) int { return countFakeMarks(path, "stalled") }

func countFakeMarks(path, mark string) int {
	n := 0
	for _, c := range readInvocations(path) {
		if c.args == mark {
			n++
		}
	}
	return n
}

func logFakeInvocation(line string) {
	if f, err := os.OpenFile(os.Getenv("NPG_FAKE_DOCKER_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "%d %s\n", os.Getpid(), line)
		f.Close()
	}
}

// processAlive reports whether pid still exists. The follower reaps its
// children, so a pid that is still there was never killed or never waited.
func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func waitAllReaped(t *testing.T, invocations []fakeInvocation) {
	t.Helper()
	waitFor(t, 10*time.Second, "every docker process killed and reaped", func() bool {
		for _, c := range invocations {
			if processAlive(c.pid) {
				return false
			}
		}
		return true
	})
}

// TestFakeDockerHelper is the fake docker CLI. In a normal test run it does
// nothing.
func TestFakeDockerHelper(t *testing.T) {
	mode := os.Getenv("NPG_FAKE_DOCKER")
	if mode == "" {
		return
	}
	args := os.Args
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	logFakeInvocation(strings.Join(args, " "))
	if len(args) > 0 && args[0] == "inspect" { // DockerLogCollector.sinceArg
		fmt.Println(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano))
		os.Exit(0)
	}
	stamps := false
	for _, a := range args {
		if a == "--timestamps" {
			stamps = true
		}
	}
	switch mode {
	case "longline":
		// Like docker logs --follow on npg-proxy before the fix: one normal
		// line, one line over 1 MiB, then an endless stream.
		emitFakeEntry(os.Stdout, time.Now(), "line-1", stamps)
		emitFakeEntry(os.Stdout, time.Now(), strings.Repeat("X", 1200*1024), stamps)
		progress := os.Getenv("NPG_FAKE_PROGRESS")
		for i := 0; ; i++ {
			emitFakeEntry(os.Stdout, time.Now(), "after-"+strconv.Itoa(i), stamps)
			if i%200 == 0 {
				time.Sleep(time.Millisecond)
			}
			if progress != "" && i%1000 == 0 {
				_ = os.WriteFile(progress, []byte(strconv.Itoa(i)), 0o644)
			}
		}
	case "silent":
		for { // attached, never says anything, never exits on its own
			time.Sleep(time.Hour)
		}
	case "store":
		runFakeStore(args, stamps)
	}
	os.Exit(0)
}

// emitFakeEntry writes one log entry the way `docker logs` does, including the
// repeated timestamp prefix inside lines longer than one partial chunk.
func emitFakeEntry(w *os.File, ts time.Time, content string, stamps bool) {
	var b bytes.Buffer
	prefix := ts.UTC().Format(fakeTSLayout) + " "
	for off := 0; ; off += fakeDockerChunk {
		end := min(off+fakeDockerChunk, len(content))
		if stamps {
			b.WriteString(prefix)
		}
		b.WriteString(content[off:end])
		if end >= len(content) {
			break
		}
	}
	b.WriteByte('\n')
	_, _ = w.Write(b.Bytes())
}

// runFakeStore emulates `docker logs [--follow] [--timestamps] [--since T]
// [--tail N] <c>` over a record file with one "<ts> <o|e> <content>" per
// line. --tail applies first, then --since (inclusive), as in docker. While
// the file named by NPG_FAKE_STALL exists, a follow stays attached and silent.
// NPG_FAKE_REPLAY_DELAY delays a follow's first output, like a daemon that
// needs seconds to scan a large log for the replay.
func runFakeStore(args []string, stamps bool) {
	follow := false
	var since time.Time
	tail := -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--follow":
			follow = true
		case "--since":
			i++
			since, _ = time.Parse(time.RFC3339Nano, args[i])
		case "--tail":
			i++
			tail, _ = strconv.Atoi(args[i])
		}
	}
	store := os.Getenv("NPG_FAKE_STORE")
	stall := os.Getenv("NPG_FAKE_STALL")
	if d, err := time.ParseDuration(os.Getenv("NPG_FAKE_REPLAY_DELAY")); err == nil && follow {
		time.Sleep(d)
	}
	emit := func(rec string) {
		tsStr, rest, _ := strings.Cut(rec, " ")
		stream, content, _ := strings.Cut(rest, " ")
		ts, _ := time.Parse(time.RFC3339Nano, tsStr)
		if !since.IsZero() && ts.Before(since) {
			return
		}
		w := os.Stdout
		if stream == "e" {
			w = os.Stderr
		}
		emitFakeEntry(w, ts, content, stamps)
	}
	readRecords := func() []string {
		b, _ := os.ReadFile(store)
		// Only complete records: a read can overlap the test's append.
		end := bytes.LastIndexByte(b, '\n')
		if end < 0 {
			return nil
		}
		return strings.Split(string(b[:end]), "\n")
	}
	recs := readRecords()
	start := 0
	if tail >= 0 && tail < len(recs) {
		start = len(recs) - tail
	}
	for _, r := range recs[start:] {
		emit(r)
	}
	if !follow {
		return
	}
	logFakeInvocation("ready")
	seen := len(recs)
	stalled := false
	for {
		time.Sleep(20 * time.Millisecond)
		if _, err := os.Stat(stall); stall != "" && err == nil {
			if !stalled {
				stalled = true
				logFakeInvocation("stalled")
			}
			continue // the follow RPC is stuck: alive and silent
		}
		recs = readRecords()
		for _, r := range recs[seen:] {
			emit(r)
		}
		seen = len(recs)
	}
}

func appendFakeRecord(t *testing.T, store string, ts time.Time, stream, content string) {
	t.Helper()
	fh, err := os.OpenFile(store, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if _, err := fmt.Fprintf(fh, "%s %s %s\n", ts.UTC().Format(fakeTSLayout), stream, content); err != nil {
		t.Fatal(err)
	}
}

// fakeAuditRecord is a ModSecurity v3 JSON audit record with one SQLi rule
// match. bodyBytes > 0 adds a response body, as part E used to.
func fakeAuditRecord(n int, bodyBytes int) string {
	body := ""
	if bodyBytes > 0 {
		body = `,"body":"` + strings.Repeat("A", bodyBytes) + `"`
	}
	return `{"transaction":{"client_ip":"192.0.2.10","time_stamp":"Fri Oct  9 12:46:28 2026","client_port":40146,` +
		`"host_ip":"192.0.2.1","host_port":80,"unique_id":"fake-` + strconv.Itoa(n) + `",` +
		`"request":{"method":"GET","http_version":"1.1","uri":"/?id=1%20UNION%20SELECT%201,2,3&n=` + strconv.Itoa(n) + `",` +
		`"headers":{"Host":"waf.example.com","User-Agent":"curl/8"}},` +
		`"response":{"http_code":200,"headers":{"Content-Type":"text/html"}` + body + `},` +
		`"producer":{"modsecurity":"ModSecurity v3.0.15 (Linux)","connector":"ModSecurity-nginx v1.0.4","secrules_engine":"DetectionOnly"},` +
		`"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.",` +
		`"reference":"v15,20","ruleId":"942100","file":"REQUEST-942-APPLICATION-ATTACK-SQLI.conf","lineNumber":"46",` +
		`"data":"Matched Data: 1UE1 found within ARGS:id: 1 UNION SELECT 1,2,3","severity":"2","ver":"OWASP_CRS/4.26.0",` +
		`"rev":"","tags":["attack-sqli"],"maturity":"0","accuracy":"0"}}]}}`
}

func bufferedURIs(c *LogCollector) map[string]int {
	c.bufferMu.Lock()
	defer c.bufferMu.Unlock()
	out := map[string]int{}
	for _, r := range c.buffer {
		out[r.RequestURI]++
	}
	return out
}

// The production deadlock, end to end through LogCollector.streamModSecLogs:
// a WAF rule match on a large page wrote an audit record over 1 MiB, and no
// WAF event after it was ever recorded. The record here is 1.2 MiB, as the
// response body made it; every record after it must still be stored, exactly
// once.
func TestStreamModSecLogs_KeepsDeliveringAfterOversizedAuditLine(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	if err := os.WriteFile(store, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	inv := installFakeDocker(t, "store", map[string]string{"NPG_FAKE_STORE": store})

	c := NewLogCollector(nil, "npg-proxy", "", nil, nil)
	c.batchSize = 1 << 30 // keep every row in the memory buffer, no DB flush
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.streamModSecLogs(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("streamModSecLogs did not return after cancel")
		}
	}()
	waitFor(t, 10*time.Second, "docker logs attached", func() bool { return followsReady(inv) > 0 })

	appendFakeRecord(t, store, time.Now(), "o", fakeAuditRecord(0, 0))
	appendFakeRecord(t, store, time.Now(), "o", fakeAuditRecord(1000, 1200*1024))
	for n := 1; n <= 20; n++ {
		appendFakeRecord(t, store, time.Now(), "o", fakeAuditRecord(n, 0))
	}

	uriOf := func(n int) string { return "/?id=1%20UNION%20SELECT%201,2,3&n=" + strconv.Itoa(n) }
	waitFor(t, 15*time.Second, "every record after the 1.2 MiB one stored", func() bool {
		got := bufferedURIs(c)
		for n := 1; n <= 20; n++ {
			if got[uriOf(n)] == 0 {
				return false
			}
		}
		return true
	})
	got := bufferedURIs(c)
	for _, n := range append([]int{0, 1000}, 1, 2, 3, 20) {
		if got[uriOf(n)] != 1 {
			t.Errorf("record n=%d stored %d times, want 1", n, got[uriOf(n)])
		}
	}
	if len(got) != 22 {
		t.Errorf("stored %d distinct records, want 22", len(got))
	}
	c.bufferMu.Lock()
	for _, r := range c.buffer {
		if r.LogType != model.LogTypeModSec || r.RuleID != 942100 {
			t.Errorf("unexpected row: type=%s rule=%d", r.LogType, r.RuleID)
		}
	}
	c.bufferMu.Unlock()
}

func readProgress(path string) int {
	b, _ := os.ReadFile(path)
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// The same deadlock in the system-log collector: when npg-proxy stdout is
// collected (StdoutExcluded is operator-configurable), a line over 1 MiB used
// to stop the Scanner while docker logs blocked writing into the pipe.
func TestDockerLogCollector_KeepsReadingAfterLongStdoutLine(t *testing.T) {
	progress := filepath.Join(t.TempDir(), "progress")
	inv := installFakeDocker(t, "longline", map[string]string{"NPG_FAKE_PROGRESS": progress})
	c := &DockerLogCollector{
		stopCh:       make(chan struct{}),
		config:       SystemLogConfig{Enabled: false}, // nothing reaches the DB
		startupGrace: map[string]time.Time{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.tailContainerLogs(ctx, ContainerConfig{Name: "npg-proxy"}); close(done) }()

	// The fake writes ~8 MB/s once the reader keeps up; stuck, it never gets
	// past the first pipe buffer (progress 0).
	waitFor(t, 15*time.Second, "docker logs keeps writing after the 1.2 MiB line", func() bool {
		return readProgress(progress) >= 50000
	})
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tailContainerLogs did not return after cancel")
	}
	waitAllReaped(t, readInvocations(inv))
}

// Stop alone (no context cancel) must end tailContainerLogs as well.
func TestDockerLogCollector_StopEndsTail(t *testing.T) {
	inv := installFakeDocker(t, "silent", nil)
	c := &DockerLogCollector{
		stopCh:       make(chan struct{}),
		config:       SystemLogConfig{Enabled: false},
		startupGrace: map[string]time.Time{},
	}
	done := make(chan struct{})
	go func() { c.tailContainerLogs(context.Background(), ContainerConfig{Name: "npg-proxy"}); close(done) }()
	waitFor(t, 10*time.Second, "docker logs attached", func() bool { return len(followInvocations(inv)) > 0 })
	close(c.stopCh)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("tailContainerLogs did not return after Stop")
	}
	waitAllReaped(t, readInvocations(inv))
}

// lineSink collects delivered lines from the follower's goroutine.
type lineSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *lineSink) add(l string) {
	s.mu.Lock()
	s.lines = append(s.lines, l)
	s.mu.Unlock()
}

func (s *lineSink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *lineSink) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lines)
}

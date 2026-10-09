package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"nginx-proxy-guard/internal/metrics"
)

// The fake docker CLI these tests drive lives in fake_docker_test.go.

func newTestFollower(stream string, sink *lineSink) *containerLogFollower {
	f := newContainerLogFollower("modsec", "npg-proxy", stream, func(l string, _ time.Time) { sink.add(l) })
	f.tick = 20 * time.Millisecond
	f.reapTimeout = 2 * time.Second
	f.minBackoff = 20 * time.Millisecond
	f.maxBackoff = 200 * time.Millisecond
	return f
}

// startFollower runs f until the returned stop function is called; stop
// fails the test if run does not return.
func startFollower(t *testing.T, f *containerLogFollower) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.run(ctx, nil); close(done) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("follower did not stop after cancel")
		}
	}
	t.Cleanup(stop)
	return stop
}

// stampLines prefixes every line of r with a distinct docker-style
// timestamp, the way `docker logs --timestamps` does.
func stampLines(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		br := bufio.NewReaderSize(r, 1<<16)
		base := time.Now().UTC()
		for i := 0; ; i++ {
			line, err := br.ReadString('\n')
			if len(line) > 0 {
				_, _ = pw.Write([]byte(base.Add(time.Duration(i)*time.Microsecond).Format(fakeTSLayout) + " " + line))
			}
			if err != nil {
				pw.Close()
				return
			}
		}
	}()
	return pr
}

// A line over the cap is discarded and the next line is read (here a 1 MiB
// cap, to prove the discard path); with the production 8 MiB cap the same
// 1.2 MiB line is delivered whole.
func TestFollower_LongLineIsDiscardedAndReadingContinues(t *testing.T) {
	for _, tc := range []struct {
		name     string
		maxLine  int
		wantLong bool
	}{{"cap 1MiB discards", 1 << 20, false}, {"cap 8MiB delivers", followerMaxLine, true}} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &lineSink{}
			f := newTestFollower("stdout", sink)
			f.maxLine = tc.maxLine
			oversizeBefore := testutil.ToFloat64(metrics.LogCollectorOversizeLinesTotal.WithLabelValues("modsec"))

			r, w := io.Pipe()
			go func() {
				_, _ = w.Write([]byte("line-1\n"))
				_, _ = w.Write(append(bytes.Repeat([]byte("X"), 1200*1024), '\n'))
				for i := 0; i < 5000; i++ {
					fmt.Fprintf(w, "after-%d\n", i)
				}
				w.Close()
			}()
			f.replaying = true
			delivered, err := f.readAll(stampLines(r))
			if err != nil {
				t.Fatal(err)
			}
			got := sink.snapshot()
			long := 0
			for _, l := range got {
				if len(l) > 1<<20 {
					long++
				}
			}
			if got[0] != "line-1" || got[len(got)-1] != "after-4999" {
				t.Fatalf("stream did not continue past the long line: first=%q last=%q n=%d", got[0], got[len(got)-1], len(got))
			}
			if (long == 1) != tc.wantLong {
				t.Fatalf("long line delivered=%v, want %v", long == 1, tc.wantLong)
			}
			if delivered != len(got) {
				t.Fatalf("readAll reported %d delivered, sink has %d", delivered, len(got))
			}
			oversize := testutil.ToFloat64(metrics.LogCollectorOversizeLinesTotal.WithLabelValues("modsec")) - oversizeBefore
			if want := map[bool]float64{true: 0, false: 1}[tc.wantLong]; oversize != want {
				t.Fatalf("oversize metric +%v, want +%v", oversize, want)
			}
		})
	}
}

// Kill before Wait, max-age: a silent stream is reconnected at max-age and
// every docker process is killed and reaped.
func TestFollower_MaxAgeKillsAndReconnectsSilentStream(t *testing.T) {
	inv := installFakeDocker(t, "silent", nil)
	sink := &lineSink{}
	f := newTestFollower("stdout", sink)
	// Well above the fake CLI's start-up time: it re-executes this test binary.
	f.maxAge = 500 * time.Millisecond
	f.probeAfter = time.Hour // only max-age may end these runs
	maxAgeBefore := testutil.ToFloat64(metrics.LogCollectorWatchdogRestartTotal.WithLabelValues("max_age"))

	stop := startFollower(t, f)
	waitFor(t, 20*time.Second, "four max-age reconnects", func() bool { return len(followInvocations(inv)) >= 5 })
	stop()

	calls := followInvocations(inv)
	waitAllReaped(t, readInvocations(inv))
	if restarts := testutil.ToFloat64(metrics.LogCollectorWatchdogRestartTotal.WithLabelValues("max_age")) - maxAgeBefore; restarts < 4 {
		t.Fatalf("max_age restarts +%v, want >= 4 (the silent child must stay attached until max-age)", restarts)
	}
	for _, c := range calls {
		if !strings.Contains(c.args, "--timestamps") || !strings.Contains(c.args, "--since") || !strings.Contains(c.args, "--tail 100000") {
			t.Fatalf("unexpected docker logs arguments: %s", c.args)
		}
	}
}

// Gap-free and duplicate-free across forced reconnects: 300 records, one of
// them 70 KB (exercises the repeated partial-chunk prefix), three sharing one
// timestamp, plus stderr noise a stdout follower must not see.
func TestFollower_ReconnectIsGapFreeAndDeduplicated(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	if err := os.WriteFile(store, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	inv := installFakeDocker(t, "store", map[string]string{"NPG_FAKE_STORE": store})
	sink := &lineSink{}
	f := newTestFollower("stdout", sink)
	f.maxAge = 400 * time.Millisecond // force reconnects mid-stream (well above the fake's start-up time)
	f.probeAfter = time.Hour
	dedupBefore := testutil.ToFloat64(metrics.LogCollectorReplayDedupTotal.WithLabelValues("modsec"))

	stop := startFollower(t, f)
	waitFor(t, 10*time.Second, "first attach", func() bool { return followsReady(inv) > 0 })

	var want []string
	base := time.Now()
	same := base.Add(100 * time.Millisecond) // records 100-102 share one timestamp
	for i := 0; i < 300; i++ {
		ts := base.Add(time.Duration(i) * time.Millisecond)
		if i >= 100 && i < 103 {
			ts = same
		}
		content := fmt.Sprintf(`{"transaction":{"n":%d}}`, i)
		if i == 150 {
			content = `{"transaction":{"n":150,"pad":"` + strings.Repeat("p", 70000) + `"}}`
		}
		appendFakeRecord(t, store, ts, "o", content)
		if i%7 == 0 {
			appendFakeRecord(t, store, ts, "e", "stderr noise must not reach a stdout follower")
		}
		want = append(want, content)
		time.Sleep(8 * time.Millisecond) // spread the records across reconnects
	}
	waitFor(t, 20*time.Second, "all 300 records delivered", func() bool { return sink.len() >= len(want) })
	// Let a few more reconnects replay the tail before checking for duplicates.
	runs := f.runs.Load()
	waitFor(t, 10*time.Second, "three more reconnects", func() bool { return f.runs.Load() >= runs+3 })
	stop()

	got := sink.snapshot()
	if len(got) != len(want) {
		t.Fatalf("delivered %d lines, want %d (runs=%d)", len(got), len(want), f.runs.Load())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d differs (len got %d, want %d)", i, len(got[i]), len(want[i]))
		}
	}
	if f.runs.Load() < 5 {
		t.Fatalf("only %d docker logs runs; the test needs reconnects mid-stream", f.runs.Load())
	}
	if testutil.ToFloat64(metrics.LogCollectorReplayDedupTotal.WithLabelValues("modsec")) == dedupBefore {
		t.Fatal("no replayed line was dropped; reconnects did not replay the boundary")
	}
	waitAllReaped(t, readInvocations(inv))
}

// A follow RPC that hangs silently while docker keeps logging is detected by
// the stall probe and reconnected without losing the record it missed.
func TestFollower_StallProbeRestartsStuckFollow(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	stall := filepath.Join(dir, "stall")
	if err := os.WriteFile(store, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	inv := installFakeDocker(t, "store", map[string]string{"NPG_FAKE_STORE": store, "NPG_FAKE_STALL": stall})
	sink := &lineSink{}
	f := newTestFollower("stdout", sink)
	f.maxAge = time.Hour
	f.probeAfter = 300 * time.Millisecond
	f.probeEvery = 300 * time.Millisecond
	f.lagGrace = 200 * time.Millisecond
	stallBefore := testutil.ToFloat64(metrics.LogCollectorWatchdogRestartTotal.WithLabelValues("stall"))

	stop := startFollower(t, f)
	waitFor(t, 10*time.Second, "first attach", func() bool { return followsReady(inv) > 0 })
	appendFakeRecord(t, store, time.Now(), "o", `{"transaction":{"n":1}}`)
	waitFor(t, 10*time.Second, "record 1", func() bool { return sink.len() == 1 })

	if err := os.WriteFile(stall, nil, 0o644); err != nil { // the follow RPC now hangs
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "the follow RPC stalled", func() bool { return followsStalled(inv) > 0 })
	appendFakeRecord(t, store, time.Now(), "o", `{"transaction":{"n":2}}`)
	waitFor(t, 15*time.Second, "record 2 after the stall probe reconnected", func() bool { return sink.len() >= 2 })
	_ = os.Remove(stall)
	stop()

	if got := sink.snapshot(); len(got) != 2 || got[1] != `{"transaction":{"n":2}}` {
		t.Fatalf("got %q, want both records exactly once", got)
	}
	if n := len(followInvocations(inv)); n < 2 {
		t.Fatalf("expected the stall probe to force a reconnect, follow invocations=%d", n)
	}
	if testutil.ToFloat64(metrics.LogCollectorWatchdogRestartTotal.WithLabelValues("stall")) == stallBefore {
		t.Fatal("stall restart not counted")
	}
	waitAllReaped(t, readInvocations(inv))
}

// A daemon that needs longer for the replay than the stall probe waits must
// not turn the follower into a reconnect loop that never delivers: a stall
// that delivered nothing makes the next run wait longer before probing.
func TestFollower_SlowReplayDoesNotLivelockTheStallProbe(t *testing.T) {
	store := filepath.Join(t.TempDir(), "store")
	recTS := time.Now().Add(-time.Second)
	appendFakeRecord(t, store, recTS, "o", `{"transaction":{"n":1}}`)
	installFakeDocker(t, "store", map[string]string{"NPG_FAKE_STORE": store, "NPG_FAKE_REPLAY_DELAY": "1s"})
	sink := &lineSink{}
	f := newTestFollower("stdout", sink)
	f.maxAge = time.Hour
	f.probeAfter = 200 * time.Millisecond
	f.probeEvery = 200 * time.Millisecond
	f.lagGrace = 50 * time.Millisecond
	f.setCursor(recTS.Add(-time.Millisecond)) // the record is newer than the cursor

	stop := startFollower(t, f)
	waitFor(t, 20*time.Second, "the record delivered despite the slow replay", func() bool { return sink.len() >= 1 })
	stop()
	if got := sink.snapshot(); len(got) != 1 {
		t.Fatalf("got %q", got)
	}
}

// failAfter returns an error after n bytes.
type failAfter struct {
	r io.Reader
	n int
}

func (f *failAfter) Read(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("injected read error")
	}
	if len(p) > f.n {
		p = p[:f.n]
	}
	k, err := f.r.Read(p)
	f.n -= k
	return k, err
}

// If the reader stops for any reason while docker is still writing, the child
// must be killed before Wait - otherwise Wait blocks forever, the production
// hang reached through a different door.
func TestFollower_ReaderErrorKillsChildAndReconnects(t *testing.T) {
	inv := installFakeDocker(t, "longline", nil)
	sink := &lineSink{}
	f := newTestFollower("stdout", sink)
	f.maxLine = 1 << 20
	f.wrap = func(r io.Reader) io.Reader { return &failAfter{r: r, n: 64 * 1024} }

	stop := startFollower(t, f)
	waitFor(t, 15*time.Second, "reconnects after injected read errors", func() bool { return len(followInvocations(inv)) >= 3 })
	stop()
	waitAllReaped(t, readInvocations(inv))
}

// The production scenario through the fake CLI: a record over the cap does
// not need a reconnect; the same process keeps delivering.
func TestFollower_ProductionScenarioNoReconnectNeeded(t *testing.T) {
	inv := installFakeDocker(t, "longline", nil)
	sink := &lineSink{}
	f := newTestFollower("stdout", sink)
	f.maxLine = 1 << 20 // smaller than the record, to exercise the discard path

	stop := startFollower(t, f)
	waitFor(t, 15*time.Second, "1000 lines past the over-cap record", func() bool { return sink.len() >= 1000 })
	stop()
	got := sink.snapshot()
	if got[0] != "line-1" || !strings.HasPrefix(got[1], "after-") {
		t.Fatalf("stream stopped at the long line: first=%q second=%q", got[0], got[1])
	}
	if n := len(followInvocations(inv)); n != 1 {
		t.Fatalf("no reconnect expected, got %d docker logs processes", n)
	}
	waitAllReaped(t, readInvocations(inv))
}

// Closing stop (LogCollector.Stop) ends run and kills the child even while
// the parent context stays alive.
func TestFollower_StopKillsChild(t *testing.T) {
	inv := installFakeDocker(t, "silent", nil)
	f := newTestFollower("stdout", &lineSink{})
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { f.run(context.Background(), stop); close(done) }()
	waitFor(t, 10*time.Second, "attached", func() bool { return len(followInvocations(inv)) > 0 })
	close(stop)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after stop")
	}
	waitAllReaped(t, readInvocations(inv))
}

// Pins docker's long-line format: every 16 KiB partial chunk repeats the
// timestamp prefix (docker 29.4: a 70,000-byte line prints as 70,155 bytes).
func TestSplitDockerTimestamp_PartialChunks(t *testing.T) {
	ts := time.Date(2026, 10, 9, 6, 0, 58, 778203194, time.UTC)
	prefix := ts.Format(fakeTSLayout) + " "
	content := strings.Repeat("b", 70000)
	var raw strings.Builder
	for off := 0; off < len(content); off += dockerPartialChunk {
		raw.WriteString(prefix)
		raw.WriteString(content[off:min(off+dockerPartialChunk, len(content))])
	}
	if raw.Len() != 70155 {
		t.Fatalf("fixture length %d", raw.Len())
	}
	got, body, ok := splitDockerTimestamp([]byte(raw.String()))
	if !ok || !got.Equal(ts) || string(body) != content {
		t.Fatalf("ok=%v ts=%v len=%d", ok, got, len(body))
	}
	if fakeDockerChunk != dockerPartialChunk {
		t.Fatal("the fake docker CLI must split lines like the follower expects")
	}
	for _, line := range []string{
		"Error response from daemon: No such container: npg-proxy",
		"",
		"2026/10/09 12:46:28 [error] 63#63: *5 access forbidden",
	} {
		if _, _, ok := splitDockerTimestamp([]byte(line)); ok {
			t.Fatalf("%q must not parse as a docker-timestamped line", line)
		}
	}
}

// The replay boundary: lines already delivered at the cursor's timestamp are
// dropped once each, a repeated identical line is not lost, and live lines
// are never dropped, even with a timestamp behind the cursor.
func TestFollower_AcceptDropsOnlyTheReplayedBoundary(t *testing.T) {
	f := newContainerLogFollower("modsec", "c", "stdout", nil)
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Nanosecond)

	f.beginReplay()
	f.setCursor(t0)
	for _, l := range []string{"a", "b", "a"} { // first run: three lines at t1
		if !f.accept(t1, []byte(l)) {
			t.Fatalf("live line %q dropped", l)
		}
	}
	// Two reconnects in a row with nothing new: --since t1 replays a, b, a
	// each time, and each time they are dropped.
	for run := 0; run < 2; run++ {
		f.beginReplay()
		for _, l := range []string{"a", "b", "a"} {
			if f.accept(t1, []byte(l)) {
				t.Fatalf("run %d: replayed line %q delivered twice", run, l)
			}
		}
	}
	if !f.accept(t1, []byte("a")) { // a third identical "a" at t1 is new
		t.Fatal("new identical line at the cursor timestamp was dropped")
	}
	if !f.accept(t0, []byte("late")) { // live, behind the cursor (clock step)
		t.Fatal("live line behind the cursor was dropped")
	}
	if !f.cursor.Equal(t1) {
		t.Fatalf("cursor moved backwards to %v", f.cursor)
	}

	// A run that stayed quiet past the replay window is live: a line stamped
	// behind the cursor (host clock stepped back meanwhile) is delivered.
	f.beginReplay()
	f.replayStart = time.Now().Add(-followerReplayWindow - time.Second)
	if !f.accept(t0, []byte("after a clock step")) {
		t.Fatal("a line after the replay window was dropped")
	}
	if f.replaying {
		t.Fatal("replay phase did not end")
	}
}

func TestForEachLine_SkipsOverLongLinesAndKeepsHead(t *testing.T) {
	input := "short\r\n" + strings.Repeat("y", 300*1024) + "\n" + "after\n" + strings.Repeat("z", 100*1024) + "\r\nlast\ntrailing-without-newline"
	var lines []string
	var heads [][]byte
	data := 0
	err := forEachLine(strings.NewReader(input), 200*1024,
		func() { data++ },
		func(l []byte) { lines = append(lines, string(l)) },
		func(head []byte) { heads = append(heads, append([]byte(nil), head...)) })
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 4 || lines[0] != "short" || lines[1] != "after" || len(lines[2]) != 100*1024 || lines[3] != "last" {
		t.Fatalf("lines: %d %q", len(lines), lines[0])
	}
	if len(heads) != 1 || string(heads[0]) != strings.Repeat("y", oversizeHead) {
		t.Fatalf("oversize heads: %q", heads)
	}
	if data == 0 {
		t.Fatal("onData never called")
	}
	if err := forEachLine(io.MultiReader(strings.NewReader("x\n"), &failAfter{n: 0}), 1024, nil, func([]byte) {}, nil); err == nil || err.Error() != "injected read error" {
		t.Fatalf("read error not returned: %v", err)
	}
}

package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"nginx-proxy-guard/internal/metrics"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

type tailRig struct {
	t     *testing.T
	path  string
	clock *fakeClock
	tail  *fileTail
	got   []string
}

func newTailRig(t *testing.T) *tailRig {
	t.Helper()
	r := &tailRig{t: t, path: filepath.Join(t.TempDir(), "access_raw.log"), clock: &fakeClock{t: time.Unix(1_800_000_000, 0)}}
	if err := os.WriteFile(r.path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	r.tail = newFileTail(r.path, r.clock.Now)
	if err := r.tail.open(false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.tail.close)
	return r
}

// writer opens path the way nginx does: its own descriptor, appending, so
// writes go to whatever inode it opened.
func (r *tailRig) writer(path string) *os.File {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { f.Close() })
	return f
}

// poll polls until nothing more is read.
func (r *tailRig) poll() {
	for r.tail.poll(func(l string) { r.got = append(r.got, l) }) {
	}
}

func (r *tailRig) rotate(suffix string) {
	r.t.Helper()
	if err := os.Rename(r.path, r.path+suffix); err != nil {
		r.t.Fatal(err)
	}
}

func writeString(t *testing.T, f *os.File, s string) {
	t.Helper()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// The race the tail lost lines to: after logrotate's rename + create, nginx
// flushes its buffered lines into the OLD inode when USR1 makes it reopen -
// after the tail has already switched to the new file.
func TestFileTail_ReadsLinesWrittenToRotatedInodeAfterSwitch(t *testing.T) {
	r := newTailRig(t)
	old := r.writer(r.path)
	writeString(t, old, "a1\na2\n")
	r.poll()

	r.rotate("-20261009-010000") // nginx has not reopened yet
	nw := r.writer(r.path)
	writeString(t, nw, "b1\n")
	r.poll()                        // switches to the new file; the old one drains
	writeString(t, old, "a3\na4\n") // USR1: a worker flushes into the old inode
	writeString(t, nw, "b2\n")
	before := testutil.ToFloat64(metrics.LogCollectorTailRotatedLinesTotal)
	r.poll()

	if want := []string{"a1", "a2", "b1", "a3", "a4", "b2"}; !reflect.DeepEqual(r.got, want) {
		t.Fatalf("got %v want %v", r.got, want)
	}
	if late := testutil.ToFloat64(metrics.LogCollectorTailRotatedLinesTotal) - before; late != 2 || r.tail.drainedLines != 2 {
		t.Fatalf("late lines counted: metric +%v, drained=%d, want 2", late, r.tail.drainedLines)
	}
}

func TestFileTail_ClosesRotatedInodeOnlyAfterQuietWindow(t *testing.T) {
	r := newTailRig(t)
	old := r.writer(r.path)
	r.rotate("-x")
	r.writer(r.path)
	r.poll()
	if len(r.tail.draining) != 1 {
		t.Fatalf("draining=%d want 1", len(r.tail.draining))
	}
	r.clock.Advance(tailQuietWindow - time.Second)
	writeString(t, old, "late\n") // still inside the window: read, and the window restarts
	r.poll()
	r.clock.Advance(tailQuietWindow - time.Second)
	r.poll()
	if len(r.tail.draining) != 1 {
		t.Fatal("closed too early")
	}
	r.clock.Advance(2 * time.Second)
	r.poll()
	if len(r.tail.draining) != 0 {
		t.Fatalf("draining=%d want 0 after the quiet window", len(r.tail.draining))
	}
	if !reflect.DeepEqual(r.got, []string{"late"}) {
		t.Fatalf("got %v", r.got)
	}
}

func TestFileTail_PartialLineAtEOFIsCompletedNotDropped(t *testing.T) {
	r := newTailRig(t)
	w := r.writer(r.path)
	writeString(t, w, "first\nsec")
	r.poll()
	writeString(t, w, "ond\nthird\n")
	r.poll()
	if want := []string{"first", "second", "third"}; !reflect.DeepEqual(r.got, want) {
		t.Fatalf("got %v want %v", r.got, want)
	}
}

// A partial line left in a rotated inode is completed by the flush that
// arrives after the switch.
func TestFileTail_PartialLineInRotatedInodeIsCompleted(t *testing.T) {
	r := newTailRig(t)
	old := r.writer(r.path)
	writeString(t, old, "a1\na2-par")
	r.poll()
	r.rotate("-x")
	writeString(t, r.writer(r.path), "b1\n")
	r.poll()
	writeString(t, old, "tial\n")
	r.poll()
	if want := []string{"a1", "b1", "a2-partial"}; !reflect.DeepEqual(r.got, want) {
		t.Fatalf("got %v want %v", r.got, want)
	}
}

func TestFileTail_MissingPathKeepsReadingOldDescriptor(t *testing.T) {
	r := newTailRig(t)
	w := r.writer(r.path)
	r.rotate("-x") // no create yet
	writeString(t, w, "during-gap\n")
	r.poll()
	if !reflect.DeepEqual(r.got, []string{"during-gap"}) {
		t.Fatalf("got %v", r.got)
	}
}

// RestartTail onto the inode already being read must not read it again.
func TestFileTail_ReopenSameInodeDoesNotDuplicate(t *testing.T) {
	r := newTailRig(t)
	w := r.writer(r.path)
	writeString(t, w, "x1\n")
	r.poll()
	if err := r.tail.reopen(r.path, true); err != nil {
		t.Fatal(err)
	}
	writeString(t, w, "x2\n")
	r.poll()
	if !reflect.DeepEqual(r.got, []string{"x1", "x2"}) {
		t.Fatalf("got %v", r.got)
	}
}

// RestartTail (the pipeline canary's heal) can arrive while the tail is still
// behind on a file logrotate has just renamed. The new file at the same path
// has held nginx's lines since the rotation, and none of them has been read:
// it is read from its start, as poll's own switch would. Only a different
// path skips what its file already holds.
func TestFileTail_RestartAfterUnseenRotationReadsTheNewFileFromItsStart(t *testing.T) {
	r := newTailRig(t)
	writeString(t, r.writer(r.path), "a1\n")
	r.rotate("-20261010-000000") // the tail has not polled since
	nw := r.writer(r.path)       // logrotate's create; nginx reopens on USR1
	writeString(t, nw, "b1\nb2\n")
	if err := r.tail.reopen(r.path, true); err != nil { // as streamFileAccessLogs does
		t.Fatal(err)
	}
	writeString(t, nw, "b3\n")
	r.poll()
	if want := []string{"a1", "b1", "b2", "b3"}; !reflect.DeepEqual(r.got, want) {
		t.Fatalf("got %v want %v", r.got, want)
	}

	other := filepath.Join(filepath.Dir(r.path), "other.log")
	if err := os.WriteFile(other, []byte("history\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.tail.reopen(other, true); err != nil {
		t.Fatal(err)
	}
	writeString(t, r.writer(other), "c1\n")
	r.poll()
	if want := []string{"a1", "b1", "b2", "b3", "c1"}; !reflect.DeepEqual(r.got, want) {
		t.Fatalf("after a restart onto another path: got %v want %v", r.got, want)
	}
}

func TestFileTail_TruncationRestartsFromZero(t *testing.T) {
	r := newTailRig(t)
	w := r.writer(r.path)
	writeString(t, w, "aaaa\nbbbb\n")
	r.poll()
	if err := os.Truncate(r.path, 0); err != nil {
		t.Fatal(err)
	}
	writeString(t, w, "cc\n") // O_APPEND: lands at the new end, offset 0
	r.poll()
	if !reflect.DeepEqual(r.got, []string{"aaaa", "bbbb", "cc"}) {
		t.Fatalf("got %v", r.got)
	}
}

func TestFileTail_OverlongLineIsDroppedNotBuffered(t *testing.T) {
	r := newTailRig(t)
	w := r.writer(r.path)
	before := testutil.ToFloat64(metrics.LogCollectorTailOverlongLinesTotal)
	writeString(t, w, strings.Repeat("z", tailMaxLine+10)+"\nok\n")
	r.poll()
	if !reflect.DeepEqual(r.got, []string{"ok"}) || r.tail.droppedLong != 1 {
		t.Fatalf("got %d lines, dropped=%d", len(r.got), r.tail.droppedLong)
	}
	if d := testutil.ToFloat64(metrics.LogCollectorTailOverlongLinesTotal) - before; d != 1 {
		t.Fatalf("overlong metric +%v, want 1", d)
	}
}

// A rotated file that keeps growing must not hold up the switch to a newer
// file: once the current one is at EOF, the next rotation is followed even
// while an older inode still drains.
func TestFileTail_SwitchesWhileAnOlderFileStillDrains(t *testing.T) {
	r := newTailRig(t)
	w0 := r.writer(r.path)
	r.rotate("-1")
	writeString(t, r.writer(r.path), "f1-a\n")
	r.poll() // current: file 1; draining: file 0
	r.rotate("-2")
	writeString(t, r.writer(r.path), "f2-a\n")
	emit := func(l string) { r.got = append(r.got, l) }
	for i := 0; i < 5; i++ {
		writeString(t, w0, "f0-late-"+strconv.Itoa(i)+"\n") // file 0 grows before every poll
		r.tail.poll(emit)
	}
	if !strings.Contains(strings.Join(r.got, ","), "f2-a") {
		t.Fatalf("file 2 not read while file 0 kept draining: %v", r.got)
	}
	r.poll()
	if len(r.got) != 7 {
		t.Fatalf("got %v", r.got)
	}
}

func TestFileTail_BurstOfRotationsCapsOpenDescriptors(t *testing.T) {
	r := newTailRig(t)
	for i := 0; i < tailMaxDraining+3; i++ {
		r.rotate("-" + strconv.Itoa(i))
		writeString(t, r.writer(r.path), "l\n")
		r.poll()
	}
	if len(r.tail.draining) > tailMaxDraining {
		t.Fatalf("draining=%d > cap %d", len(r.tail.draining), tailMaxDraining)
	}
}

// One poll reads at most tailLinesPerPoll lines, so stop and restart stay
// responsive; the rest comes with the next polls, in order.
func TestFileTail_PollReadsABoundedNumberOfLines(t *testing.T) {
	r := newTailRig(t)
	w := r.writer(r.path)
	var b strings.Builder
	for i := 0; i < tailLinesPerPoll+10; i++ {
		fmt.Fprintf(&b, "l%d\n", i)
	}
	writeString(t, w, b.String())
	n := 0
	if !r.tail.poll(func(string) { n++ }) || n != tailLinesPerPoll {
		t.Fatalf("first poll read %d lines, want %d", n, tailLinesPerPoll)
	}
	r.poll()
	if len(r.got) != 10 || r.got[9] != "l"+strconv.Itoa(tailLinesPerPoll+9) {
		t.Fatalf("the rest: %d lines", len(r.got))
	}
}

// nginx buffers access lines (buffer=64k flush=5s) and flushes them into the
// old inode when it reopens after a rotation; the tail keeps that inode open
// until it has been quiet for tailQuietWindow. The window must stay at least
// twice the flush interval, or the loss at rotation comes back. This reads
// the flush interval from every place that renders the access_raw.log
// directive.
func TestTailQuietWindowCoversNginxFlush(t *testing.T) {
	flush := regexp.MustCompile(`access_raw\.log[^;\n]*\bflush=(\d+)s`)
	for _, src := range []string{
		"../handler/system_settings_rawlog.go",          // 00-raw-logging.conf
		"../nginx/templates/proxy_host/base.conf.tmpl",  // per-host access_log
		"../nginx/templates/proxy_host/cache.conf.tmpl", // per-host access_log (cache)
	} {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("%s: %v (moved? update this test with the new place of the access_raw.log directive)", src, err)
		}
		m := flush.FindAllStringSubmatch(string(b), -1)
		if len(m) == 0 {
			t.Fatalf("%s: no access_raw.log flush=Ns found", src)
		}
		for _, sm := range m {
			secs, _ := strconv.Atoi(sm[1])
			if f := time.Duration(secs) * time.Second; tailQuietWindow < 2*f {
				t.Errorf("%s: flush=%v needs tailQuietWindow >= %v (is %v)", src, f, 2*f, tailQuietWindow)
			}
		}
	}
}

// End to end through streamFileAccessLogs: lines nginx writes to the renamed
// file after the collector has switched to the new one are still stored, and
// a restart onto the same file reads nothing twice.
func TestStreamFileAccessLogs_KeepsLinesWrittenToRotatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access_raw.log")
	if err := os.WriteFile(path, []byte("192.0.2.9 - - [09/Oct/2026:11:59:59 +0900] \"app.example.com\" \"GET /history HTTP/1.1\" 200 1 \"-\" \"curl/8\" \"-\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := NewLogCollector(nil, "npg-proxy", path, nil, nil)
	c.batchSize = 1 << 30 // memory buffer only
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.streamFileAccessLogs(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("streamFileAccessLogs did not return")
		}
	}()
	line := func(uri string) string {
		return `192.0.2.10 - - [09/Oct/2026:12:00:00 +0900] "app.example.com" "GET ` + uri + ` HTTP/1.1" 200 1 "-" "curl/8" "-"` + "\n"
	}
	stored := func(uri string) int { return bufferedURIs(c)[uri] }
	open := func(p string) *os.File {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}

	old := open(path) // nginx's descriptor
	// The tail opens at the end of the file; write probes until one is read,
	// so nothing below races that first open.
	probes, lastProbe := 0, time.Time{}
	waitFor(t, 10*time.Second, "file-tail reading", func() bool {
		for i := 1; i <= probes; i++ {
			if stored("/ready-"+strconv.Itoa(i)) > 0 {
				return true
			}
		}
		if time.Since(lastProbe) >= 250*time.Millisecond {
			probes++
			writeString(t, old, line("/ready-"+strconv.Itoa(probes)))
			lastProbe = time.Now()
		}
		return false
	})
	writeString(t, old, line("/a1"))
	waitFor(t, 5*time.Second, "/a1 stored", func() bool { return stored("/a1") == 1 })

	if err := os.Rename(path, path+"-20261009-120000"); err != nil { // logrotate
		t.Fatal(err)
	}
	nw := open(path)
	writeString(t, nw, line("/b1"))
	waitFor(t, 5*time.Second, "/b1 stored (switched to the new file)", func() bool { return stored("/b1") == 1 })

	writeString(t, old, line("/a2-late")) // flushed into the old inode on reopen
	writeString(t, nw, line("/b2"))
	waitFor(t, 5*time.Second, "the late line and /b2 stored", func() bool { return stored("/a2-late") == 1 && stored("/b2") == 1 })

	c.RestartTail() // same file: must not read it again
	writeString(t, nw, line("/b3"))
	waitFor(t, 5*time.Second, "/b3 stored", func() bool { return stored("/b3") == 1 })
	got := bufferedURIs(c)
	if got["/history"] != 0 {
		t.Error("history before the start must not be ingested")
	}
	for _, uri := range []string{"/a1", "/b1", "/a2-late", "/b2", "/b3"} {
		if got[uri] != 1 {
			t.Errorf("%s stored %d times, want 1", uri, got[uri])
		}
	}
}

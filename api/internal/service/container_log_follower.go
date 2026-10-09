package service

// containerLogFollower reads one stream of `docker logs --follow` for the
// nginx container: stdout carries ModSecurity's JSON audit records, stderr
// carries nginx's error log.
//
// Why it exists: in production, WAF events and WAF auto-ban stopped on
// 2026-09-27 and stayed dead for twelve days. The previous reader used
// bufio.Scanner with a 1 MiB token limit. One audit record over 1 MiB (a rule
// match on a large HTML page, logged together with its response body) made
// Scan() return false; the loop then stopped its watchdog and called
// cmd.Wait() without killing `docker logs`. The child filled the pipe, blocked
// in write(2) and never exited, so Wait never returned and nothing ever
// restarted the stream.
//
// Invariants kept here:
//  1. Reading never stops on a long line. A line over maxLine is discarded
//     (counted) and reading continues with the next one.
//  2. Every exit path kills the child before Wait: each process runs under its
//     own context, cancelled by defer, and Wait is bounded by WaitDelay.
//  3. The watchdog lives until the child has been reaped, so max-age and the
//     stall probe keep working while the reader is blocked.
//  4. Reconnects lose nothing and repeat nothing. Lines carry docker's own
//     timestamp (--timestamps); a reconnect resumes with --since <timestamp of
//     the last delivered line> and drops the lines already delivered at
//     exactly that timestamp (--since is inclusive at nanosecond precision),
//     however long the daemon takes to answer.
//  5. A stuck follow is noticed on a busy container too. The stall probe
//     runs only after the follower has been silent for probeAfter, so a line
//     on its stream after the cursor that docker has held for more than
//     lagGrace was missed, and so was a younger one that has still not
//     arrived by the next tick. docker counts --tail across both streams, so
//     on a busy container the entries the probe sees may all be seconds old.

import (
	"bufio"
	"bytes"
	"context"
	"hash/fnv"
	"io"
	"log"
	"os/exec"
	"strconv"
	"sync/atomic"
	"time"

	"nginx-proxy-guard/internal/metrics"
)

const (
	// followerMaxLine bounds the memory one log line may take. An audit record
	// with part E (response body) is at most SecResponseBodyLimit (1 MiB) plus
	// JSON escaping and headers - 1,121,516 bytes measured for a 1.5 MB HTML
	// page, and worst-case escaping of control bytes is 6x. 8 MiB keeps every
	// such record parseable while an API that already has this reader still
	// runs next to an nginx image that logs bodies, and it still bounds a
	// pathological line without '\n'.
	followerMaxLine = 8 << 20

	// followerMaxAge forces a reconnect even when the stream looks healthy, as
	// a backstop for any stall the probe cannot see. Reconnects replay from
	// the cursor, so this costs one `docker logs` spawn and nothing else.
	followerMaxAge = time.Hour

	// followerTick is how often the watchdog looks at the stream.
	followerTick = 30 * time.Second

	// followerProbeAfter: only after nothing has arrived for this long does
	// the watchdog ask docker whether it holds a line the follower missed. A
	// quiet stream is normal (stdout carries only rule matches and the
	// optional access copy), so silence alone is never a reason to reconnect.
	followerProbeAfter = 90 * time.Second

	// followerProbeEvery spaces the probes on a stream that stays quiet.
	followerProbeEvery = 2 * time.Minute

	// followerLagGrace is how long a line may be on its way from docker to
	// the follower. The probe runs only after the follower has been silent
	// for probeAfter, so a line on its stream after the cursor that docker
	// has held longer than this was missed: the follow RPC is stuck (the
	// 2026-05-19/20 incidents: `docker logs --follow` alive, silent, for
	// hours). A line still younger than this is checked again on the next
	// tick: if nothing has arrived by then, the follow is stuck as well.
	followerLagGrace = 2 * time.Second

	// followerReplayTail bounds what the daemon reads on a reconnect. Without
	// --tail, `docker logs --since` decodes every retained json-file from the
	// start (3.4 s measured for 294 MB); with --tail 100000 it takes about
	// 0.5 s and still covers about 30 minutes of the busiest stdout measured.
	// docker counts it across stdout and stderr together.
	followerReplayTail = 100000

	// followerProbeTail is how many of the newest entries the probe reads.
	// docker applies --tail across stdout and stderr together, before --since
	// and before the stream is picked, so on a busy container the newest
	// entries span only seconds: production stdout carries about 37 access
	// lines/s when the access copy is on. 5000 entries cover minutes of that
	// and are cheap to read; a burst too fast even for that is caught by the
	// next-tick check (see followerLagGrace).
	followerProbeTail = 5000

	// followerProbeOutput caps what one probe keeps of its stream. docker
	// prints the oldest entries first, and those are the ones the probe looks
	// for.
	followerProbeOutput = 4 << 20

	// followerProbeTimeout bounds one probe.
	followerProbeTimeout = 10 * time.Second

	// followerReapTimeout: if the reader has not returned this long after the
	// kill, the pipe is closed from our side. A killed docker CLI has no
	// children holding the pipe, so this should never fire.
	followerReapTimeout = 15 * time.Second

	// followerWaitDelay bounds cmd.Wait's I/O wait after the child is gone.
	followerWaitDelay = 5 * time.Second

	// followerQuickDeath: a run that ends within this window without
	// delivering anything counts as a failed attach (container missing,
	// daemon down) and backs off; any other run reconnects at once.
	followerQuickDeath = 5 * time.Second

	// followerFailLogEvery: while attaching keeps failing, the reconnect line
	// is logged for the first failure and then at most this often.
	followerFailLogEvery = 10 * time.Minute

	// dockerPartialChunk is the daemon's log copier buffer (moby
	// daemon/logger/copier.go). A longer line is stored as partial entries
	// that share one timestamp, and with --timestamps every partial gets the
	// prefix again: for a 70,000-byte line `docker logs -t` printed the same
	// 31-byte prefix at offsets 0, 16415, 32830, 49245 and 65660 (docker 29.4).
	dockerPartialChunk = 16 * 1024

	// oversizeHead is how much of a discarded line is kept: enough for the
	// docker timestamp, so the cursor still moves past the line.
	oversizeHead = 64
)

// containerLogFollower follows one stream ("stdout" or "stderr") of a
// container through the docker CLI. It is not safe for concurrent use: run
// owns it.
type containerLogFollower struct {
	label     string // metrics/log label: "modsec" | "error"
	container string
	stream    string // "stdout" | "stderr"
	handle    func(line string, ts time.Time)

	maxLine      int
	maxAge       time.Duration
	tick         time.Duration
	probeAfter   time.Duration
	probeEvery   time.Duration
	lagGrace     time.Duration
	replayTail   int
	probeTail    int
	reapTimeout  time.Duration
	minBackoff   time.Duration
	maxBackoff   time.Duration
	failLogEvery time.Duration

	// command builds the subprocess: exec.CommandContext in production.
	command func(ctx context.Context, name string, args ...string) *exec.Cmd
	// wrap lets tests inject reader faults; nil in production.
	wrap func(io.Reader) io.Reader

	// cursor is docker's timestamp of the newest delivered line; atCursor
	// counts the delivered lines with exactly that timestamp, by content
	// hash. replayed counts the same during the replay at the start of a run.
	cursor      time.Time
	cursorNanos atomic.Int64 // cursor, for the watchdog goroutine
	atCursor    map[uint64]int
	replayed    map[uint64]int
	replaying   bool // from (re)attach until the first line not seen before

	lastDataAt atomic.Int64 // unix nanos of the last byte received
	runs       atomic.Int64 // docker logs --follow processes started
	cliMsg     string       // the docker CLI's own last complaint, for the log
}

func newContainerLogFollower(label, container, stream string, handle func(line string, ts time.Time)) *containerLogFollower {
	return &containerLogFollower{
		label:        label,
		container:    container,
		stream:       stream,
		handle:       handle,
		maxLine:      followerMaxLine,
		maxAge:       followerMaxAge,
		tick:         followerTick,
		probeAfter:   followerProbeAfter,
		probeEvery:   followerProbeEvery,
		lagGrace:     followerLagGrace,
		replayTail:   followerReplayTail,
		probeTail:    followerProbeTail,
		reapTimeout:  followerReapTimeout,
		minBackoff:   time.Second,
		maxBackoff:   30 * time.Second,
		failLogEvery: followerFailLogEvery,
		command:      exec.CommandContext,
		atCursor:     map[uint64]int{},
		replayed:     map[uint64]int{},
	}
}

// run follows the stream until ctx is cancelled or stop is closed.
func (f *containerLogFollower) run(ctx context.Context, stop <-chan struct{}) {
	backoff := f.minBackoff
	failures := 0
	var lastFailLog time.Time
	// A stall that delivered nothing may have been a daemon still scanning a
	// large log for the replay, not a stuck follow. The next run then waits
	// twice as long before probing (up to max-age), so a slow replay cannot
	// become a reconnect loop that never delivers.
	probeAfter := f.probeAfter
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		default:
		}

		started := time.Now()
		reason, delivered := f.runOnce(ctx, stop, probeAfter)
		lived := time.Since(started)
		if reason == "shutdown" {
			return
		}
		if reason == "max_age" || reason == "stall" {
			// Watchdog-driven restarts, the metric's historical meaning.
			metrics.LogCollectorWatchdogRestartTotal.WithLabelValues(reason).Inc()
		}
		switch {
		case reason == "stall" && delivered == 0:
			probeAfter = min(probeAfter*2, f.maxAge)
		case delivered > 0:
			probeAfter = f.probeAfter
		}

		// Back off only when the process died at once without data; any
		// other reconnect is immediate (it replays from the cursor anyway).
		wait := f.minBackoff
		quickDeath := delivered == 0 && lived < followerQuickDeath
		if quickDeath {
			failures++
			wait = backoff
			backoff = min(backoff*2, f.maxBackoff)
		} else {
			failures = 0
			backoff = f.minBackoff
		}

		// One line per reconnect, except the routine hourly one, and except
		// repeats of the same failed attach (logged first, then at most every
		// failLogEvery while it keeps failing).
		if reason != "max_age" && (!quickDeath || failures == 1 || time.Since(lastFailLog) >= f.failLogEvery) {
			if quickDeath {
				lastFailLog = time.Now()
			}
			detail := ""
			if f.cliMsg != "" {
				detail = " (docker: " + f.cliMsg + ")"
			}
			if failures > 1 {
				detail += " [" + strconv.Itoa(failures) + " failed attaches in a row]"
			}
			log.Printf("[LogCollector] %s stream (%s) reconnecting: %s after %s, %d lines%s",
				f.label, f.stream, reason, lived.Round(time.Second), delivered, detail)
		}
		f.cliMsg = ""

		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-time.After(wait):
		}
	}
}

// runOnce runs one `docker logs --follow` process to completion and reports
// why it ended ("max_age", "stall", "eof", "read_error", "start_failed" or
// "shutdown") and how many lines it handed to the handler.
func (f *containerLogFollower) runOnce(parent context.Context, stop <-chan struct{}, probeAfter time.Duration) (reason string, delivered int) {
	ctx, kill := context.WithCancel(parent)
	defer kill() // invariant 2: whatever happens below, the child dies

	if f.cursor.IsZero() {
		f.setCursor(time.Now()) // first attach: follow from now, like --tail 0
	}
	cmd := f.command(ctx, "docker", "logs", "--follow", "--timestamps",
		"--since", formatDockerSince(f.cursor),
		"--tail", strconv.Itoa(f.replayTail),
		f.container)
	cmd.WaitDelay = followerWaitDelay

	// The other stream goes to /dev/null. The CLI's own complaints ("No such
	// container") are written to stderr, so the error-log follower reports
	// them for both.
	var pipe io.ReadCloser
	var err error
	if f.stream == "stderr" {
		pipe, err = cmd.StderrPipe()
	} else {
		pipe, err = cmd.StdoutPipe()
	}
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		f.cliMsg = err.Error()
		return "start_failed", 0
	}
	f.runs.Add(1)
	f.beginReplay()
	f.lastDataAt.Store(time.Now().UnixNano())

	reasonCh := make(chan string, 1)
	reaped := make(chan struct{})
	go f.watch(ctx, stop, kill, pipe, reaped, reasonCh, probeAfter)

	var src io.Reader = pipe
	if f.wrap != nil {
		src = f.wrap(pipe)
	}
	delivered, readErr := f.readAll(src) // invariant 1: only EOF or a read error ends it
	kill()                               // e.g. a read error while docker still writes
	_ = cmd.Wait()                       // bounded: the child is dead, WaitDelay bounds the I/O
	close(reaped)                        // invariant 3: the watchdog outlived the child

	select {
	case r := <-reasonCh:
		return r, delivered
	default:
	}
	if parent.Err() != nil {
		return "shutdown", delivered
	}
	select {
	case <-stop:
		return "shutdown", delivered
	default:
	}
	if readErr != nil {
		if f.cliMsg == "" {
			f.cliMsg = readErr.Error()
		}
		return "read_error", delivered
	}
	return "eof", delivered
}

// watch enforces max-age, the stall probe (after probeAfter of silence) and
// stop for one process. It returns only once that process has been reaped.
func (f *containerLogFollower) watch(ctx context.Context, stop <-chan struct{}, kill context.CancelFunc, pipe io.Closer, reaped <-chan struct{}, reasonCh chan<- string, probeAfter time.Duration) {
	age := time.NewTimer(f.maxAge)
	defer age.Stop()
	ticker := time.NewTicker(f.tick)
	defer ticker.Stop()
	done := ctx.Done()
	var killedAt, lastProbe time.Time
	reapWarned := false
	// A line docker held at the last probe that had not reached the follower
	// yet, and lastDataAt at that probe: if nothing arrives within lagGrace,
	// the follow is stuck, however many newer entries docker holds by then.
	var pendingSince time.Time
	var pendingDataAt int64
	stopWith := func(r string) {
		select {
		case reasonCh <- r:
		default:
		}
		kill()
		if killedAt.IsZero() {
			killedAt = time.Now()
		}
	}
	for {
		select {
		case <-reaped:
			return
		case <-stop:
			stop = nil // closed: never select it again
			stopWith("shutdown")
		case <-done:
			done = nil // killed by the reader's exit path or by the parent
			if killedAt.IsZero() {
				killedAt = time.Now()
			}
		case <-age.C:
			if killedAt.IsZero() {
				stopWith("max_age")
			}
		case <-ticker.C:
			if !killedAt.IsZero() {
				if !reapWarned && time.Since(killedAt) > f.reapTimeout {
					reapWarned = true
					log.Printf("[LogCollector] ERROR: %s stream reader still blocked %s after the kill; closing the pipe",
						f.label, time.Since(killedAt).Round(time.Second))
					_ = pipe.Close()
				}
				continue
			}
			if !pendingSince.IsZero() {
				switch {
				case f.lastDataAt.Load() != pendingDataAt:
					pendingSince = time.Time{} // the stream moved
				case time.Since(pendingSince) >= f.lagGrace:
					stopWith("stall")
					continue
				}
			}
			idle := time.Since(time.Unix(0, f.lastDataAt.Load()))
			if idle < probeAfter || time.Since(lastProbe) < f.probeEvery {
				continue
			}
			lastProbe = time.Now()
			dataAt := f.lastDataAt.Load()
			switch stalled, waiting := f.probe(ctx, dataAt); {
			case stalled:
				stopWith("stall")
			case waiting && (pendingSince.IsZero() || pendingDataAt != dataAt):
				// Keep the first sighting while nothing arrives: a later
				// probe that sees the line again does not restart the wait.
				pendingSince, pendingDataAt = lastProbe, dataAt
			}
		}
	}
}

// probe asks docker, in a separate non-follow request, for the newest entries
// after the cursor, and looks at the ones on our stream. The follower has
// been silent for at least probeAfter when this runs, so any such line that
// docker has held for more than lagGrace was missed: stalled. A line younger
// than that is reported as waiting, and watch checks on the next tick whether
// anything has arrived since. dataAt is lastDataAt when the probe started;
// if data arrives while it runs, the stream is moving and nothing is
// reported. Any error means "unknown", which is treated as not stalled:
// max-age still bounds the damage.
func (f *containerLogFollower) probe(parent context.Context, dataAt int64) (stalled, waiting bool) {
	ctx, cancel := context.WithTimeout(parent, followerProbeTimeout)
	defer cancel()
	started := time.Now()
	cursor := time.Unix(0, f.cursorNanos.Load())
	cmd := f.command(ctx, "docker", "logs", "--timestamps",
		"--since", formatDockerSince(cursor),
		"--tail", strconv.Itoa(f.probeTail),
		f.container)
	cmd.WaitDelay = 2 * time.Second
	var out bytes.Buffer
	w := &limitedWriter{w: &out, n: followerProbeOutput}
	if f.stream == "stderr" {
		cmd.Stderr = w
	} else {
		cmd.Stdout = w
	}
	if err := cmd.Run(); err != nil && out.Len() == 0 {
		return false, false
	}
	if f.lastDataAt.Load() != dataAt {
		return false, false
	}
	deadline := started.Add(-f.lagGrace)
	for _, line := range bytes.Split(out.Bytes(), []byte{'\n'}) {
		ts, _, ok := splitDockerTimestamp(line)
		if !ok || !ts.After(cursor) {
			continue
		}
		if ts.Before(deadline) {
			return true, false
		}
		waiting = true
	}
	return false, waiting
}

// readAll reads lines until EOF or a read error. Over-long lines are
// discarded, never fatal.
func (f *containerLogFollower) readAll(r io.Reader) (int, error) {
	delivered := 0
	oversize := 0
	var lastOversizeLog time.Time
	err := forEachLine(r, f.maxLine,
		func() { f.lastDataAt.Store(time.Now().UnixNano()) },
		func(line []byte) {
			if f.deliver(line) {
				delivered++
			}
		},
		func(head []byte) {
			metrics.LogCollectorOversizeLinesTotal.WithLabelValues(f.label).Inc()
			oversize++
			if time.Since(lastOversizeLog) >= time.Minute {
				log.Printf("[LogCollector] %s stream: discarded %d line(s) over %d bytes", f.label, oversize, f.maxLine)
				lastOversizeLog, oversize = time.Now(), 0
			}
			if ts, _, ok := splitDockerTimestamp(head); ok {
				f.accept(ts, nil) // move the cursor past it: never replay it
			}
		})
	return delivered, err
}

// forEachLine calls onLine for every '\n'-terminated line of r (without the
// '\n' and a '\r' before it) until EOF, and returns nil at EOF or the read
// error. onLine must not
// keep the slice. A line longer than maxLine bytes is not an error:
// onOversize gets its first bytes and reading continues with the next line.
// bufio.Scanner instead stops for good at its limit (ErrTooLong), which is how
// both docker-logs readers deadlocked. A trailing fragment without '\n' is
// dropped. onData, when set, is called whenever bytes arrive.
func forEachLine(r io.Reader, maxLine int, onData func(), onLine func([]byte), onOversize func(head []byte)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var buf []byte
	discarding := false
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 && onData != nil {
			onData()
		}
		if err == nil && len(buf) == 0 && !discarding && len(chunk) <= maxLine {
			onLine(trimEOL(chunk)) // whole line in the read buffer: no copy
			continue
		}
		if len(chunk) > 0 {
			switch {
			case discarding:
			case len(buf)+len(chunk) > maxLine:
				discarding = true
				if len(buf) < oversizeHead {
					buf = append(buf, chunk[:min(len(chunk), oversizeHead-len(buf))]...)
				}
				buf = buf[:min(len(buf), oversizeHead)]
			default:
				buf = append(buf, chunk...)
			}
		}
		switch err {
		case nil:
			if discarding {
				if onOversize != nil {
					onOversize(buf)
				}
			} else {
				onLine(trimEOL(buf))
			}
			if cap(buf) > 1<<20 {
				buf = nil // do not pin a multi-MiB buffer after one huge line
			} else {
				buf = buf[:0]
			}
			discarding = false
		case bufio.ErrBufferFull:
			// a long line: keep accumulating (or discarding) until its '\n'
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}

// trimEOL drops the line's '\n' and a '\r' before it, as bufio.ScanLines did.
func trimEOL(line []byte) []byte {
	line = line[:len(line)-1]
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line
}

// deliver strips docker's timestamp, drops the replayed boundary and hands the
// line over. It reports whether the handler was called.
func (f *containerLogFollower) deliver(raw []byte) bool {
	ts, content, ok := splitDockerTimestamp(raw)
	if !ok {
		// Not docker-timestamped: the CLI's own message on stderr ("Error
		// response from daemon: ..."), never a container log line.
		if len(raw) > 0 {
			f.cliMsg = truncateForLog(raw, 200)
		}
		return false
	}
	if !f.accept(ts, content) {
		metrics.LogCollectorReplayDedupTotal.WithLabelValues(f.label).Inc()
		return false
	}
	if len(content) == 0 {
		return false
	}
	f.handle(string(content), ts)
	return true
}

// accept decides whether a line is new and moves the cursor.
//
// Duplicates only exist at the start of a run: --since is inclusive, so the
// lines already delivered at exactly the cursor's timestamp come back first,
// and nothing older comes back at all (docker filters followed lines by
// --since as well). The replay phase therefore ends at the first line that
// is not one of them, by content, not after some time: a daemon busy with a
// large log can take minutes to answer a reconnect, and its first line is
// still the boundary. From then on every line is delivered, even one older
// than the cursor: a host clock stepping back must not silently drop live
// lines.
func (f *containerLogFollower) accept(ts time.Time, content []byte) bool {
	h := fnv.New64a()
	_, _ = h.Write(content)
	sum := h.Sum64()
	if f.replaying {
		if ts.Equal(f.cursor) {
			f.replayed[sum]++
			if f.replayed[sum] <= f.atCursor[sum] {
				return false
			}
		}
		f.replaying = false
		clear(f.replayed)
	}
	if ts.After(f.cursor) {
		f.setCursor(ts)
		clear(f.atCursor)
	}
	if ts.Equal(f.cursor) {
		f.atCursor[sum]++
	}
	return true
}

// beginReplay marks the start of a run: its first lines may be the ones
// already delivered at the cursor's timestamp.
func (f *containerLogFollower) beginReplay() {
	f.replaying = true
	clear(f.replayed)
}

func (f *containerLogFollower) setCursor(ts time.Time) {
	f.cursor = ts
	f.cursorNanos.Store(ts.UnixNano())
}

// formatDockerSince renders a cursor for `docker logs --since`, which accepts
// RFC 3339 with nanoseconds and filters inclusively at that precision.
func formatDockerSince(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// splitDockerTimestamp parses the "<RFC3339Nano> " prefix that
// `docker logs --timestamps` puts on every entry, and removes the copies the
// daemon repeats inside a line longer than one partial chunk (all partials of
// a line share the first one's timestamp, see dockerPartialChunk).
func splitDockerTimestamp(raw []byte) (time.Time, []byte, bool) {
	sp := bytes.IndexByte(raw[:min(len(raw), 40)], ' ')
	if sp < 20 {
		return time.Time{}, raw, false
	}
	ts, err := time.Parse(time.RFC3339Nano, string(raw[:sp]))
	if err != nil {
		return time.Time{}, raw, false
	}
	prefix := raw[:sp+1]
	content := raw[sp+1:]
	if len(content) > dockerPartialChunk && bytes.Contains(content, prefix) {
		content = bytes.ReplaceAll(content, prefix, nil)
	}
	return ts, content, true
}

// limitedWriter keeps the first n bytes written to it and discards the rest
// without failing the writer (the docker CLI must never block on it).
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, err := l.w.Write(q)
	return len(p), err
}

func truncateForLog(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

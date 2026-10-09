package service

import (
	"bufio"
	"errors"
	"io"
	"log"
	"os"
	"syscall"
	"time"

	"nginx-proxy-guard/internal/metrics"
)

// fileTail follows access_raw.log across logrotate's rename + create without
// losing the lines nginx still writes into the renamed file.
//
// nginx keeps its own descriptor. After logrotate renames the file and
// creates a new one, workers go on writing to the OLD inode until the
// postrotate USR1 makes them reopen, and their buffered lines (buffer=64k
// flush=5s) are flushed into the old inode at that moment - after a reader
// that switched at the first EOF has already left it. Measured against real
// nginx + logrotate with the production postrotate, the previous tail lost up
// to 1% of the lines around each rotation. So:
//  1. on an inode change at EOF, the new file is read from offset 0 and the
//     old one moves to "draining";
//  2. a draining inode is read until it has gained no bytes for
//     tailQuietWindow, then closed;
//  3. a partial line at EOF is kept and completed by the next read, never
//     dropped;
//  4. at most tailMaxDraining inodes drain at once; a burst of rotations
//     closes the oldest early instead of leaking descriptors;
//  5. one poll reads at most tailLinesPerPoll lines, so the caller's select
//     (stop, restart) stays responsive;
//  6. re-opening the inode already being read is a no-op (no duplicates);
//  7. truncation in place restarts from offset 0;
//  8. a line over tailMaxLine is dropped and counted, never buffered whole.
//
// Not safe for concurrent use: streamFileAccessLogs owns it.
type fileTail struct {
	path     string
	now      func() time.Time
	cur      *tailSource
	draining []*tailSource

	// Counters for tests; production reports them through metrics.
	drainedLines int
	droppedLong  int
}

const (
	// tailQuietWindow: a rotated inode is read until it has gained no bytes
	// for this long. It must stay at least twice the access_log flush
	// interval - flush=5s in 00-raw-logging.conf
	// (handler/system_settings_rawlog.go) and in the per-host access_log of
	// templates/proxy_host/base.conf.tmpl and cache.conf.tmpl - because the
	// last buffered lines reach the old inode up to one flush after the
	// reopen. TestTailQuietWindowCoversNginxFlush reads those files and
	// fails when the pairing breaks.
	tailQuietWindow = 10 * time.Second

	// tailMaxDraining bounds how many rotated inodes stay open at once.
	// Hourly rotation and a 10 s window mean one in practice.
	tailMaxDraining = 4

	// tailMaxLine: longer lines are dropped (counted) rather than buffered
	// without bound. nginx access lines are a few hundred bytes.
	tailMaxLine = 1 << 20

	// tailLinesPerPoll keeps one poll short.
	tailLinesPerPoll = 5000
)

type tailSource struct {
	f          *os.File
	r          *bufio.Reader
	ino        uint64
	off        int64 // bytes consumed by the line reader
	partial    []byte
	overlong   bool
	lastGrowth time.Time
	lateLines  int // lines read after the inode was rotated away
}

func newFileTail(path string, now func() time.Time) *fileTail {
	if now == nil {
		now = time.Now
	}
	return &fileTail{path: path, now: now}
}

// inodeOf returns the inode of path, or 0 when it cannot be read.
func inodeOf(path string) uint64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}

func (t *fileTail) openSource(seekEnd bool) (*tailSource, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	var off int64
	if seekEnd {
		if off, err = f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return nil, err
		}
	}
	var ino uint64
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		ino = s.Ino
	}
	return &tailSource{f: f, r: bufio.NewReaderSize(f, 64*1024), ino: ino, off: off, lastGrowth: t.now()}, nil
}

// open is the first open. seekEnd skips what is already in the file (it was
// ingested before this process started).
func (t *fileTail) open(seekEnd bool) error {
	s, err := t.openSource(seekEnd)
	if err != nil {
		return err
	}
	t.cur = s
	return nil
}

// reopen serves RestartTail: a new path (or a replaced file) becomes current
// and the old inode keeps draining. Re-resolving to the inode already being
// read does nothing - opening it a second time would read every later line
// twice.
func (t *fileTail) reopen(path string, seekEnd bool) error {
	t.path = path
	if t.cur != nil && inodeOf(path) == t.cur.ino {
		return nil
	}
	s, err := t.openSource(seekEnd)
	if err != nil {
		return err
	}
	t.retire(t.cur, nil)
	t.cur = s
	return nil
}

func (t *fileTail) retire(s *tailSource, emit func(string)) {
	if s == nil {
		return
	}
	s.lastGrowth = t.now()
	t.draining = append(t.draining, s)
	if len(t.draining) > tailMaxDraining {
		oldest := t.draining[0]
		log.Printf("[LogCollector] file-tail closed rotated inode %d early: more than %d rotations within %s", oldest.ino, tailMaxDraining, tailQuietWindow)
		t.closeSource(oldest, emit)
		t.draining = t.draining[1:]
	}
}

func (t *fileTail) closeSource(s *tailSource, emit func(string)) {
	if len(s.partial) > 0 && emit != nil && !s.overlong {
		emit(string(s.partial)) // a last line nginx never terminated; the parser decides
	}
	if s.lateLines > 0 {
		log.Printf("[LogCollector] file-tail read %d late lines from rotated inode %d", s.lateLines, s.ino)
	}
	s.f.Close()
}

func (t *fileTail) isDraining(ino uint64) bool {
	for _, d := range t.draining {
		if d.ino == ino {
			return true
		}
	}
	return false
}

// readLines emits complete lines; an unterminated tail is kept for the next
// call. It reports whether any byte was read.
func (t *fileTail) readLines(s *tailSource, emit func(string), budget *int) (grew bool) {
	for *budget > 0 {
		chunk, err := s.r.ReadSlice('\n')
		if len(chunk) > 0 {
			grew = true
			s.off += int64(len(chunk))
		}
		switch {
		case err == nil:
			line := chunk[:len(chunk)-1]
			if !s.overlong && len(s.partial)+len(line) > tailMaxLine {
				s.overlong = true
			}
			if len(s.partial) > 0 && !s.overlong {
				line = append(s.partial, line...)
			}
			if s.overlong {
				t.droppedLong++
				metrics.LogCollectorTailOverlongLinesTotal.Inc()
			} else {
				emit(string(line))
				*budget--
			}
			if cap(s.partial) > 64*1024 {
				s.partial = nil // do not pin the buffer of one huge line
			} else {
				s.partial = s.partial[:0]
			}
			s.overlong = false
		case errors.Is(err, bufio.ErrBufferFull) || errors.Is(err, io.EOF):
			if !s.overlong {
				if len(s.partial)+len(chunk) > tailMaxLine {
					s.overlong = true
					s.partial = s.partial[:0]
				} else {
					s.partial = append(s.partial, chunk...)
				}
			}
			if errors.Is(err, io.EOF) {
				return grew
			}
		default:
			return grew
		}
	}
	return grew
}

// poll reads what is available from the draining inodes and the current
// file, and switches to a newly created file at the path once the current
// one is at EOF. It returns false when nothing was read (the caller sleeps).
func (t *fileTail) poll(emit func(string)) bool {
	now := t.now()
	budget := tailLinesPerPoll
	progressed := false

	kept := t.draining[:0]
	for _, d := range t.draining {
		late := func(l string) {
			t.drainedLines++
			d.lateLines++
			metrics.LogCollectorTailRotatedLinesTotal.Inc()
			emit(l)
		}
		if t.readLines(d, late, &budget) {
			d.lastGrowth = now
			progressed = true
		}
		if now.Sub(d.lastGrowth) >= tailQuietWindow {
			t.closeSource(d, emit)
			continue
		}
		kept = append(kept, d)
	}
	t.draining = kept

	if t.cur == nil {
		if err := t.open(false); err != nil {
			return progressed
		}
	}
	if budget == 0 {
		return true // the draining inodes used this poll up
	}
	if t.readLines(t.cur, emit, &budget) {
		t.cur.lastGrowth = now
		return true
	}

	// The current file is at EOF. Look for a rotation now, even while an
	// older inode is still draining: one that keeps growing must not hold up
	// the switch to the newest file.
	ino := inodeOf(t.path)
	switch {
	case ino == 0:
		// renamed and not created again yet: keep reading the old descriptor
	case ino != t.cur.ino && !t.isDraining(ino):
		nf, err := t.openSource(false)
		if err != nil {
			return progressed
		}
		t.retire(t.cur, emit)
		t.cur = nf
		return true
	case ino == t.cur.ino:
		if st, err := t.cur.f.Stat(); err == nil && st.Size() < t.cur.off {
			// truncated in place: start over from 0
			if _, err := t.cur.f.Seek(0, io.SeekStart); err != nil {
				return progressed
			}
			t.cur.r.Reset(t.cur.f)
			t.cur.off = 0
			t.cur.partial = t.cur.partial[:0]
			t.cur.overlong = false
			return true
		}
	}
	return progressed
}

// close releases every descriptor; partial lines are dropped.
func (t *fileTail) close() {
	for _, d := range t.draining {
		d.f.Close()
	}
	t.draining = nil
	if t.cur != nil {
		t.cur.f.Close()
		t.cur = nil
	}
}

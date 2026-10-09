package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

// DiskGuard's view of the raw-log archive: the archiver's own cached
// measurement through ArchiveUsageSource, reported only while archiving is on
// and the archive has been measured, a stalled share as stalled, and never a
// filesystem call on the tick.

// archiveNAS is what the archive share answers to statfs: its own filesystem.
var archiveNAS = rawStatfs{FSID: "77", Type: 0x6969, Frsize: 4096, Blocks: 1 << 28, Bfree: 1 << 26, Bavail: 1 << 26, Files: 1 << 20}

// archiveProvider is a provider whose only local disk is the nginx log volume
// and whose database answers through exec, with the archiver wired in the way
// bootstrap wires it. Any statfs other than the log volume fails the test.
func archiveProvider(t *testing.T, a *RawLogArchiver) *HostUsageProvider {
	t.Helper()
	p := newDiskTestProvider(func(_ context.Context, path string) (rawStatfs, error) {
		if path != "/etc/nginx/logs" {
			t.Errorf("DiskGuard ran statfs on %s itself", path)
		}
		return diskTestExt4, nil
	}, func(context.Context, ...string) ([]byte, error) { return []byte(busyboxStatLine), nil }, time.Now)
	p.SetArchiveUsage(ArchiveUsageSource(a))
	return p
}

// measureArchive runs one tick's measurement, which must not wait on the
// archive, and returns the archive's filesystem and stall, if any.
func measureArchive(t *testing.T, p *HostUsageProvider) (*FSUsage, *StalledDisk) {
	t.Helper()
	type result struct {
		fss     []FSUsage
		stalled []StalledDisk
		err     error
	}
	done := make(chan result, 1)
	go func() {
		fss, stalled, err := p.Measure(context.Background())
		done <- result{fss, stalled, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the measurement waited on the archive")
	}
	if r.err != nil {
		t.Fatalf("measure: %v", r.err)
	}
	var fs *FSUsage
	for i := range r.fss {
		if r.fss[i].HasRole(DiskRoleArchive) {
			fs = &r.fss[i]
		} else if r.fss[i].roleCodes() != "db,nginx_logs" {
			t.Errorf("unexpected filesystem %q", r.fss[i].roleCodes())
		}
	}
	var st *StalledDisk
	for i := range r.stalled {
		if r.stalled[i].Role == DiskRoleArchive {
			st = &r.stalled[i]
		}
	}
	return fs, st
}

// measuredArchive is an archive that is initialised, enabled and measured by
// a pass.
func measuredArchive(t *testing.T) *archiverHarness {
	t.Helper()
	h := newArchiverHarness(t, true)
	h.a.statfs = func(context.Context, string) (rawStatfs, error) { return archiveNAS, nil }
	h.initialise()
	h.a.runPass(context.Background())
	return h
}

// hangArchive leaves one archive call stuck, as on a share that stopped
// answering, until the test ends. The archiver's own statfs then blocks as
// well, so any filesystem call the source made would hang the measurement.
func hangArchive(t *testing.T, h *archiverHarness) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.a.ioTimeout = 20 * time.Millisecond
	var stalled *ArchiveStalledError
	if err := h.a.fsCall(context.Background(), func() error { <-release; return nil }); !errors.As(err, &stalled) {
		t.Fatalf("hung call: %v", err)
	}
	h.a.statfs = func(ctx context.Context, _ string) (rawStatfs, error) {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return rawStatfs{}, errors.New("released")
	}
}

func TestArchiveUsageSourceReportsTheMeasuredArchive(t *testing.T) {
	h := measuredArchive(t)
	fs, st := measureArchive(t, archiveProvider(t, h.a))
	if fs == nil || st != nil {
		t.Fatalf("archive = %#v, stalled = %#v; want it measured", fs, st)
	}
	total, used, avail, _ := archiveNAS.usage()
	if fs.Key != string(DiskRoleArchive) || fs.Path != h.root || fs.Total != total || fs.Used != used || fs.Avail != avail {
		t.Fatalf("archive filesystem = %#v", fs)
	}
	if !fs.MeasuredAt.Equal(h.now) {
		t.Fatalf("measured at %v, want the archiver's own measurement at %v", fs.MeasuredAt, h.now)
	}
}

func TestArchiveUsageSourceReportsNothingWhenNotInUse(t *testing.T) {
	t.Run("no archiver", func(t *testing.T) {
		if u, ok := ArchiveUsageSource(nil)(); ok {
			t.Fatalf("a nil archiver reported %#v", u)
		}
		if fs, st := measureArchive(t, archiveProvider(t, nil)); fs != nil || st != nil {
			t.Fatalf("archive = %#v, stalled = %#v", fs, st)
		}
	})
	t.Run("before the first pass", func(t *testing.T) {
		h := newArchiverHarness(t, true)
		if fs, st := measureArchive(t, archiveProvider(t, h.a)); fs != nil || st != nil {
			t.Fatalf("archive = %#v, stalled = %#v", fs, st)
		}
	})
	t.Run("archiving switched off", func(t *testing.T) {
		h := measuredArchive(t)
		h.settings.RawLogArchiveEnabled = false
		h.a.runPass(context.Background())
		if fs, st := measureArchive(t, archiveProvider(t, h.a)); fs != nil || st != nil {
			t.Fatalf("archive = %#v, stalled = %#v", fs, st)
		}
	})
	t.Run("share unmounted", func(t *testing.T) {
		h := newArchiverHarness(t, false)
		h.a.runPass(context.Background())
		if fs, st := measureArchive(t, archiveProvider(t, h.a)); fs != nil || st != nil {
			t.Fatalf("archive = %#v, stalled = %#v", fs, st)
		}
	})
	t.Run("never measured", func(t *testing.T) {
		h := newArchiverHarness(t, true)
		h.a.statfs = func(context.Context, string) (rawStatfs, error) { return rawStatfs{}, errors.New("input/output error") }
		h.initialise()
		h.a.runPass(context.Background())
		if fs, st := measureArchive(t, archiveProvider(t, h.a)); fs != nil || st != nil {
			t.Fatalf("archive = %#v, stalled = %#v", fs, st)
		}
	})
}

func TestArchiveUsageSourceReportsAStalledArchive(t *testing.T) {
	t.Run("a call timed out", func(t *testing.T) {
		h := measuredArchive(t)
		hangArchive(t, h)
		fs, st := measureArchive(t, archiveProvider(t, h.a))
		if fs != nil || st == nil || st.Path != h.root || st.Since.IsZero() {
			t.Fatalf("archive = %#v, stalled = %#v; want it stalled", fs, st)
		}
	})
	t.Run("a pass probed a hung share", func(t *testing.T) {
		h := measuredArchive(t)
		hangArchive(t, h)
		h.a.runPass(context.Background()) // the probe fails at once and records the stall
		h.a.mu.Lock()
		h.a.ioStallSince = nil // only the recorded status says so now
		h.a.mu.Unlock()
		if fs, st := measureArchive(t, archiveProvider(t, h.a)); fs != nil || st == nil {
			t.Fatalf("archive = %#v, stalled = %#v; want it stalled", fs, st)
		}
	})
	t.Run("hung before it was ever measured", func(t *testing.T) {
		// A process that starts while the share is already hung: the marker
		// is there from an earlier run, but nothing here has measured it.
		h := newArchiverHarness(t, true)
		h.initialise()
		h.a.mu.Lock()
		h.a.statfsAt = time.Time{}
		h.a.mu.Unlock()
		hangArchive(t, h)
		h.a.runPass(context.Background())
		fs, st := measureArchive(t, archiveProvider(t, h.a))
		if fs != nil || st == nil || st.Path != h.root {
			t.Fatalf("archive = %#v, stalled = %#v; want it stalled", fs, st)
		}
	})
	t.Run("a move made no progress", func(t *testing.T) {
		// A copy blocked on a hung share holds the pass, and with it every
		// refresh, so the cached numbers stop moving; the stalled pass must
		// say so instead.
		h := measuredArchive(t)
		since := h.now.Add(-h.a.stallAfter - time.Minute)
		h.a.running.Store(true)
		h.a.mu.Lock()
		h.a.progressAt = since
		h.a.mu.Unlock()
		fs, st := measureArchive(t, archiveProvider(t, h.a))
		if fs != nil || st == nil || !st.Since.Equal(since) {
			t.Fatalf("archive = %#v, stalled = %#v; want it stalled since %v", fs, st, since)
		}
		// A pass that is moving along is not a stall.
		h.a.mu.Lock()
		h.a.progressAt = h.now.Add(-time.Second)
		h.a.mu.Unlock()
		if fs, st := measureArchive(t, archiveProvider(t, h.a)); fs == nil || st != nil {
			t.Fatalf("archive = %#v, stalled = %#v; want it measured", fs, st)
		}
	})
}

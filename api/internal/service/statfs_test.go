package service

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// A hung network mount blocks statfs(2) for as long as the server is gone.
// The guard must give up after its timeout, report the path as stalled, and
// not start a second call for the same path while the first is still stuck.
func TestStatfsGuardReportsAHungMountAsStalled(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	g := newStatfsGuard(func(path string) (rawStatfs, error) {
		calls.Add(1)
		if path == "/mnt/nas" {
			<-release // the NAS stopped answering
		}
		return rawStatfs{Frsize: 4096, Blocks: 100, Bfree: 50, Bavail: 40}, nil
	}, 50*time.Millisecond)
	ctx := context.Background()

	start := time.Now()
	_, err := g.stat(ctx, "/mnt/nas")
	s, stalled := asStatfsStalled(err)
	if !stalled || s.Path != "/mnt/nas" {
		t.Fatalf("want a stall, got %v", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("waited %v for a hung mount", waited)
	}

	// Still stuck: the next tick reports the stall at once, with the same
	// start time, and does not park a second goroutine on the mount.
	since := s.Since
	start = time.Now()
	_, err = g.stat(ctx, "/mnt/nas")
	if s2, ok := asStatfsStalled(err); !ok || !s2.Since.Equal(since) {
		t.Fatalf("second call: %v", err)
	}
	if time.Since(start) > 20*time.Millisecond || calls.Load() != 1 {
		t.Fatalf("a second statfs was started on a stuck mount (calls=%d)", calls.Load())
	}

	// Other paths are unaffected.
	if _, err := g.stat(ctx, "/etc/nginx/logs"); err != nil {
		t.Fatalf("a healthy path failed while another one hangs: %v", err)
	}

	// The mount answers again: the stuck call returns, and the path measures.
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := g.stat(ctx, "/mnt/nas"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the path never measured again after the mount answered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Two checks measuring the same path at the same moment (the minute tick and
// an emergency pass, or two requests for the log files page) share one
// statfs. The second used to be told the path was a hung mount at once,
// however young the first call was: a false "not answering" warning, and
// DiskGuard dropped the volume it measures the database disk through.
func TestStatfsGuardSharesAYoungCall(t *testing.T) {
	var calls atomic.Int32
	g := newStatfsGuard(func(string) (rawStatfs, error) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		return rawStatfs{FSID: "77", Frsize: 4096, Blocks: 100, Bfree: 50, Bavail: 40}, nil
	}, time.Second)
	errs := make(chan error, 2)
	go func() {
		_, err := g.stat(context.Background(), "/etc/nginx/logs")
		errs <- err
	}()
	time.Sleep(10 * time.Millisecond)
	raw, err := g.stat(context.Background(), "/etc/nginx/logs")
	if err != nil || raw.FSID != "77" {
		t.Fatalf("the second caller got %#v, %v; want the shared answer", raw, err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("the first caller: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("statfs ran %d times for two overlapping callers, want 1", n)
	}

	// A shared call that does not answer within the timeout is a stall for
	// every caller waiting on it, with its own start time.
	release := make(chan struct{})
	defer close(release)
	g = newStatfsGuard(func(string) (rawStatfs, error) { <-release; return rawStatfs{}, nil }, 60*time.Millisecond)
	go func() { _, _ = g.stat(context.Background(), "/mnt/nas") }()
	time.Sleep(10 * time.Millisecond)
	start := time.Now()
	_, err = g.stat(context.Background(), "/mnt/nas")
	if _, ok := asStatfsStalled(err); !ok {
		t.Fatalf("waiting on a hung call: %v", err)
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("the second caller waited %v, more than the first call's timeout", waited)
	}
}

func TestStatfsGuardPassesErrorsAndHonoursTheContext(t *testing.T) {
	boom := errors.New("no such file or directory")
	g := newStatfsGuard(func(string) (rawStatfs, error) { return rawStatfs{}, boom }, time.Second)
	if _, err := g.stat(context.Background(), "/x"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := asStatfsStalled(boom); ok {
		t.Fatal("an ordinary error must not read as a stall")
	}

	block := make(chan struct{})
	defer close(block)
	g = newStatfsGuard(func(string) (rawStatfs, error) { <-block; return rawStatfs{}, nil }, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.stat(ctx, "/y"); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled tick must not wait: %v", err)
	}
}

func TestStatfsUsageFollowsDf(t *testing.T) {
	// df: 1K-blocks 490048472, Used 245532840, Available 219549028, 53%.
	r := rawStatfs{Frsize: 1024, Blocks: 490048472, Bfree: 490048472 - 245532840, Bavail: 219549028}
	total, used, avail, pct := r.usage()
	if total != 490048472*1024 || used != 245532840*1024 || avail != 219549028*1024 {
		t.Fatalf("total=%d used=%d avail=%d", total, used, avail)
	}
	if pct < 52.7 || pct > 52.9 {
		t.Fatalf("pct = %.2f, df rounds it to 53", pct)
	}
	if _, _, _, pct := (rawStatfs{}).usage(); pct != 0 {
		t.Fatal("an empty result must not divide by zero")
	}
}

func TestFilesystemTypeNames(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the magic numbers are Linux's")
	}
	for magic, want := range map[int64]string{
		0xef53: "ext4", 0x58465342: "xfs", 0x9123683e: "btrfs", 0x2fc12fc1: "zfs",
		0x01021994: "tmpfs", overlayFSMagic: "overlay", 0x6969: "nfs",
		0xff534d42: "cifs", 0xfe534d42: "smb2", 0x65735546: "fuse",
	} {
		if got := (rawStatfs{Type: magic}).typeName(); got != want {
			t.Errorf("type %#x = %q, want %q", magic, got, want)
		}
	}
	if got := fsTypeName(0x12345678); got != "" {
		t.Errorf("an unknown magic must name nothing, got %q", got)
	}
}

// statfs on the root of this test process: a real syscall, a sane result,
// and an f_type the table usually knows.
func TestStatfsPathOnALiveFilesystem(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("statfs is Linux-only")
	}
	r, err := statfsPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	total, _, avail, pct := r.usage()
	if r.FSID == "" || total == 0 || avail > total || pct < 0 || pct > 100 {
		t.Fatalf("implausible statfs result %#v", r)
	}
	if _, err := statfsNearest(t.TempDir() + "/not/created/yet"); err != nil {
		t.Fatalf("a missing directory must be measured on its nearest existing parent: %v", err)
	}
}

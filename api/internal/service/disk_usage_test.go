package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The exact line BusyBox printed inside timescale/timescaledb:2.24.0-pg17 for a
// Docker volume on the dev box's ext4 root.
const busyboxStatLine = "6a24fcb0c35b83 4096 122512118 61128908 54887257 31195136 28172863 ef53\n"

// The statfs result Go gets for the same filesystem.
var diskTestExt4 = rawStatfs{FSID: "6a24fcb0c35b83", Type: 0xef53, Frsize: 4096, Blocks: 122512118, Bfree: 61128908, Bavail: 54887257, Files: 31195136}

func TestParseStatfsLine(t *testing.T) {
	raw, err := parseStatfsLine(busyboxStatLine)
	if err != nil {
		t.Fatal(err)
	}
	if raw.FSID != "6a24fcb0c35b83" || raw.Type != 0xef53 || raw.Frsize != 4096 {
		t.Fatalf("raw = %#v", raw)
	}
	_, _, _, pct := raw.usage()
	// df printed 53% for the same filesystem; used/(used+avail) = 52.79%.
	if pct < 52.7 || pct > 52.9 {
		t.Fatalf("pct = %.2f", pct)
	}
	for _, bad := range []string{"", "stat: can't read file system information", "zz 4096 1 1 1 1 1 ef53", "6a 0 1 1 1 1 1 ef53"} {
		if _, err := parseStatfsLine(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestParseDfP(t *testing.T) {
	out := "Filesystem           1024-blocks    Used Available Capacity Mounted on\n/dev/sda2            490048472 245532840 219549028  53% /etc/resolv.conf\n"
	raw, err := parseDfP(out)
	if err != nil {
		t.Fatal(err)
	}
	total, used, avail, pct := raw.usage()
	if total != 490048472*1024 || used != 245532840*1024 || avail != 219549028*1024 || pct < 52.7 || pct > 52.9 {
		t.Fatalf("total=%d used=%d avail=%d pct=%.2f", total, used, avail, pct)
	}
	if _, err := parseDfP("Filesystem 1024-blocks Used\n"); err == nil {
		t.Error("accepted a header-only df output")
	}
}

// Go's statfs and BusyBox's `stat -f -c %i` must agree, or the database disk is
// never recognised as the volume disk. The pair is from the same filesystem.
func TestFsidHexMatchesStat(t *testing.T) {
	if got := fsidHex(0x006a24fc, int32(-1329374333) /* 0xb0c35b83 */); got != "6a24fcb0c35b83" {
		t.Fatalf("fsidHex = %s", got)
	}
}

func diskMeas(role DiskRole, raw rawStatfs) diskMeasurement {
	return diskMeasurement{role: role, display: string(role), source: "statfs", raw: raw, at: time.Now()}
}

func TestGroupDiskMeasurementsDefaultInstall(t *testing.T) {
	overlay := diskTestExt4
	overlay.FSID, overlay.Type = "b7d3002f05929451", overlayFSMagic // what "/" reported in the same container
	got := groupDiskMeasurements([]diskMeasurement{
		diskMeas(DiskRoleDocker, overlay), diskMeas(DiskRoleNginxLogs, diskTestExt4), diskMeas(DiskRoleBackups, diskTestExt4), diskMeas(DiskRoleDB, diskTestExt4),
	})
	if len(got) != 1 {
		t.Fatalf("one disk became %d groups: %#v", len(got), got)
	}
	if got[0].Key != "db" || got[0].roleCodes() != "db,nginx_logs,backups,docker" {
		t.Fatalf("key=%s roles=%s", got[0].Key, got[0].roleCodes())
	}
}

func TestGroupDiskMeasurementsSeparateDatabaseDisk(t *testing.T) {
	osDisk := rawStatfs{FSID: "1", Type: 0xef53, Frsize: 4096, Blocks: 1000, Bfree: 500, Bavail: 450, Files: 64}
	dataDisk := rawStatfs{FSID: "2", Type: 0xef53, Frsize: 4096, Blocks: 9000, Bfree: 500, Bavail: 450, Files: 640}
	overlay := osDisk
	overlay.FSID, overlay.Type = "9", overlayFSMagic
	got := groupDiskMeasurements([]diskMeasurement{
		diskMeas(DiskRoleDocker, overlay), diskMeas(DiskRoleNginxLogs, osDisk), diskMeas(DiskRoleDB, dataDisk),
	})
	if len(got) != 2 {
		t.Fatalf("got %d groups", len(got))
	}
	if got[0].Key != "db" || got[1].Key != "nginx_logs" || got[1].roleCodes() != "nginx_logs,docker" {
		t.Fatalf("groups = %s/%s, %s/%s", got[0].Key, got[0].roleCodes(), got[1].Key, got[1].roleCodes())
	}
}

func TestDatabaseHost(t *testing.T) {
	cases := map[string]string{
		"postgres://postgres:pw@db:5432/npg?sslmode=disable": "db",
		"postgres://postgres:pw@npg-db:5432/nginx_guard":     "npg-db",
		"host=npg-db port=5432 user=postgres dbname=x":       "npg-db",
		"host=/var/run/postgresql user=postgres":             "/var/run/postgresql",
		"postgresql://u@[2001:db8::1]:5432/x":                "2001:db8::1",
	}
	for dsn, want := range cases {
		if got := databaseHost(dsn); got != want {
			t.Errorf("databaseHost(%q) = %q, want %q", dsn, got, want)
		}
	}
}

// diskFakeDocker answers the docker CLI calls dbLocator makes.
type diskFakeDocker struct {
	mu      sync.Mutex
	calls   []string
	running map[string]bool
	ps      string
	inspect string
}

func (f *diskFakeDocker) run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, strings.Join(args, " "))
	f.mu.Unlock()
	switch {
	case args[0] == "container" && strings.Contains(strings.Join(args, " "), "{{.State.Running}}"):
		if f.running[args[len(args)-1]] {
			return []byte("true\n"), nil
		}
		return nil, errors.New("No such container")
	case args[0] == "ps":
		return []byte(f.ps), nil
	case args[0] == "container":
		return []byte(f.inspect), nil
	}
	return nil, errors.New("unexpected")
}

func (f *diskFakeDocker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestDBLocator(t *testing.T) {
	ctx := context.Background()
	lookup := func(context.Context, string) ([]string, error) { return []string{"192.0.2.3"}, nil }

	// The release compose connects to the service alias "db".
	d := &diskFakeDocker{running: map[string]bool{}, ps: "aaa\nbbb\n", inspect: "/npg-valkey|192.0.2.2 \n/npg-db|192.0.2.3 \n"}
	l := &dbLocator{run: d.run, dbHost: "db", lookup: lookup}
	if name, reason := l.locate(ctx); name != "npg-db" {
		t.Fatalf("alias: got %q (%s)", name, reason)
	}

	// The dev compose connects to the container name directly.
	d = &diskFakeDocker{running: map[string]bool{"npg-db": true}}
	l = &dbLocator{run: d.run, dbHost: "npg-db", lookup: lookup}
	if name, _ := l.locate(ctx); name != "npg-db" {
		t.Fatalf("container name: got %q", name)
	}

	// An explicit override wins, and a wrong one is reported, not guessed past.
	l = &dbLocator{run: d.run, env: "custom-db", dbHost: "npg-db", lookup: lookup}
	if name, reason := l.locate(ctx); name != "" || reason != "db_container_not_found" {
		t.Fatalf("bad override: got %q (%s)", name, reason)
	}

	// A database no container here owns is external: nothing to watch.
	d = &diskFakeDocker{running: map[string]bool{}, ps: "aaa\n", inspect: "/other|192.0.2.9 \n"}
	l = &dbLocator{run: d.run, dbHost: "pg.example.com", lookup: lookup}
	if name, reason := l.locate(ctx); name != "" || reason != "db_external" {
		t.Fatalf("external: got %q (%s)", name, reason)
	}

	// Loopback and sockets cannot be mapped to a container.
	for _, h := range []string{"localhost", "127.0.0.1", "/var/run/postgresql", ""} {
		l = &dbLocator{run: d.run, dbHost: h, lookup: lookup}
		if name, reason := l.locate(ctx); name != "" || reason != "db_container_not_found" {
			t.Fatalf("host %q: got %q (%s)", h, name, reason)
		}
	}

	// A name that could be read as a flag is never passed to docker.
	l = &dbLocator{run: d.run, env: "--privileged", lookup: lookup}
	before := d.callCount()
	if name, _ := l.locate(ctx); name != "" || d.callCount() != before {
		t.Fatalf("flag-like name reached docker: %v", d.calls[before:])
	}
}

func TestValidDataDir(t *testing.T) {
	for _, ok := range []string{"/var/lib/postgresql/data", "/var/lib/postgresql/18/docker"} {
		if !validDataDir(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"", "data", "/var/lib/../etc", "/a\nb", "/a\x00b"} {
		if validDataDir(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

// newDiskTestProvider measures one local volume (nginx logs) with statfsFn and
// asks the "npg-db" container through execFn.
func newDiskTestProvider(statfsFn func(ctx context.Context, path string) (rawStatfs, error), execFn dockerRunner, now func() time.Time) *HostUsageProvider {
	return &HostUsageProvider{
		local:   []diskTarget{{Role: DiskRoleNginxLogs, Path: "/etc/nginx/logs"}},
		statfs:  statfsFn,
		locator: &dbLocator{run: (&diskFakeDocker{running: map[string]bool{"npg-db": true}}).run, dbHost: "npg-db"},
		run:     execFn,
		now:     now,
		dbEvery: dbMeasureEvery,
		warned:  map[string]bool{},
		stalled: map[string]bool{},
	}
}

func statfsReturns(raw rawStatfs) func(context.Context, string) (rawStatfs, error) {
	return func(context.Context, string) (rawStatfs, error) { return raw, nil }
}

// The database disk is measured through docker exec; when it shares a
// filesystem with a mounted volume the volume answers afterwards, without exec.
func TestProviderUsesAliasAfterVerifiedExec(t *testing.T) {
	var execs atomic.Int32
	p := newDiskTestProvider(statfsReturns(diskTestExt4), func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "exec" {
			execs.Add(1)
			return []byte(busyboxStatLine), nil
		}
		return nil, errors.New("unexpected")
	}, time.Now)
	for i := 0; i < 3; i++ {
		got, stalled, err := p.Measure(context.Background())
		if err != nil || len(got) != 1 || got[0].Key != "db" || len(stalled) != 0 {
			t.Fatalf("measure %d: %v %#v %v", i, err, got, stalled)
		}
	}
	// A forced measurement (the emergency compressor, DBFree) is answered by
	// the alias as well, and must not throw it away.
	for i := 0; i < 2; i++ {
		if fs, err := p.MeasureDB(context.Background()); err != nil || fs.Path != "npg-db:/var/lib/postgresql/data" {
			t.Fatalf("MeasureDB = %#v, %v", fs, err)
		}
	}
	if execs.Load() != 1 {
		t.Fatalf("docker exec ran %d times, want 1 (then the volume alias)", execs.Load())
	}
	if info := p.DatabaseInfo(); !info.Measured || info.Container != "npg-db" || info.DataDir != defaultPGDataDir {
		t.Fatalf("database info = %#v", info)
	}
}

// A database container that is restarting must not rename the shared disk,
// and the container is asked again every dbEvery until it answers.
func TestProviderKeepsAliasWhileExecFails(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	var execOK atomic.Bool
	execOK.Store(true)
	var execs atomic.Int32
	p := newDiskTestProvider(statfsReturns(diskTestExt4), func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "exec" {
			execs.Add(1)
			if execOK.Load() {
				return []byte(busyboxStatLine), nil
			}
		}
		return nil, errors.New("container is restarting")
	}, func() time.Time { return now })
	if got, _, _ := p.Measure(context.Background()); len(got) != 1 || got[0].Key != "db" {
		t.Fatalf("first measure: %#v", got)
	}
	execOK.Store(false)
	now = now.Add(3 * time.Hour) // alias expired, exec failing
	before := execs.Load()
	for i := 0; i < 10; i++ { // ten ticks, one minute apart
		got, _, err := p.Measure(context.Background())
		if err != nil || len(got) != 1 || got[0].Key != "db" {
			t.Fatalf("while exec fails the disk must stay \"db\": %#v %v", got, err)
		}
		now = now.Add(time.Minute)
	}
	// exec (stat, then the df fallback) was retried about every 5 minutes,
	// not every tick and not never.
	if tries := execs.Load() - before; tries < 2*2 || tries > 3*2 {
		t.Fatalf("exec attempts in 10 minutes = %d, want 2-3 tries", tries)
	}
	if info := p.DatabaseInfo(); !info.Measured || info.Reason != "db_exec_failed" {
		t.Fatalf("database info while the container is unreachable = %#v", info)
	}

	// The container is back: the next retry verifies it again.
	execOK.Store(true)
	now = now.Add(dbMeasureEvery)
	if got, _, _ := p.Measure(context.Background()); len(got) != 1 || got[0].Key != "db" {
		t.Fatalf("after recovery: %#v", got)
	}
	if info := p.DatabaseInfo(); !info.Measured || info.Reason != "" {
		t.Fatalf("database info after recovery = %#v", info)
	}
}

// Without a container to ask, the database disk is reported as not measured —
// never guessed from another disk — and the other disks are still watched.
func TestProviderReportsUnmeasuredDatabase(t *testing.T) {
	p := newDiskTestProvider(statfsReturns(diskTestExt4), func(context.Context, ...string) ([]byte, error) {
		return nil, errors.New("unexpected")
	}, time.Now)
	p.locator = &dbLocator{run: (&diskFakeDocker{running: map[string]bool{}}).run, env: "does-not-exist"}
	got, _, err := p.Measure(context.Background())
	if err != nil || len(got) != 1 || got[0].Key != "nginx_logs" || got[0].HasRole(DiskRoleDB) {
		t.Fatalf("got %#v, %v", got, err)
	}
	if info := p.DatabaseInfo(); info.Measured || info.Reason != "db_container_not_found" {
		t.Fatalf("database info = %#v", info)
	}
	if _, err := p.MeasureDB(context.Background()); err == nil {
		t.Fatal("MeasureDB must fail when the database disk cannot be measured")
	}
}

// A path whose statfs hangs is reported as stalled; the other disks are
// measured as usual.
func TestProviderReportsStalledPath(t *testing.T) {
	p := newDiskTestProvider(func(_ context.Context, path string) (rawStatfs, error) {
		if path == "/mnt/nas/backups" {
			return rawStatfs{}, &statfsStalledError{Path: path, Since: time.Unix(1, 0)}
		}
		return diskTestExt4, nil
	}, func(_ context.Context, args ...string) ([]byte, error) { return []byte(busyboxStatLine), nil }, time.Now)
	p.local = append(p.local, diskTarget{Role: DiskRoleBackups, Path: "/mnt/nas/backups"})
	got, stalled, err := p.Measure(context.Background())
	if err != nil || len(got) != 1 || got[0].roleCodes() != "db,nginx_logs" {
		t.Fatalf("got %#v, %v", got, err)
	}
	if len(stalled) != 1 || stalled[0].Role != DiskRoleBackups || stalled[0].Path != "/mnt/nas/backups" {
		t.Fatalf("stalled = %#v", stalled)
	}
}

// The archive comes from the archiver's own (timed-out, cached) measurement,
// never from a statfs of the share by DiskGuard.
func TestProviderTakesArchiveUsageFromTheArchiver(t *testing.T) {
	var archivePathMeasured atomic.Bool
	p := newDiskTestProvider(func(_ context.Context, path string) (rawStatfs, error) {
		if path == "/archive" {
			archivePathMeasured.Store(true)
		}
		return diskTestExt4, nil
	}, func(_ context.Context, args ...string) ([]byte, error) { return []byte(busyboxStatLine), nil }, time.Now)
	nas := rawStatfs{FSID: "77", Type: 0x6969, Frsize: 4096, Blocks: 1 << 30, Bfree: 1 << 29, Bavail: 1 << 29, Files: 1 << 20}
	usage := ArchiveDiskUsage{Path: "/archive", Stat: nas, MeasuredAt: time.Now()}
	p.SetArchiveUsage(func() (ArchiveDiskUsage, bool) { return usage, true })

	got, stalled, err := p.Measure(context.Background())
	if err != nil || len(got) != 2 || len(stalled) != 0 {
		t.Fatalf("got %#v %v %v", got, stalled, err)
	}
	var keys []string
	for _, fs := range got {
		keys = append(keys, fs.Key)
	}
	if strings.Join(keys, ",") != "db,archive" && strings.Join(keys, ",") != "archive,db" {
		t.Fatalf("keys = %v", keys)
	}
	if archivePathMeasured.Load() {
		t.Fatal("DiskGuard ran statfs on the archive share itself")
	}

	usage.StalledSince = time.Now()
	got, stalled, _ = p.Measure(context.Background())
	if len(got) != 1 || len(stalled) != 1 || stalled[0].Role != DiskRoleArchive {
		t.Fatalf("a stalled archive: got %#v, stalled %#v", got, stalled)
	}
}

// DiskGuard's tick (Measure) and an emergency pass or the raw_log reclaim job
// (MeasureDB) run on different goroutines; run with -race.
func TestProviderConcurrentMeasure(t *testing.T) {
	p := newDiskTestProvider(statfsReturns(diskTestExt4), func(_ context.Context, args ...string) ([]byte, error) {
		return []byte(busyboxStatLine), nil
	}, time.Now)
	p.dbEvery = time.Nanosecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _ = p.MeasureDB(context.Background())
		}
	}()
	for i := 0; i < 200; i++ {
		_, _, _ = p.Measure(context.Background())
		_ = p.DatabaseInfo()
		p.SetUrgent(i%2 == 0)
	}
	<-done
}

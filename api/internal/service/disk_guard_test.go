package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// fakeDiskUsage returns a scripted used percentage per filesystem key.
type fakeDiskUsage struct {
	pct     map[string]float64 // key -> percent for the next Measure
	roles   map[string][]DiskRole
	stalled []StalledDisk
	urgent  bool
	dbErr   error
}

const diskTestTotal = uint64(200 << 30)

func (f *fakeDiskUsage) fs(key string, p float64) FSUsage {
	used := uint64(float64(diskTestTotal) * p / 100)
	roles := f.roles[key]
	if roles == nil {
		roles = []DiskRole{DiskRole(key)}
	}
	return FSUsage{Key: key, Roles: roles, Path: "npg-db:/var/lib/postgresql/data",
		Total: diskTestTotal, Used: used, Avail: diskTestTotal - used, UsedPercent: p, MeasuredAt: time.Now()}
}

func (f *fakeDiskUsage) Measure(context.Context) ([]FSUsage, []StalledDisk, error) {
	var out []FSUsage
	for key, p := range f.pct {
		out = append(out, f.fs(key, p))
	}
	return out, f.stalled, nil
}

func (f *fakeDiskUsage) MeasureDB(context.Context) (*FSUsage, error) {
	if f.dbErr != nil {
		return nil, f.dbErr
	}
	fs := f.fs("db", f.pct["db"])
	return &fs, nil
}
func (f *fakeDiskUsage) SetUrgent(v bool) { f.urgent = v }
func (f *fakeDiskUsage) DatabaseInfo() model.DatabaseDiskInfo {
	return model.DatabaseDiskInfo{Measured: true, Container: "npg-db", DataDir: "/var/lib/postgresql/data"}
}

type diskClock struct{ t time.Time }

func (c *diskClock) now() time.Time          { return c.t }
func (c *diskClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestDiskGuard(t *testing.T, events ...string) (*DiskGuard, *fakeDiskUsage, *fakeStore, *diskClock) {
	t.Helper()
	if len(events) == 0 {
		events = []string{eventDiskLow, eventDiskCritical, eventDiskRecovered}
	}
	store := newFakeStore(events...)
	notify := NewNotificationServiceWithStore(store)
	usage := &fakeDiskUsage{pct: map[string]float64{}, roles: map[string][]DiskRole{"db": {DiskRoleDB, DiskRoleNginxLogs}}}
	c := &diskClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	g := NewDiskGuard(usage, notify, store, nil, DiskGuardOptions{
		Thresholds: DefaultDiskThresholds, ConfirmSamples: 2, Cooldown: 6 * time.Hour, Now: c.now,
	})
	return g, usage, store, c
}

func diskTickAt(g *DiskGuard, u *fakeDiskUsage, c *diskClock, pct float64) {
	u.pct["db"] = pct
	g.Tick(context.Background())
	c.advance(time.Minute)
}

func diskEvents(store *fakeStore) []string {
	var out []string
	for _, m := range store.enqueued {
		out = append(out, m.Event+"/"+m.Severity)
	}
	return out
}

func TestNextDiskLevelHysteresis(t *testing.T) {
	th := DefaultDiskThresholds
	cases := []struct {
		prev DiskLevel
		pct  float64
		want DiskLevel
	}{
		{DiskLevelOK, 84.9, DiskLevelOK},
		{DiskLevelOK, 85, DiskLevelLow},
		{DiskLevelOK, 95, DiskLevelCritical},
		{DiskLevelLow, 80, DiskLevelLow},
		{DiskLevelLow, 79.9, DiskLevelOK},
		{DiskLevelLow, 90, DiskLevelCritical},
		{DiskLevelCritical, 85, DiskLevelCritical},
		{DiskLevelCritical, 84.9, DiskLevelLow},
		{DiskLevelCritical, 79.9, DiskLevelOK},
	}
	for _, c := range cases {
		if got := nextDiskLevel(c.prev, c.pct, th); got != c.want {
			t.Errorf("nextDiskLevel(%s, %.1f) = %s, want %s", c.prev, c.pct, got, c.want)
		}
	}
}

func TestDiskThresholdsValid(t *testing.T) {
	for _, bad := range []DiskThresholds{{80, 90, 85}, {85, 85, 80}, {85, 100, 80}, {85, 90, 0}, {85, 90, 90}} {
		if bad.Valid() {
			t.Errorf("%+v accepted", bad)
		}
	}
	if !DefaultDiskThresholds.Valid() || !(DiskThresholds{Warn: 40, Critical: 50, Recover: 30}).Valid() {
		t.Error("valid thresholds rejected")
	}
}

// One sample over the line is a spike (a backup tarball being written), not
// an alert.
func TestDiskGuardWaitsForConfirmation(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	diskTickAt(g, u, c, 86)
	if len(store.enqueued) != 0 {
		t.Fatalf("alerted on the first sample: %v", diskEvents(store))
	}
	diskTickAt(g, u, c, 70)
	diskTickAt(g, u, c, 86)
	if len(store.enqueued) != 0 {
		t.Fatalf("two non-consecutive samples alerted: %v", diskEvents(store))
	}
	diskTickAt(g, u, c, 86)
	if got := diskEvents(store); len(got) != 1 || got[0] != "disk.space_low/warning" {
		t.Fatalf("got %v, want one disk.space_low/warning", got)
	}
	if !u.urgent {
		t.Error("a disk past the warning line must make the provider measure the database every tick")
	}
}

// The full life of a filling disk: one message per state an operator cares
// about, nothing while it hovers inside a band, one recovery.
func TestDiskGuardLifecycle(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	for _, p := range []float64{70, 86, 86, 88, 91, 91, 89, 86, 84, 82, 81, 79, 79, 70} {
		diskTickAt(g, u, c, p)
	}
	got := strings.Join(diskEvents(store), " ")
	want := "disk.space_low/warning disk.space_critical/error disk.space_recovered/resolved"
	if got != want {
		t.Fatalf("messages = %q\nwant      %q", got, want)
	}
	crit := store.enqueued[1]
	for _, k := range []string{"detail", "free", "roles", "subject"} {
		if crit.Fields[k] == "" {
			t.Errorf("critical message lacks %s: %#v", k, crit.Fields)
		}
	}
	if crit.Fields["roles"] != "db,nginx_logs" || crit.Fields["subject"] != "npg-db:/var/lib/postgresql/data" {
		t.Errorf("critical message fields = %#v", crit.Fields)
	}
	if u.urgent {
		t.Error("urgent stayed on after the disk recovered")
	}
}

func TestDiskGuardDirectJumpAnnouncesBoth(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	diskTickAt(g, u, c, 70)
	diskTickAt(g, u, c, 95)
	diskTickAt(g, u, c, 95)
	if got := strings.Join(diskEvents(store), " "); got != "disk.space_low/warning disk.space_critical/error" {
		t.Fatalf("got %q", got)
	}
}

// A restart must neither re-announce an open alert nor forget it: at 83% an
// install that was "low" before the restart is still low.
func TestDiskGuardRestoresLevelAfterRestart(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	store.state[eventDiskLow+"|db"] = stateFailing // as the previous process left it
	diskTickAt(g, u, c, 83)
	diskTickAt(g, u, c, 83)
	if len(store.enqueued) != 0 {
		t.Fatalf("restart re-announced or recovered early: %v", diskEvents(store))
	}
	diskTickAt(g, u, c, 79)
	diskTickAt(g, u, c, 79)
	if got := diskEvents(store); len(got) != 1 || got[0] != "disk.space_recovered/resolved" {
		t.Fatalf("got %v, want one recovery", got)
	}
}

// After a recovery a disk that refills quickly is held for the cooldown — but
// only a warning; critical always goes out.
func TestDiskGuardCooldownHoldsLowNotCritical(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	for _, p := range []float64{86, 86, 79, 79} {
		diskTickAt(g, u, c, p)
	}
	before := len(store.enqueued) // low + recovered
	diskTickAt(g, u, c, 86)
	diskTickAt(g, u, c, 86)
	if len(store.enqueued) != before {
		t.Fatalf("low re-announced inside the cooldown: %v", diskEvents(store))
	}
	c.advance(7 * time.Hour)
	diskTickAt(g, u, c, 86)
	if got := diskEvents(store); got[len(got)-1] != "disk.space_low/warning" {
		t.Fatalf("low not announced after the cooldown: %v", got)
	}

	g2, u2, store2, c2 := newTestDiskGuard(t)
	for _, p := range []float64{86, 86, 79, 79, 92, 92} {
		diskTickAt(g2, u2, c2, p)
	}
	if got := diskEvents(store2); got[len(got)-1] != "disk.space_critical/error" {
		t.Fatalf("critical was held by the cooldown: %v", got)
	}
}

// A disk on a network mount that stopped answering is not measured, but its
// open alert must not be closed as if the disk had gone away.
func TestDiskGuardStalledDiskKeepsItsAlert(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	u.roles["backups"] = []DiskRole{DiskRoleBackups}
	u.pct["backups"] = 95
	for i := 0; i < 2; i++ {
		diskTickAt(g, u, c, 50)
	}
	if got := strings.Join(diskEvents(store), " "); got != "disk.space_low/warning disk.space_critical/error" {
		t.Fatalf("got %q", got)
	}
	delete(u.pct, "backups")
	u.stalled = []StalledDisk{{Role: DiskRoleBackups, Path: "/mnt/nas/backups", Since: c.now()}}
	for i := 0; i < 30; i++ {
		diskTickAt(g, u, c, 50)
	}
	if s, _ := store.GetState(context.Background(), eventDiskLow, "backups"); s != stateFailing {
		t.Fatalf("a stalled disk's alert was closed (state %q)", s)
	}
	st := g.Status(context.Background())
	if len(st.Stalled) != 1 || st.Stalled[0].Role != "backups" || st.Stalled[0].Path != "/mnt/nas/backups" {
		t.Fatalf("stalled = %#v", st.Stalled)
	}

	// A disk that is really gone (not stalled) is closed quietly after ten
	// minutes: no recovery message for a recovery that did not happen.
	u.stalled = nil
	sent := len(store.enqueued)
	for i := 0; i < 12; i++ {
		diskTickAt(g, u, c, 50)
	}
	if s, _ := store.GetState(context.Background(), eventDiskLow, "backups"); s != stateOK {
		t.Fatalf("a vanished disk's alert stayed open (state %q)", s)
	}
	if len(store.enqueued) != sent {
		t.Fatalf("closing a vanished disk's alert sent %v", diskEvents(store)[sent:])
	}
}

// Growth compares with the same disk a day ago, from system_health.
type fakeDiskHistory struct {
	used  uint64
	paths []string
}

func (f *fakeDiskHistory) DiskUsedNear(_ context.Context, path string, _ uint64, at time.Time, _ time.Duration) (uint64, time.Time, bool, error) {
	f.paths = append(f.paths, path)
	return f.used, at, true, nil
}

func TestDiskGuardGrowthAndDaysToFull(t *testing.T) {
	store := newFakeStore(eventDiskLow)
	u := &fakeDiskUsage{pct: map[string]float64{"db": 86}, roles: map[string][]DiskRole{"db": {DiskRoleDB}}}
	c := &diskClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	used := uint64(float64(diskTestTotal) * 0.86)
	g := NewDiskGuard(u, NewNotificationServiceWithStore(store), store, &fakeDiskHistory{used: used - 2<<30},
		DiskGuardOptions{ConfirmSamples: 1, Now: c.now})
	g.Tick(context.Background())
	if len(store.enqueued) != 1 {
		t.Fatalf("got %d messages", len(store.enqueued))
	}
	f := store.enqueued[0].Fields
	if f["growth_per_day"] != "+2.0 GB" {
		t.Errorf("growth_per_day = %q", f["growth_per_day"])
	}
	// 28 GB free at 2 GB/day.
	if f["days_to_full"] != "14" {
		t.Errorf("days_to_full = %q", f["days_to_full"])
	}
	st := g.Status(context.Background())
	if st == nil || st.Level != "low" || st.Filesystems[0].DaysToFull == nil {
		t.Fatalf("status = %#v", st)
	}
}

// system_health holds the primary disk's history only. Another disk must not
// be matched against it — by size it could borrow the wrong disk's numbers.
func TestDiskGuardGrowthHistoryIsThePrimaryDisksOnly(t *testing.T) {
	store := newFakeStore()
	u := &fakeDiskUsage{pct: map[string]float64{"db": 50, "backups": 60},
		roles: map[string][]DiskRole{"db": {DiskRoleDB}, "backups": {DiskRoleBackups}}}
	h := &fakeDiskHistory{used: 1 << 30}
	c := &diskClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	g := NewDiskGuard(u, NewNotificationServiceWithStore(store), store, h, DiskGuardOptions{Now: c.now})
	g.Tick(context.Background())
	st := g.Status(context.Background())
	for _, fs := range st.Filesystems {
		if fs.Key == "backups" && fs.GrowthPerDayBytes != nil {
			t.Errorf("backups got a growth figure from the database disk's history")
		}
		if fs.Key == "db" && fs.GrowthPerDayBytes == nil {
			t.Errorf("the primary disk has no growth figure")
		}
	}
	if len(h.paths) != 1 {
		t.Fatalf("system_health was consulted for %d disks, want 1", len(h.paths))
	}
}

// The probe the raw_log reclaim job (C6) uses.
func TestDiskGuardDatabaseProbe(t *testing.T) {
	g, u, _, c := newTestDiskGuard(t)
	if g.DBCritical() {
		t.Fatal("critical before any measurement")
	}
	// DBFree measures now rather than reading the last tick.
	u.pct["db"] = 50
	if free, ok := g.DBFree(context.Background()); !ok || free != diskTestTotal/2 {
		t.Fatalf("DBFree = %d, %v", free, ok)
	}
	diskTickAt(g, u, c, 93)
	if g.DBCritical() {
		t.Fatal("critical after one sample; it must be confirmed like the alert")
	}
	diskTickAt(g, u, c, 93)
	if !g.DBCritical() {
		t.Fatal("not critical after two samples at 93%")
	}
	u.dbErr = errors.New("database container unreachable")
	if _, ok := g.DBFree(context.Background()); ok {
		t.Fatal("DBFree must say so when the database disk cannot be measured")
	}

	// Only the database's disk counts.
	u.roles["db"] = []DiskRole{DiskRoleNginxLogs}
	diskTickAt(g, u, c, 95)
	if g.DBCritical() {
		t.Fatal("a full disk without the database made DBCritical true")
	}

	var nilGuard *DiskGuard
	if _, ok := nilGuard.DBFree(context.Background()); ok || nilGuard.DBCritical() {
		t.Fatal("a nil guard (disabled) must report nothing")
	}
}

// /health/detailed is readable by any session or any-scope token: its view
// must carry no container name, data directory or path.
func TestDiskGuardHealthViewHasNoPathsOrContainers(t *testing.T) {
	g, u, _, c := newTestDiskGuard(t)
	u.stalled = []StalledDisk{{Role: DiskRoleBackups, Path: "/mnt/nas/backups", Since: c.now()}}
	diskTickAt(g, u, c, 86)
	full, err := json.Marshal(g.Status(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), "npg-db") {
		t.Fatalf("the dashboard view lost the path: %s", full)
	}
	reduced, err := json.Marshal(g.Status(context.Background()).Health())
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"npg-db", "/var/lib/postgresql", "/mnt/nas", `"path"`, `"container"`, `"data_dir"`, `"source"`} {
		if strings.Contains(string(reduced), leak) {
			t.Errorf("the /health/detailed view contains %s: %s", leak, reduced)
		}
	}
	for _, keep := range []string{`"level"`, `"used_percent"`, `"avail_bytes"`, `"measured":true`, `"stalled_roles":["backups"]`} {
		if !strings.Contains(string(reduced), keep) {
			t.Errorf("the /health/detailed view lacks %s: %s", keep, reduced)
		}
	}
	var nilStatus *model.StorageStatus
	if nilStatus.Health() != nil {
		t.Error("no status must stay no status")
	}
}

func TestDiskGuardPrimaryIsTheDatabaseDisk(t *testing.T) {
	g, u, _, c := newTestDiskGuard(t)
	if _, ok := g.Primary(); ok {
		t.Fatal("a primary disk before the first measurement")
	}
	u.roles["docker"] = []DiskRole{DiskRoleDocker}
	u.pct["docker"] = 95
	diskTickAt(g, u, c, 40)
	fs, ok := g.Primary()
	if !ok || fs.Key != "db" {
		t.Fatalf("primary = %#v", fs)
	}
	pct, _, _, path, ok := primaryDiskUsage(g)
	if !ok || pct != 40 || path != "npg-db:/var/lib/postgresql/data" {
		t.Fatalf("primaryDiskUsage = %.1f %q %v", pct, path, ok)
	}
	// Without DiskGuard the Disk figure is this container's "/", as before.
	if _, _, _, path, ok := primaryDiskUsage(nil); ok && path != "/" {
		t.Fatalf("fallback path = %q", path)
	}
	// Without a measured database it is Docker's "/" as well, whichever role
	// names the shared filesystem.
	delete(u.pct, "db")
	delete(u.pct, "docker")
	u.roles["nginx_logs"] = []DiskRole{DiskRoleNginxLogs, DiskRoleDocker}
	u.pct["nginx_logs"] = 61
	g.Tick(context.Background())
	if pct, _, _, path, ok := primaryDiskUsage(g); !ok || path != "/" || pct != 61 {
		t.Fatalf("without the database: %.1f %q %v", pct, path, ok)
	}
}

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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
	// fixedAt, when set, is reported as every sample's measurement time:
	// the provider handing back one cached measurement.
	fixedAt time.Time
}

const diskTestTotal = uint64(200 << 30)

func (f *fakeDiskUsage) fs(key string, p float64) FSUsage {
	used := uint64(float64(diskTestTotal) * p / 100)
	roles := f.roles[key]
	if roles == nil {
		roles = []DiskRole{DiskRole(key)}
	}
	at := time.Now()
	if !f.fixedAt.IsZero() {
		at = f.fixedAt
	}
	return FSUsage{Key: key, Roles: roles, Path: "npg-db:/var/lib/postgresql/data",
		Total: diskTestTotal, Used: used, Avail: diskTestTotal - used, UsedPercent: p, MeasuredAt: at}
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

// failingNotifier fails like a database that cannot write, then recovers.
type failingNotifier struct {
	err   error
	calls int
	sent  []string
}

func (f *failingNotifier) EmitTransition(_ context.Context, key, _ string, failing bool, _ string, _ map[string]string) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, fmt.Sprintf("%s/%v", key, failing))
	return nil
}
func (f *failingNotifier) ResolveQuietly(context.Context, string, string) error { return nil }

// With the database on the full disk, recording the alert fails every tick.
// That is logged once, retried every tick, and goes out once it can.
func TestDiskGuardLogsAFailingAlertOnceAndRetries(t *testing.T) {
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prev); log.SetFlags(flags) }()

	n := &failingNotifier{err: errors.New("failed to write notification state: pq: could not extend file: No space left on device (53100)")}
	u := &fakeDiskUsage{pct: map[string]float64{"db": 95}, roles: map[string][]DiskRole{"db": {DiskRoleDB}}}
	c := &diskClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	g := NewDiskGuard(u, n, nil, nil, DiskGuardOptions{ConfirmSamples: 1, Now: c.now})
	for i := 0; i < 5; i++ {
		g.Tick(context.Background())
		c.advance(time.Minute)
	}
	if got := strings.Count(buf.String(), "could not record"); got != 2 { // low and critical, once each
		t.Fatalf("logged %d times:\n%s", got, buf.String())
	}
	if n.calls < 10 {
		t.Fatalf("the alert was retried %d times in 5 ticks, want every tick", n.calls)
	}
	n.err = nil
	g.Tick(context.Background())
	if strings.Join(n.sent, " ") != "disk.space_low/true disk.space_critical/true" {
		t.Fatalf("after the database recovered: %v", n.sent)
	}
}

// Without a volume on the same disk, the database disk is measured through
// docker exec every few minutes and the provider hands back the last result in
// between. One cached sample must not confirm itself, and a pending change
// must ask for a fresh measurement.
func TestDiskGuardSameSampleDoesNotConfirmItself(t *testing.T) {
	g, u, store, c := newTestDiskGuard(t)
	u.fixedAt = time.Date(2026, 10, 9, 11, 58, 0, 0, time.UTC)
	diskTickAt(g, u, c, 86)
	if !u.urgent {
		t.Fatal("a pending level change must ask for a fresh database measurement")
	}
	diskTickAt(g, u, c, 86)
	if len(store.enqueued) != 0 {
		t.Fatalf("one cached sample confirmed itself: %v", diskEvents(store))
	}
	u.fixedAt = u.fixedAt.Add(2 * time.Minute) // a fresh exec
	diskTickAt(g, u, c, 86)
	if got := diskEvents(store); len(got) != 1 || got[0] != "disk.space_low/warning" {
		t.Fatalf("got %v, want one disk.space_low/warning", got)
	}
}

// flakyStateReader fails the first reads, as a database that is busy (or down)
// right after the API starts.
type flakyStateReader struct {
	fails int
	store *fakeStore
}

func (f *flakyStateReader) GetState(ctx context.Context, key, subject string) (string, error) {
	if f.fails > 0 {
		f.fails--
		return "", errors.New("database is starting up")
	}
	return f.store.GetState(ctx, key, subject)
}

// An alert left open by the previous process (the disk recovered while the
// API was down) must be read before anything is announced, even when the
// first read fails; otherwise it is never closed, and the next episode on that
// disk is swallowed because the state already says "failing".
func TestDiskGuardRetriesAFailedStateRead(t *testing.T) {
	store := newFakeStore(eventDiskLow, eventDiskCritical, eventDiskRecovered)
	store.state[eventDiskLow+"|db"] = stateFailing
	u := &fakeDiskUsage{pct: map[string]float64{"db": 70}, roles: map[string][]DiskRole{"db": {DiskRoleDB}}}
	c := &diskClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	g := NewDiskGuard(u, NewNotificationServiceWithStore(store), &flakyStateReader{fails: 2, store: store}, nil,
		DiskGuardOptions{ConfirmSamples: 2, Now: c.now})
	for i := 0; i < 4; i++ {
		diskTickAt(g, u, c, 70)
	}
	if got := diskEvents(store); len(got) != 1 || got[0] != "disk.space_recovered/resolved" {
		t.Fatalf("got %v, want the stale alert closed with one recovery", got)
	}
	if s, _ := store.GetState(context.Background(), eventDiskLow, "db"); s != stateOK {
		t.Fatalf("state = %q", s)
	}
}

func TestDiskPathFitsTheColumn(t *testing.T) {
	long := "npg-db:/" + strings.Repeat("데이터/", 120) + "pgdata"
	got := fitDiskPath(long)
	if n := len([]rune(got)); n != maxDiskPathRunes || !strings.HasSuffix(got, "pgdata") || !strings.HasPrefix(got, "…") {
		t.Fatalf("fitDiskPath = %d runes %q", n, got)
	}
	if fitDiskPath("npg-db:/var/lib/postgresql/data") != "npg-db:/var/lib/postgresql/data" {
		t.Fatal("a normal path must pass through")
	}
}

// downStore is the notification store of a database that cannot be reached
// while down is set: every query fails, as while npg-db is crash-looping or
// still recovering after a full disk.
type downStore struct {
	*fakeStore
	down bool
}

var errDBDown = errors.New("dial unix /var/run/postgresql/.s.PGSQL.5432: connect: connection refused")

func (d *downStore) TablesExist(ctx context.Context) (bool, error) {
	if d.down {
		return false, fmt.Errorf("failed to check the notification tables: %w", errDBDown)
	}
	return d.fakeStore.TablesExist(ctx)
}

func (d *downStore) GetState(ctx context.Context, key, subject string) (string, error) {
	if d.down {
		return "", errDBDown
	}
	return d.fakeStore.GetState(ctx, key, subject)
}

func (d *downStore) SetState(ctx context.Context, key, subject, label, state, detail string) error {
	if d.down {
		return errDBDown
	}
	return d.fakeStore.SetState(ctx, key, subject, label, state, detail)
}

func newDownStoreGuard(t *testing.T) (*DiskGuard, *fakeDiskUsage, *downStore, *diskClock) {
	t.Helper()
	store := newFakeStore(eventDiskLow, eventDiskCritical, eventDiskRecovered)
	db := &downStore{fakeStore: store}
	u := &fakeDiskUsage{pct: map[string]float64{}, roles: map[string][]DiskRole{"db": {DiskRoleDB}}}
	c := &diskClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	g := NewDiskGuard(u, NewNotificationServiceWithStore(db), db, nil,
		DiskGuardOptions{ConfirmSamples: 2, Cooldown: 6 * time.Hour, Now: c.now})
	return g, u, db, c
}

// A level change confirmed at a tick when the database cannot be reached is
// not lost. The notification check used to read "cannot reach the database"
// as "no notification tables" and report success, so the guard believed the
// alert was recorded and never tried again: the alert never went out, the
// recorded state kept saying "failing" after a recovery, and the next episode
// on that disk was swallowed because nothing seemed to change.
func TestDiskGuardRetriesAnAlertTheDatabaseCouldNotRecord(t *testing.T) {
	g, u, db, c := newDownStoreGuard(t)
	tick := func(pct float64, down bool) {
		db.down = down
		diskTickAt(g, u, c, pct)
	}
	tick(70, false)
	tick(92, false)
	tick(92, true) // confirms "critical" while the database is down
	if len(db.enqueued) != 0 {
		t.Fatalf("sent while the database was down: %v", diskEvents(db.fakeStore))
	}
	tick(92, false)
	want := []string{"disk.space_low/warning", "disk.space_critical/error"}
	if got := diskEvents(db.fakeStore); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("once the database is back: %v, want %v", got, want)
	}

	// Space freed while npg-db is still recovering: the recovery is
	// confirmed while it is down and goes out once it answers.
	tick(70, false)
	tick(70, true)
	tick(70, true)
	tick(70, false)
	want = append(want, "disk.space_recovered/resolved")
	if got := diskEvents(db.fakeStore); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("recovery: %v, want %v", got, want)
	}
	for _, ev := range []string{eventDiskLow, eventDiskCritical} {
		if s, _ := db.fakeStore.GetState(context.Background(), ev, "db"); s != stateOK {
			t.Fatalf("%s is still %q after the recovery", ev, s)
		}
	}

	// The next episode is announced again.
	c.advance(7 * time.Hour)
	for _, p := range []float64{87, 87, 92, 92} {
		tick(p, false)
	}
	want = append(want, "disk.space_low/warning", "disk.space_critical/error")
	if got := diskEvents(db.fakeStore); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("next episode: %v, want %v", got, want)
	}
}

// A filesystem that is no longer measured has its open alert closed quietly,
// and is forgotten only once that is recorded: with the database down at that
// moment the alert stayed "failing" for good.
func TestDiskGuardClosesAVanishedDisksAlertOnceItCan(t *testing.T) {
	g, u, db, c := newDownStoreGuard(t)
	u.roles["backups"] = []DiskRole{DiskRoleBackups}
	u.pct["backups"] = 95
	diskTickAt(g, u, c, 50)
	diskTickAt(g, u, c, 50)
	if got := strings.Join(diskEvents(db.fakeStore), " "); got != "disk.space_low/warning disk.space_critical/error" {
		t.Fatalf("got %q", got)
	}
	delete(u.pct, "backups")
	db.down = true
	for i := 0; i < 15; i++ {
		diskTickAt(g, u, c, 50)
	}
	db.down = false
	diskTickAt(g, u, c, 50)
	for _, ev := range []string{eventDiskLow, eventDiskCritical} {
		if s, _ := db.fakeStore.GetState(context.Background(), ev, "backups"); s != stateOK {
			t.Fatalf("%s of the vanished disk is still %q", ev, s)
		}
	}
	if len(db.enqueued) != 2 {
		t.Fatalf("closing a vanished disk's alert sent %v", diskEvents(db.fakeStore)[2:])
	}
}

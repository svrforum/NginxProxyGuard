package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"

	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
)

// DiskGuard watches the filesystems NPG writes to (D1), tells the operator
// when one is filling (D2), compresses closed log chunks early when the
// database disk passes the critical line (D3), and feeds the dashboard (D4).
//
// Why the lines sit at 85% and 90% rather than 99%: an alert travels through
// notification_outbox, which is a database table. On 2026-10-09 production
// reached 100%, Postgres could not even write postmaster.pid, and from then on
// nothing NPG does — alerting included — could commit. A warning has to fire
// while the database can still write it down.

// DiskLevel is a filesystem's alert level.
type DiskLevel int

const (
	DiskLevelOK DiskLevel = iota
	DiskLevelLow
	DiskLevelCritical
)

func (l DiskLevel) String() string {
	switch l {
	case DiskLevelLow:
		return "low"
	case DiskLevelCritical:
		return "critical"
	default:
		return "ok"
	}
}

const (
	eventDiskLow       = "disk.space_low"
	eventDiskCritical  = "disk.space_critical"
	eventDiskRecovered = "disk.space_recovered"
)

// DiskThresholds are used-space percentages, df style.
type DiskThresholds struct {
	Warn     float64
	Critical float64
	Recover  float64
}

// DefaultDiskThresholds are the shipped lines.
var DefaultDiskThresholds = DiskThresholds{Warn: 85, Critical: 90, Recover: 80}

func (t DiskThresholds) Valid() bool {
	return t.Recover > 0 && t.Recover < t.Warn && t.Warn < t.Critical && t.Critical < 100
}

// nextDiskLevel applies hysteresis. Escalation happens at the line itself;
// de-escalation needs a drop below a LOWER line: critical holds until usage is
// under Warn, low holds until it is under Recover. A disk hovering at 85.0% ±
// a few MB would otherwise alert and recover every minute.
func nextDiskLevel(prev DiskLevel, pct float64, t DiskThresholds) DiskLevel {
	switch {
	case pct >= t.Critical:
		return DiskLevelCritical
	case prev == DiskLevelCritical && pct >= t.Warn:
		return DiskLevelCritical
	case pct >= t.Warn:
		return DiskLevelLow
	case prev >= DiskLevelLow && pct >= t.Recover:
		return DiskLevelLow
	default:
		return DiskLevelOK
	}
}

// ── collaborators (interfaces so the rules are testable without a disk) ────

type diskUsageProvider interface {
	Measure(ctx context.Context) ([]FSUsage, []StalledDisk, error)
	MeasureDB(ctx context.Context) (*FSUsage, error)
	SetUrgent(bool)
	DatabaseInfo() model.DatabaseDiskInfo
}

type diskNotifier interface {
	EmitTransition(ctx context.Context, eventKey, subject string, failing bool, detail string, fields map[string]string) error
	ResolveQuietly(ctx context.Context, eventKey, subject string) error
}

// diskStateReader restores the hysteresis level and the low-alert cooldown
// after a restart, and re-reads the recorded state after a failed alert.
type diskStateReader interface {
	StateSince(ctx context.Context, eventKey, subject string) (state string, since time.Time, err error)
}

// diskHistory answers "how full was this disk a day ago" from system_health,
// so a growth estimate survives an API restart.
type diskHistory interface {
	DiskUsedNear(ctx context.Context, path string, total uint64, at time.Time, tol time.Duration) (used uint64, recordedAt time.Time, ok bool, err error)
}

// emergencyRunner is the emergency compressor (D3) as the guard drives it.
type emergencyRunner interface {
	Plan(ctx context.Context, fs FSUsage) EmergencyPlan
	TriggerAsync(fs FSUsage)
	Status() model.EmergencyCompressionStatus
}

// fsState is the per-filesystem memory of the guard. Only the tick goroutine
// reads or writes its fields.
type fsState struct {
	loaded       bool
	level        DiskLevel
	pending      DiskLevel
	pendingCount int
	// lastSampleAt is when the last counted sample was taken. A provider may
	// hand back the same measurement twice (the database disk is measured
	// through docker exec every few minutes, not every tick); the same
	// sample must not confirm itself.
	lastSampleAt time.Time
	// announcedLow / announcedCritical mirror notification_state, so the
	// guard calls EmitTransition only on a change instead of every minute.
	announcedLow      bool
	announcedCritical bool
	// resync is set when recording an alert failed: what notification_state
	// holds is read again before the next announcement, so the copy above
	// cannot drift from it.
	resync       bool
	recoveredAt  time.Time
	missingSince time.Time
}

type usageSample struct {
	at   time.Time
	used uint64
}

type growthEstimate struct {
	at    time.Time
	bytes int64
	ok    bool
}

// DiskGuardOptions are the knobs bootstrap reads from the environment.
type DiskGuardOptions struct {
	Thresholds     DiskThresholds
	ConfirmSamples int           // consecutive samples before a level changes
	Cooldown       time.Duration // hold a new "low" this long after a recovery
	Now            func() time.Time
}

type DiskGuard struct {
	usage   diskUsageProvider
	notify  diskNotifier
	state   diskStateReader
	history diskHistory
	emerg   emergencyRunner // nil until SetEmergencyCompressor
	opts    DiskGuardOptions

	mu         sync.RWMutex
	fs         map[string]*fsState
	last       []FSUsage
	stalled    []StalledDisk
	lastAt     time.Time
	primaryKey string
	ring       map[string][]usageSample
	growth     map[string]growthEstimate

	// Tick goroutine only.
	metricKeys map[string]bool
	lastErr    string
	emitErrs   map[string]string // event|key -> the alert error last logged
}

func NewDiskGuard(usage diskUsageProvider, notify diskNotifier, state diskStateReader, history diskHistory, opts DiskGuardOptions) *DiskGuard {
	if !opts.Thresholds.Valid() {
		opts.Thresholds = DefaultDiskThresholds
	}
	if opts.ConfirmSamples < 1 {
		opts.ConfirmSamples = 2
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &DiskGuard{
		usage: usage, notify: notify, state: state, history: history, opts: opts,
		fs: map[string]*fsState{}, ring: map[string][]usageSample{}, growth: map[string]growthEstimate{},
		metricKeys: map[string]bool{}, emitErrs: map[string]string{},
	}
}

// SetEmergencyCompressor wires D3. Call before the scheduler starts.
func (g *DiskGuard) SetEmergencyCompressor(e *EmergencyCompressor) {
	if e == nil {
		g.emerg = nil
		return
	}
	g.emerg = e
}

// Tick measures, updates levels, announces changes and starts an emergency
// compression when the database disk is critical. Called every minute by
// DiskGuardScheduler, from one goroutine.
func (g *DiskGuard) Tick(ctx context.Context) {
	now := g.opts.Now()
	measured, stalled, err := g.usage.Measure(ctx)
	g.mu.Lock()
	g.stalled = stalled
	g.mu.Unlock()
	if err != nil || len(measured) == 0 {
		g.logMeasureFailure(err)
		return
	}
	g.lastErr = ""

	// A stalled disk is not measured, but it has not gone away either: its
	// open alert stays open until it answers.
	present := map[string]bool{}
	for _, s := range stalled {
		present[string(s.Role)] = true
	}
	g.mu.Lock()
	g.primaryKey = primaryDiskKey(measured)
	g.mu.Unlock()

	urgent := false
	for i := range measured {
		fs := &measured[i]
		present[fs.Key] = true
		st := g.stateFor(ctx, fs.Key)
		st.missingSince = time.Time{}
		prev := st.level
		g.advance(st, fs.UsedPercent, fs.MeasuredAt)
		fs.Level = st.level
		g.record(fs.Key, now, fs.Used)
		if st.level != prev {
			g.logTransition(*fs, prev, st.level)
		}
		// Nothing is announced until the alert state is known; it is read
		// again next tick.
		if st.loaded && !st.resync {
			g.announce(ctx, *fs, st, now)
		}
		// Past the warning line, or a level change waiting for its
		// confirming sample: measure the database disk afresh next tick.
		if st.level >= DiskLevelLow || st.pendingCount > 0 {
			urgent = true
		}
		// Compressing the database only frees space on the database's disk.
		// The sample itself must still support "critical" (with the usual
		// hysteresis): right after a restart the level is the one restored
		// from notification_state, which can be stale until it is confirmed.
		if st.level == DiskLevelCritical && fs.HasRole(DiskRoleDB) && g.emerg != nil &&
			nextDiskLevel(DiskLevelCritical, fs.UsedPercent, g.opts.Thresholds) == DiskLevelCritical {
			g.emerg.TriggerAsync(*fs)
		}
	}
	g.usage.SetUrgent(urgent)
	g.forgetVanished(ctx, present, now)
	g.exportMetrics(measured)

	g.mu.Lock()
	g.last, g.lastAt = measured, now
	g.mu.Unlock()
}

// logMeasureFailure logs a failed measurement once per distinct error, not
// once a minute.
func (g *DiskGuard) logMeasureFailure(err error) {
	msg := "no filesystem could be measured"
	if err != nil {
		msg = err.Error()
	}
	if msg == g.lastErr {
		return
	}
	g.lastErr = msg
	log.Printf("[DiskGuard] measurement failed: %s", msg)
}

// primaryDiskKey is the filesystem NPG's single Disk figure describes: the
// database's when it is measured, else Docker's "/".
func primaryDiskKey(fss []FSUsage) string {
	for _, want := range []DiskRole{DiskRoleDB, DiskRoleDocker} {
		for _, fs := range fss {
			if fs.HasRole(want) {
				return fs.Key
			}
		}
	}
	return ""
}

// stateFor loads a filesystem's alert state from notification_state the first
// time it is seen, so a restart neither re-announces nor forgets an open
// alert, nor forgets the low-alert cooldown of a recent recovery. A read that
// fails (the database is busy, or down because it is the full disk) is
// retried next tick; until then the level is still tracked but nothing is
// announced, because an open alert that was never read could not be closed.
//
// After an alert could not be recorded (resync), the state is read again the
// same way, but only the announced flags are taken from it: the level stays
// what the samples confirmed.
func (g *DiskGuard) stateFor(ctx context.Context, key string) *fsState {
	g.mu.Lock()
	st := g.fs[key]
	if st == nil {
		st = &fsState{}
		g.fs[key] = st
	}
	g.mu.Unlock()
	if st.loaded && !st.resync {
		return st
	}
	if g.state == nil {
		st.loaded, st.resync = true, false
		return st
	}
	crit, _, errCrit := g.state.StateSince(ctx, eventDiskCritical, key)
	low, lowSince, errLow := g.state.StateSince(ctx, eventDiskLow, key)
	if errCrit != nil || errLow != nil {
		return st
	}
	st.announcedCritical = crit == stateFailing
	st.announcedLow = low == stateFailing
	if st.resync {
		st.resync = false
		return st
	}
	st.loaded = true
	// A recovery is recorded as disk.space_low turning "ok"; its since is
	// when. The cooldown that holds a new warning counts from there, across
	// a restart too.
	if low == stateOK {
		st.recoveredAt = lowSince
	}
	restored := DiskLevelOK
	switch {
	case st.announcedCritical:
		restored = DiskLevelCritical
	case st.announcedLow:
		restored = DiskLevelLow
	}
	// The higher of what was announced and what has been measured since: the
	// samples then take it from there, with the usual confirmation.
	if restored > st.level {
		st.level = restored
	}
	st.pending, st.pendingCount = st.level, 0
	return st
}

// advance moves the level only after ConfirmSamples consecutive samples agree,
// so a momentary spike — a backup tarball written and moved — is not an alert.
// A sample taken at the same moment as the last one is the same sample and is
// not counted again.
func (g *DiskGuard) advance(st *fsState, pct float64, at time.Time) {
	if !at.IsZero() {
		if at.Equal(st.lastSampleAt) {
			return
		}
		st.lastSampleAt = at
	}
	cand := nextDiskLevel(st.level, pct, g.opts.Thresholds)
	if cand == st.level {
		st.pending, st.pendingCount = st.level, 0
		return
	}
	if cand == st.pending {
		st.pendingCount++
	} else {
		st.pending, st.pendingCount = cand, 1
	}
	if st.pendingCount >= g.opts.ConfirmSamples {
		st.level, st.pendingCount = cand, 0
	}
}

// announce turns the level into notification state. Low is announced before
// critical so a direct jump reads as an escalation in the channel. Critical is
// never held back; a new "low" within Cooldown of a recovery is.
func (g *DiskGuard) announce(ctx context.Context, fs FSUsage, st *fsState, now time.Time) {
	wantLow := st.level >= DiskLevelLow
	wantCrit := st.level == DiskLevelCritical
	if wantLow == st.announcedLow && wantCrit == st.announcedCritical {
		return
	}
	fields := g.fields(ctx, fs, now)

	if wantLow != st.announcedLow {
		held := wantLow && !st.recoveredAt.IsZero() && now.Sub(st.recoveredAt) < g.opts.Cooldown && !wantCrit
		if !held {
			if err := g.notify.EmitTransition(ctx, eventDiskLow, fs.Key, wantLow, fields["detail"], fields); err != nil {
				g.logEmitFailure(eventDiskLow, fs, err)
				st.resync = true
			} else {
				delete(g.emitErrs, eventDiskLow+"|"+fs.Key)
				if !wantLow {
					st.recoveredAt = now
				}
				st.announcedLow = wantLow
			}
		}
	}
	if wantCrit != st.announcedCritical {
		// The first message says whether NPG can win space back or the
		// operator has to act. The pass itself starts right after, off the
		// tick.
		if wantCrit && g.emerg != nil && fs.HasRole(DiskRoleDB) {
			fields["action"] = g.emerg.Plan(ctx, fs).Action
		}
		if err := g.notify.EmitTransition(ctx, eventDiskCritical, fs.Key, wantCrit, fields["detail"], fields); err != nil {
			g.logEmitFailure(eventDiskCritical, fs, err)
			st.resync = true
		} else {
			delete(g.emitErrs, eventDiskCritical+"|"+fs.Key)
			st.announcedCritical = wantCrit
		}
	}
}

// logEmitFailure logs a failed alert once per distinct error. When the full
// disk is the database's, recording the alert fails the same way every tick
// until the database can write again; the next tick re-reads the recorded
// state and retries regardless.
func (g *DiskGuard) logEmitFailure(event string, fs FSUsage, err error) {
	k, msg := event+"|"+fs.Key, err.Error()
	if g.emitErrs[k] == msg {
		return
	}
	g.emitErrs[k] = msg
	log.Printf("[DiskGuard] could not record the %s alert for %s (retrying every check): %v", event, fs.Path, err)
}

// fields is the message. Values are language-neutral (sizes, a path, codes);
// the formatter translates roles and action per channel.
func (g *DiskGuard) fields(ctx context.Context, fs FSUsage, now time.Time) map[string]string {
	f := map[string]string{
		"subject": fs.Path,
		"detail":  fmt.Sprintf("%.1f%% · %s / %s", fs.UsedPercent, formatBytes(int64(fs.Used)), formatBytes(int64(fs.Total))),
		"free":    formatBytes(int64(fs.Avail)),
		"roles":   fs.roleCodes(),
	}
	if gr, ok := g.growthPerDay(ctx, fs, now); ok {
		f["growth_per_day"] = signedBytes(gr)
		if days, ok := daysToFull(fs.Avail, gr); ok {
			f["days_to_full"] = days
		}
	}
	return f
}

func signedBytes(n int64) string {
	if n < 0 {
		return "-" + formatBytes(-n)
	}
	return "+" + formatBytes(n)
}

func daysToFull(avail uint64, perDay int64) (string, bool) {
	if perDay <= 0 {
		return "", false
	}
	d := float64(avail) / float64(perDay)
	switch {
	case d < 1:
		return "<1", true
	case d > 999:
		return "", false
	default:
		return fmt.Sprintf("%.0f", math.Round(d)), true
	}
}

// growthPerDay compares with the same disk a day ago. A day, not an hour:
// usage is a sawtooth — the uncompressed chunk grows all day and shrinks ~10x
// when the policy compresses it, raw logs drop at the midnight rotation — and
// only a full cycle cancels that out.
//
// Only the primary filesystem has history in system_health (written every
// 30 s, kept 24-48 h), so only it is looked up there: matching another disk
// against the primary's rows by size could borrow the wrong disk's history.
// Every filesystem also has an in-memory ring, which answers once the API has
// run for a day.
func (g *DiskGuard) growthPerDay(ctx context.Context, fs FSUsage, now time.Time) (int64, bool) {
	g.mu.RLock()
	cached, hit := g.growth[fs.Key]
	primary := g.primaryKey
	g.mu.RUnlock()
	if hit && now.Sub(cached.at) < 10*time.Minute {
		return cached.bytes, cached.ok
	}
	est := growthEstimate{at: now}
	target := now.Add(-24 * time.Hour)
	if g.history != nil && fs.Key == primary {
		if used, at, ok, err := g.history.DiskUsedNear(ctx, fs.Path, fs.Total, target, time.Hour); err == nil && ok {
			if span := now.Sub(at); span >= 20*time.Hour {
				est.bytes = int64(float64(int64(fs.Used)-int64(used)) * float64(24*time.Hour) / float64(span))
				est.ok = true
			}
		}
	}
	if !est.ok {
		g.mu.RLock()
		samples := g.ring[fs.Key]
		g.mu.RUnlock()
		for _, s := range samples {
			if d := s.at.Sub(target); d > -time.Hour && d < time.Hour {
				span := now.Sub(s.at)
				est.bytes = int64(float64(int64(fs.Used)-int64(s.used)) * float64(24*time.Hour) / float64(span))
				est.ok = true
				break
			}
		}
	}
	g.mu.Lock()
	g.growth[fs.Key] = est
	g.mu.Unlock()
	return est.bytes, est.ok
}

// record keeps one sample per 10 minutes for 26 hours.
func (g *DiskGuard) record(key string, now time.Time, used uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.ring[key]
	if n := len(r); n > 0 && now.Sub(r[n-1].at) < 10*time.Minute {
		return
	}
	r = append(r, usageSample{at: now, used: used})
	cut := 0
	for cut < len(r) && now.Sub(r[cut].at) > 26*time.Hour {
		cut++
	}
	g.ring[key] = r[cut:]
}

// forgetVanished clears an open alert for a filesystem that is no longer
// measured (the database moved to another disk) after ten minutes, quietly:
// announcing a recovery that did not happen would be worse than silence.
func (g *DiskGuard) forgetVanished(ctx context.Context, present map[string]bool, now time.Time) {
	g.mu.Lock()
	var gone []string
	for key, st := range g.fs {
		if present[key] {
			continue
		}
		if st.missingSince.IsZero() {
			st.missingSince = now
			continue
		}
		if now.Sub(st.missingSince) >= 10*time.Minute && (st.announcedLow || st.announcedCritical) {
			gone = append(gone, key)
		}
	}
	g.mu.Unlock()
	for _, key := range gone {
		// Forgotten only once both are recorded: an alert left "failing"
		// would stay in the digest, and swallow the next episode if the
		// filesystem comes back.
		errLow := g.notify.ResolveQuietly(ctx, eventDiskLow, key)
		errCrit := g.notify.ResolveQuietly(ctx, eventDiskCritical, key)
		if err := errors.Join(errLow, errCrit); err != nil {
			g.logEmitFailure("closing of the", FSUsage{Key: key, Path: key}, err)
			continue
		}
		delete(g.emitErrs, "closing of the|"+key)
		g.mu.Lock()
		delete(g.fs, key)
		g.mu.Unlock()
		log.Printf("[DiskGuard] %s is no longer measured; its open disk alert was closed without a message", key)
	}
}

func (g *DiskGuard) logTransition(fs FSUsage, from, to DiskLevel) {
	log.Printf("[DiskGuard] %s (%s) %s -> %s: %.1f%% used, %s free of %s",
		fs.Path, fs.roleCodes(), from, to, fs.UsedPercent, formatBytes(int64(fs.Avail)), formatBytes(int64(fs.Total)))
}

// exportMetrics sets npg_disk_used_ratio and npg_disk_level per filesystem and
// drops the series of one that is no longer measured, so a scrape never shows
// a number nobody measured.
func (g *DiskGuard) exportMetrics(measured []FSUsage) {
	seen := map[string]bool{}
	for _, fs := range measured {
		seen[fs.Key] = true
		metrics.DiskUsedRatio.WithLabelValues(fs.Key).Set(fs.UsedPercent / 100)
		metrics.DiskLevel.WithLabelValues(fs.Key).Set(float64(fs.Level))
	}
	for key := range g.metricKeys {
		if !seen[key] {
			metrics.DiskUsedRatio.DeleteLabelValues(key)
			metrics.DiskLevel.DeleteLabelValues(key)
		}
	}
	g.metricKeys = seen
}

// Status is the snapshot GET /dashboard serves (and, reduced by Health, GET
// /health/detailed). nil until the first tick.
func (g *DiskGuard) Status(ctx context.Context) *model.StorageStatus {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	last, at := append([]FSUsage(nil), g.last...), g.lastAt
	stalled := append([]StalledDisk(nil), g.stalled...)
	g.mu.RUnlock()
	if at.IsZero() {
		return nil
	}
	out := &model.StorageStatus{
		Level: DiskLevelOK.String(),
		Thresholds: model.StorageThresholds{WarnPercent: g.opts.Thresholds.Warn,
			CriticalPercent: g.opts.Thresholds.Critical, RecoverPercent: g.opts.Thresholds.Recover},
		Filesystems: make([]model.FilesystemUsage, 0, len(last)),
		Database:    g.usage.DatabaseInfo(),
		MeasuredAt:  at,
	}
	worst := DiskLevelOK
	for _, fs := range last {
		roles := make([]string, len(fs.Roles))
		for i, r := range fs.Roles {
			roles[i] = string(r)
		}
		u := model.FilesystemUsage{
			Key: fs.Key, Roles: roles, Path: fs.Path, Source: fs.Source,
			TotalBytes: fs.Total, UsedBytes: fs.Used, AvailBytes: fs.Avail,
			UsedPercent: math.Round(fs.UsedPercent*10) / 10, Level: fs.Level.String(), MeasuredAt: fs.MeasuredAt,
		}
		if gr, ok := g.growthPerDay(ctx, fs, at); ok {
			v := gr
			u.GrowthPerDayBytes = &v
			if gr > 0 {
				d := float64(fs.Avail) / float64(gr)
				u.DaysToFull = &d
			}
		}
		if fs.Level > worst {
			worst = fs.Level
		}
		out.Filesystems = append(out.Filesystems, u)
	}
	sort.SliceStable(out.Filesystems, func(i, j int) bool {
		return out.Filesystems[i].UsedPercent > out.Filesystems[j].UsedPercent
	})
	for _, s := range stalled {
		out.Stalled = append(out.Stalled, model.StalledFilesystem{Role: string(s.Role), Path: s.Path, Since: s.Since})
	}
	out.Level = worst.String()
	if g.emerg != nil {
		em := g.emerg.Status()
		out.Emergency = &em
	}
	return out
}

// Primary is the filesystem the dashboard's Disk tile, system_health and the
// digest report: the database's when it is measured, else Docker's "/".
func (g *DiskGuard) Primary() (FSUsage, bool) {
	if g == nil {
		return FSUsage{}, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	key := primaryDiskKey(g.last)
	for _, fs := range g.last {
		if fs.Key == key {
			return fs, true
		}
	}
	return FSUsage{}, false
}

// DBFree and DBCritical are the database-disk probe the raw_log reclaim job
// (C6, RawLogReclaimService) consumes through its SetDiskProbe: DBFree before
// each chunk for its free-space precheck, DBCritical to pause while the
// database disk is critical, which is the emergency compression's turn.

// DBFree measures the database's filesystem now — through the volume verified
// to share it, or docker exec — and returns the bytes a non-root writer such
// as Postgres can still use. ok is false when the database disk cannot be
// measured; a caller that needs room must then not proceed.
func (g *DiskGuard) DBFree(ctx context.Context) (avail uint64, ok bool) {
	if g == nil || g.usage == nil {
		return 0, false
	}
	fs, err := g.usage.MeasureDB(ctx)
	if err != nil || fs == nil {
		return 0, false
	}
	return fs.Avail, true
}

// DBCritical reports whether the filesystem holding the database is at the
// critical level, as of the last tick (confirmed over ConfirmSamples ticks,
// with the same hysteresis as the alerts). false when it is not measured.
func (g *DiskGuard) DBCritical() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, fs := range g.last {
		if fs.HasRole(DiskRoleDB) {
			return fs.Level == DiskLevelCritical
		}
	}
	return false
}

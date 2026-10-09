package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
)

// HostUsageProvider measures every filesystem NPG writes to (D1). See
// disk_usage.go for what is measured where and why.

const (
	// dbMeasureEvery is how often the database disk is measured through
	// docker exec when nothing is urgent and no verified alias answers, and
	// how long a failed exec is left alone before it is tried again.
	dbMeasureEvery = 5 * time.Minute
	// dbAliasTTL bounds how long a local path that shares the database's
	// filesystem stands in for a docker exec before exec re-verifies it, in
	// case the database volume moved.
	dbAliasTTL = time.Hour
	// dbLocateTTL bounds how long a located container name is trusted.
	dbLocateTTL = time.Hour
	// dbStaleAfter keeps the last good database measurement through a
	// transient exec failure, so the filesystem does not "vanish" for a tick.
	dbStaleAfter = 15 * time.Minute
)

// StalledDisk is a role whose filesystem did not answer statfs in time — in
// practice a network mount whose server stopped answering. It has no numbers;
// it is reported so the operator can see that this disk is not being watched.
type StalledDisk struct {
	Role  DiskRole
	Path  string
	Since time.Time
}

// ArchiveDiskUsage is the raw-log archive's filesystem as the archiver (B6)
// last measured it. DiskGuard never measures the archive itself: the archive
// is typically a NAS share, statfs on a hung NAS blocks uninterruptibly, and
// the archiver already measures it under its own timeout and single slot.
type ArchiveDiskUsage struct {
	// Path is where the archive is mounted in the API container, e.g. /archive.
	Path string
	// Stat is the archiver's last statfsPath result for Path.
	Stat       rawStatfs
	MeasuredAt time.Time
	// StalledSince is non-zero while the archiver's filesystem calls time out.
	StalledSince time.Time
}

// HostUsageProvider is safe for concurrent use: DiskGuard's tick calls Measure
// while an emergency compression pass or the raw_log reclaim job calls
// MeasureDB.
type HostUsageProvider struct {
	local     []diskTarget
	statfs    func(ctx context.Context, path string) (rawStatfs, error)
	locator   *dbLocator
	dataDirFn func(ctx context.Context) (string, error)
	run       dockerRunner
	now       func() time.Time
	dbEvery   time.Duration

	mu            sync.Mutex
	archiveFn     func() (ArchiveDiskUsage, bool)
	urgent        bool
	dbName        string
	dbDataDir     string
	locatedAt     time.Time
	dbLast        *diskMeasurement
	dbInfo        model.DatabaseDiskInfo
	alias         string    // local path verified to be on the database's filesystem
	aliasVerified time.Time // when an exec last confirmed it
	lastExec      time.Time // last attempt to ask the database container
	execFailing   bool      // that attempt failed
	warned        map[string]bool
	stalled       map[string]bool // local paths currently stalled, for one log line each way
}

// NewHostUsageProvider wires the real statfs (under a timeout) and the docker
// CLI. dataDirFn reads the database's data_directory; it may fail, in which
// case the image default is used.
func NewHostUsageProvider(nginxLogsDir, backupPath, envDBContainer, databaseURL string,
	dataDirFn func(ctx context.Context) (string, error)) *HostUsageProvider {
	guard := newStatfsGuard(statfsNearest, statfsTimeout)
	return &HostUsageProvider{
		local: []diskTarget{
			{Role: DiskRoleNginxLogs, Path: nginxLogsDir},
			{Role: DiskRoleBackups, Path: backupPath},
			{Role: DiskRoleDocker, Path: "/"},
		},
		statfs: guard.stat,
		locator: &dbLocator{run: runDockerCLI, env: envDBContainer, dbHost: databaseHost(databaseURL),
			lookup: net.DefaultResolver.LookupHost},
		dataDirFn: dataDirFn,
		run:       runDockerCLI,
		now:       time.Now,
		dbEvery:   dbMeasureEvery,
		warned:    map[string]bool{},
		stalled:   map[string]bool{},
	}
}

// SetArchiveUsage wires the raw-log archive (B6). fn must return at once —
// the archiver's cached result, never a fresh statfs of the share — and
// ok=false when no archive is configured or mounted. ArchiveUsageSource is
// that fn for a RawLogArchiver.
func (p *HostUsageProvider) SetArchiveUsage(fn func() (ArchiveDiskUsage, bool)) {
	p.mu.Lock()
	p.archiveFn = fn
	p.mu.Unlock()
}

// SetUrgent makes every tick re-measure the database disk. DiskGuard turns it
// on while any filesystem is at or above the warning line.
func (p *HostUsageProvider) SetUrgent(v bool) {
	p.mu.Lock()
	p.urgent = v
	p.mu.Unlock()
}

// DatabaseInfo reports whether the database disk is being measured.
func (p *HostUsageProvider) DatabaseInfo() model.DatabaseDiskInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dbInfo
}

// Measure returns every filesystem that answered, grouped, and the roles whose
// filesystem did not answer in time.
func (p *HostUsageProvider) Measure(ctx context.Context) ([]FSUsage, []StalledDisk, error) {
	local, stalled := p.measureLocal(ctx)
	ms := append([]diskMeasurement(nil), local...)
	if db, ok := p.measureDB(ctx, false, local); ok {
		ms = append(ms, db)
	}
	if len(ms) == 0 {
		return nil, stalled, errors.New("no filesystem could be measured")
	}
	return groupDiskMeasurements(ms), stalled, nil
}

// MeasureDB returns a fresh measurement of the database filesystem. The
// emergency compressor calls it before every chunk, and DiskGuard.DBFree
// through it.
func (p *HostUsageProvider) MeasureDB(ctx context.Context) (*FSUsage, error) {
	m, ok := p.measureDB(ctx, true, nil)
	if !ok {
		return nil, errors.New("database disk is not measurable")
	}
	g := groupDiskMeasurements([]diskMeasurement{m})
	return &g[0], nil
}

func (p *HostUsageProvider) measureLocal(ctx context.Context) ([]diskMeasurement, []StalledDisk) {
	var out []diskMeasurement
	var stalled []StalledDisk
	for _, t := range p.local {
		raw, err := p.statfs(ctx, t.Path)
		if err != nil {
			if s, ok := asStatfsStalled(err); ok {
				stalled = append(stalled, StalledDisk{Role: t.Role, Path: t.Path, Since: s.Since})
				p.noteStall(t, true)
			} else if ctx.Err() == nil {
				p.warnOnce("statfs:"+t.Path, fmt.Sprintf("[DiskGuard] cannot measure %s (%s): %v", t.Path, t.Role, err))
			}
			continue
		}
		p.noteStall(t, false)
		out = append(out, diskMeasurement{role: t.Role, display: t.Path, source: "statfs", raw: raw, at: p.now()})
	}

	p.mu.Lock()
	archiveFn := p.archiveFn
	p.mu.Unlock()
	if archiveFn != nil {
		if a, ok := archiveFn(); ok && a.Path != "" {
			switch {
			case !a.StalledSince.IsZero():
				stalled = append(stalled, StalledDisk{Role: DiskRoleArchive, Path: a.Path, Since: a.StalledSince})
			case a.Stat.Blocks > 0:
				out = append(out, diskMeasurement{role: DiskRoleArchive, display: a.Path, source: "statfs", raw: a.Stat, at: a.MeasuredAt})
			}
		}
	}
	return out, stalled
}

// noteStall logs once when a path stops answering and once when it answers
// again, instead of every tick in between.
func (p *HostUsageProvider) noteStall(t diskTarget, stalled bool) {
	p.mu.Lock()
	was := p.stalled[t.Path]
	if stalled {
		p.stalled[t.Path] = true
	} else {
		delete(p.stalled, t.Path)
	}
	p.mu.Unlock()
	switch {
	case stalled && !was:
		log.Printf("[DiskGuard] %s (%s) is not answering: statfs did not return within %s. A hung network mount? Its disk is reported as stalled, not measured, until it answers", t.Path, t.Role, statfsTimeout)
	case !stalled && was:
		log.Printf("[DiskGuard] %s (%s) answers again", t.Path, t.Role)
	}
}

// measureDB measures the database's filesystem. force skips the reuse of a
// recent measurement (MeasureDB); local, when given, lets a verified exec
// find a mounted volume on the same filesystem to use as an alias.
func (p *HostUsageProvider) measureDB(ctx context.Context, force bool, local []diskMeasurement) (diskMeasurement, bool) {
	now := p.now()
	p.mu.Lock()
	alias, display := p.alias, p.dbDisplay()
	aliasFresh := alias != "" && now.Sub(p.aliasVerified) < dbAliasTTL
	backingOff := p.execFailing && now.Sub(p.lastExec) < p.dbEvery
	p.mu.Unlock()

	// A local path on the same filesystem answers instantly and exactly; exec
	// re-verifies it hourly. While the container cannot be asked (restarting,
	// exec failing) the alias keeps answering past that hour: a volume cannot
	// move to another disk without recreating the container, after which exec
	// works again and re-verifies. Without this a database restart would
	// rename the shared disk from "db" to "nginx_logs" and repeat an open
	// alert under the new name.
	if alias != "" && (aliasFresh || backingOff) {
		if raw, err := p.statfs(ctx, alias); err == nil {
			return diskMeasurement{role: DiskRoleDB, display: display, source: "docker_exec", raw: raw, at: now}, true
		}
		p.mu.Lock()
		p.alias = "" // the path no longer answers; exec decides below
		p.mu.Unlock()
	}

	p.mu.Lock()
	if !force && !p.urgent && p.dbLast != nil && now.Sub(p.dbLast.at) < p.dbEvery {
		last := *p.dbLast
		p.mu.Unlock()
		return last, true
	}
	if !force && backingOff {
		p.mu.Unlock()
		return p.staleDB(now)
	}
	p.mu.Unlock()

	name, dir, reason := p.locateDB(ctx)
	if name == "" {
		return p.dbUnreachable(ctx, now, "", "", reason, nil)
	}
	raw, source, err := p.execStatfs(ctx, name, dir)
	if err != nil {
		p.mu.Lock()
		p.locatedAt = time.Time{} // re-locate next time: the container may have been recreated
		p.mu.Unlock()
		return p.dbUnreachable(ctx, now, name, dir, "db_exec_failed", err)
	}

	m := diskMeasurement{role: DiskRoleDB, display: name + ":" + dir, source: source, raw: raw, at: now}
	p.mu.Lock()
	p.lastExec, p.execFailing = now, false
	// A later failure must be able to log again.
	for k := range p.warned {
		if strings.HasPrefix(k, "db:") {
			delete(p.warned, k)
		}
	}
	p.dbLast = &m
	p.dbInfo = model.DatabaseDiskInfo{Measured: true, Container: name, DataDir: dir}
	if local != nil {
		p.alias = ""
		if id := raw.identity(); id != "" {
			for _, l := range local {
				if l.raw.identity() == id && l.role != DiskRoleDocker {
					p.alias, p.aliasVerified = l.display, now
					break
				}
			}
		}
	}
	p.mu.Unlock()
	return m, true
}

// dbUnreachable handles a database container that could not be asked: the
// verified alias keeps answering; without one the last measurement is reused
// for up to dbStaleAfter, and after that the database disk is reported as not
// measured — never guessed from another disk.
func (p *HostUsageProvider) dbUnreachable(ctx context.Context, now time.Time, name, dir, reason string, cause error) (diskMeasurement, bool) {
	p.mu.Lock()
	p.lastExec, p.execFailing = now, true
	alias, display := p.alias, p.dbDisplay()
	p.mu.Unlock()
	if alias != "" {
		if raw, err := p.statfs(ctx, alias); err == nil {
			// Known disk, unverified container: say both.
			p.setInfo(model.DatabaseDiskInfo{Measured: true, Container: name, DataDir: dir, Reason: reason})
			p.warnOnce("db:alias", fmt.Sprintf("[DiskGuard] cannot reach the database container (%s); measuring %s, which was verified to be on the same disk", reason, alias))
			return diskMeasurement{role: DiskRoleDB, display: display, source: "docker_exec", raw: raw, at: now}, true
		}
	}
	p.setInfo(model.DatabaseDiskInfo{Measured: false, Container: name, DataDir: dir, Reason: reason})
	p.warnOnce("db:"+reason, dbNotMeasuredLine(reason, name, cause))
	return p.staleDB(now)
}

// dbNotMeasuredLine is the one container-log line that tells the operator why
// the database disk is not watched and what to do about it.
func dbNotMeasuredLine(reason, name string, cause error) string {
	const prefix = "[DiskGuard] database disk is not measured: "
	switch reason {
	case "db_external":
		return prefix + "DATABASE_URL points at a database that is not a container on this Docker host, so its disk is not watched here. If it is one, set NPG_DB_CONTAINER to its name"
	case "docker_unavailable":
		return prefix + "the Docker CLI in the API container cannot reach the Docker socket"
	case "db_exec_failed":
		return fmt.Sprintf("%srunning stat in the container %s failed: %v", prefix, name, cause)
	default:
		return prefix + "set NPG_DB_CONTAINER to the name of your TimescaleDB container to get database disk alerts and emergency compression"
	}
}

// dbDisplay must be called with p.mu held.
func (p *HostUsageProvider) dbDisplay() string {
	if p.dbLast != nil {
		return p.dbLast.display
	}
	return p.dbName + ":" + p.dbDataDir
}

func (p *HostUsageProvider) staleDB(now time.Time) (diskMeasurement, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dbLast != nil && now.Sub(p.dbLast.at) < dbStaleAfter {
		return *p.dbLast, true
	}
	return diskMeasurement{}, false
}

func (p *HostUsageProvider) setInfo(i model.DatabaseDiskInfo) {
	p.mu.Lock()
	p.dbInfo = i
	p.mu.Unlock()
}

func (p *HostUsageProvider) locateDB(ctx context.Context) (name, dir, reason string) {
	p.mu.Lock()
	if p.dbName != "" && p.now().Sub(p.locatedAt) < dbLocateTTL {
		name, dir = p.dbName, p.dbDataDir
		p.mu.Unlock()
		return name, dir, ""
	}
	p.mu.Unlock()

	name, reason = p.locator.locate(ctx)
	if name == "" {
		return "", "", reason
	}
	dir = defaultPGDataDir
	if p.dataDirFn != nil {
		// SHOW data_directory needs superuser or pg_read_all_settings; the
		// stock compose connects as postgres. Otherwise the image default.
		if d, err := p.dataDirFn(ctx); err == nil && validDataDir(d) {
			dir = d
		}
	}
	p.mu.Lock()
	p.dbName, p.dbDataDir, p.locatedAt = name, dir, p.now()
	p.mu.Unlock()
	return name, dir, ""
}

// execStatfs runs `stat -f` inside the database container: a fixed argv, the
// name checked by containerNameRe, the path validated and passed after "--".
// BusyBox `df -Pk` is the fallback for images without `stat -f`.
func (p *HostUsageProvider) execStatfs(ctx context.Context, name, dir string) (rawStatfs, string, error) {
	out, err := p.run(ctx, "exec", name, "stat", "-f", "-c", statfsFormat, "--", dir)
	if err == nil {
		raw, perr := parseStatfsLine(string(out))
		if perr == nil {
			return raw, "docker_exec", nil
		}
		err = perr
	}
	out2, err2 := p.run(ctx, "exec", name, "df", "-Pk", "--", dir)
	if err2 == nil {
		if raw, perr := parseDfP(string(out2)); perr == nil {
			return raw, "docker_exec_df", nil
		}
	}
	return rawStatfs{}, "", err
}

func (p *HostUsageProvider) warnOnce(key, msg string) {
	p.mu.Lock()
	seen := p.warned[key]
	p.warned[key] = true
	p.mu.Unlock()
	if !seen {
		log.Print(msg)
	}
}

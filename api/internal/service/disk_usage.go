package service

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Disk measurement for DiskGuard (D1): what a measurement is, and how
// measurements of the same physical disk are grouped.
//
// The only disk number NPG had was gopsutil's disk.Usage("/") inside the API
// container, which is Docker's storage, not the database's. On the
// 2026-10-09 production outage the database volume filled first. So each
// filesystem NPG writes to is measured where it actually lives
// (disk_provider.go):
//
//   - the database data directory is NOT mounted in this container. It is
//     measured with `stat -f` run inside the database container, through the
//     Docker socket the API already uses for nginx. The timescale image is
//     Alpine; BusyBox `stat -f -c %i` prints the same fsid as Go's statfs for
//     the same filesystem (verified against TimescaleDB 2.24.0-pg17).
//   - nginx logs (/etc/nginx/logs) and backups (BACKUP_PATH) are Docker volumes
//     mounted here; statfs directly, under a timeout.
//   - Docker's own storage (images, container json logs, the nginx proxy
//     cache) is this container's "/" overlay, whose statfs reports the backing
//     disk's numbers under a different fsid.
//
// On a default install all of these are one disk. They are grouped per
// filesystem so one full disk is one alert, not four.

// DiskRole is what a filesystem holds for NPG.
type DiskRole string

const (
	DiskRoleDB        DiskRole = "db"
	DiskRoleNginxLogs DiskRole = "nginx_logs"
	DiskRoleArchive   DiskRole = "archive"
	DiskRoleBackups   DiskRole = "backups"
	DiskRoleDocker    DiskRole = "docker"
)

// diskRolePriority orders roles by how badly a full disk under them hurts. The
// first role on a filesystem names it, and is the notification subject.
var diskRolePriority = map[DiskRole]int{
	DiskRoleDB: 0, DiskRoleNginxLogs: 1, DiskRoleArchive: 2, DiskRoleBackups: 3, DiskRoleDocker: 4,
}

// identity is the grouping key when the fsid is trustworthy.
func (r rawStatfs) identity() string {
	if r.FSID == "" || r.FSID == "0" || r.Type == overlayFSMagic {
		return ""
	}
	return "fsid:" + r.FSID
}

// fingerprint matches an overlay root (or an fsid-less df result) to the
// filesystem it reports on. Two different disks would have to agree on block
// size, block count and inode count to collide.
func (r rawStatfs) fingerprint() string {
	if r.Files == 0 {
		// df gives no inode count; total bytes is the best it can do.
		return fmt.Sprintf("bytes:%d", r.Blocks*r.Frsize)
	}
	return fmt.Sprintf("fp:%d:%d:%d", r.Frsize, r.Blocks, r.Files)
}

// FSUsage is one measured filesystem with every role it holds.
type FSUsage struct {
	Key         string
	Roles       []DiskRole
	Path        string
	Source      string
	Total       uint64
	Used        uint64
	Avail       uint64
	UsedPercent float64
	MeasuredAt  time.Time
	Level       DiskLevel
	raw         rawStatfs
}

func (f FSUsage) HasRole(r DiskRole) bool {
	for _, x := range f.Roles {
		if x == r {
			return true
		}
	}
	return false
}

func (f FSUsage) roleCodes() string {
	parts := make([]string, len(f.Roles))
	for i, r := range f.Roles {
		parts[i] = string(r)
	}
	return strings.Join(parts, ",")
}

type diskTarget struct {
	Role DiskRole
	Path string
}

// diskMeasurement is one role measured once.
type diskMeasurement struct {
	role    DiskRole
	display string
	source  string
	raw     rawStatfs
	at      time.Time
}

// groupDiskMeasurements merges measurements that are on the same filesystem
// and returns one FSUsage per filesystem, fullest first.
func groupDiskMeasurements(ms []diskMeasurement) []FSUsage {
	type group struct {
		ms []diskMeasurement
		fp string
	}
	byID := map[string]*group{}
	var order []*group
	var loose []diskMeasurement
	for _, m := range ms {
		id := m.raw.identity()
		if id == "" {
			loose = append(loose, m)
			continue
		}
		g := byID[id]
		if g == nil {
			g = &group{fp: m.raw.fingerprint()}
			byID[id] = g
			order = append(order, g)
		}
		g.ms = append(g.ms, m)
	}
	for _, m := range loose {
		fp := m.raw.fingerprint()
		var into *group
		for _, g := range order {
			if g.fp == fp || sameBytes(g.ms[0].raw, m.raw, fp) {
				into = g
				break
			}
		}
		if into == nil {
			into = &group{fp: fp}
			order = append(order, into)
		}
		into.ms = append(into.ms, m)
	}

	out := make([]FSUsage, 0, len(order))
	for _, g := range order {
		sort.SliceStable(g.ms, func(i, j int) bool {
			return diskRolePriority[g.ms[i].role] < diskRolePriority[g.ms[j].role]
		})
		primary := g.ms[0]
		// Numbers from the freshest measurement: they are the same disk.
		freshest := g.ms[0]
		seen := map[DiskRole]bool{}
		var roles []DiskRole
		for _, m := range g.ms {
			if m.at.After(freshest.at) {
				freshest = m
			}
			if !seen[m.role] {
				seen[m.role] = true
				roles = append(roles, m.role)
			}
		}
		total, used, avail, pct := freshest.raw.usage()
		out = append(out, FSUsage{
			Key: string(primary.role), Roles: roles, Path: primary.display, Source: primary.source,
			Total: total, Used: used, Avail: avail, UsedPercent: pct, MeasuredAt: freshest.at, raw: freshest.raw,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].UsedPercent > out[j].UsedPercent })
	return out
}

// sameBytes lets a df result (bytes only) join a statfs group of the same size.
func sameBytes(a, b rawStatfs, fp string) bool {
	if !strings.HasPrefix(fp, "bytes:") {
		return false
	}
	ta, tb := a.Blocks*a.Frsize, b.Blocks*b.Frsize
	if ta == 0 || tb == 0 {
		return false
	}
	diff := float64(ta) - float64(tb)
	if diff < 0 {
		diff = -diff
	}
	return diff/float64(ta) < 0.001
}

// ── parsing what the database container prints ───────────────────────────

// statfsFormat is passed to `stat -f -c`. One argv element, no shell.
const statfsFormat = "%i %S %b %f %a %c %d %t"

func parseStatfsLine(out string) (rawStatfs, error) {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) != 8 {
		return rawStatfs{}, fmt.Errorf("unexpected stat output %q", strings.TrimSpace(out))
	}
	var n [6]uint64
	for i := 0; i < 6; i++ {
		v, err := strconv.ParseUint(f[i+1], 10, 64)
		if err != nil {
			return rawStatfs{}, fmt.Errorf("unexpected stat field %q", f[i+1])
		}
		n[i] = v
	}
	if _, err := strconv.ParseUint(f[0], 16, 64); err != nil {
		return rawStatfs{}, fmt.Errorf("unexpected fsid %q", f[0])
	}
	typ, err := strconv.ParseInt(f[7], 16, 64)
	if err != nil {
		return rawStatfs{}, fmt.Errorf("unexpected fs type %q", f[7])
	}
	if n[0] == 0 || n[1] == 0 {
		return rawStatfs{}, errors.New("stat reported an empty filesystem")
	}
	return rawStatfs{FSID: strings.ToLower(f[0]), Type: typ, Frsize: n[0], Blocks: n[1], Bfree: n[2], Bavail: n[3], Files: n[4]}, nil
}

// parseDfP parses `df -Pk`: a fallback for images without `stat -f`.
func parseDfP(out string) (rawStatfs, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 {
		return rawStatfs{}, fmt.Errorf("unexpected df output %q", out)
	}
	f := strings.Fields(lines[len(lines)-1])
	if len(f) < 6 {
		return rawStatfs{}, fmt.Errorf("unexpected df line %q", lines[len(lines)-1])
	}
	total, err1 := strconv.ParseUint(f[1], 10, 64)
	used, err2 := strconv.ParseUint(f[2], 10, 64)
	avail, err3 := strconv.ParseUint(f[3], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || total == 0 || used > total {
		return rawStatfs{}, fmt.Errorf("unexpected df numbers %q", lines[len(lines)-1])
	}
	return rawStatfs{Frsize: 1024, Blocks: total, Bfree: total - used, Bavail: avail}, nil
}

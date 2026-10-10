package service

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"nginx-proxy-guard/internal/model"
)

// Raw nginx log files (access_raw.log / error_raw.log and their rotated
// copies): which names exist, what they hold, and how much disk they will
// take. Shared by the log file endpoints and the archive mover.

// Where a raw log file lives.
const (
	RawLogLocationLocal   = "local"
	RawLogLocationArchive = "archive"
)

// rawLogNameRE is every name the local log directory may serve: the two
// live files, rotated copies (-YYYYMMDD-HHMMSS, or -YYYYMMDD before #301, or
// .N from a logrotate config without dateext), compressed or not. Nothing
// else is listed, served or deleted, so no request can name another file.
var rawLogNameRE = regexp.MustCompile(`^(access|error)_raw\.log(-[0-9]{8}(-[0-9]{6})?|\.[0-9]{1,4})?(\.gz|\.bz2)?$`)

// rotatedRawLogRE is a rotated copy as logrotate's dateext writes it, with
// the rotation time: the only names the archive moves, holds and prunes.
var rotatedRawLogRE = regexp.MustCompile(`^(access|error)_raw\.log-([0-9]{8})-([0-9]{6})(\.gz)?$`)

// datedRawLogRE extracts the rotation time from any dated rotated name.
var datedRawLogRE = regexp.MustCompile(`^(access|error)_raw\.log-([0-9]{8})(?:-([0-9]{6}))?(\.gz|\.bz2)?$`)

// IsRawLogFileName reports whether name is a raw log file the local log
// directory lists and serves.
func IsRawLogFileName(name string) bool { return rawLogNameRE.MatchString(name) }

// IsArchivedRawLogName reports whether name is a rotated copy the archive
// may hold: the dateext pattern with a time ParseRotatedAt accepts, so every
// such name has a rotation time (a stray access_raw.log-20261301-000000.gz
// does not, and is left where it is).
func IsArchivedRawLogName(name string) bool {
	if !rotatedRawLogRE.MatchString(name) {
		return false
	}
	_, ok := ParseRotatedAt(name)
	return ok
}

// IsActiveRawLog reports whether name is a file nginx is writing right now.
func IsActiveRawLog(name string) bool { return name == "access_raw.log" || name == "error_raw.log" }

// ParseRotatedAt returns the rotation time a rotated name carries, in local
// time (logrotate formats it with the nginx container's TZ, which compose
// sets the same as the API's). Names from before #301 carry only the date
// and read as midnight.
func ParseRotatedAt(name string) (time.Time, bool) {
	m := datedRawLogRE.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	clock := m[3]
	if clock == "" {
		clock = "000000"
	}
	t, err := time.ParseInLocation("20060102-150405", m[2]+"-"+clock, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// RawLogFile is one raw log file, local or archived.
type RawLogFile struct {
	Name         string     `json:"name"`
	Size         int64      `json:"size"`
	ModifiedAt   time.Time  `json:"modified_at"`
	RotatedAt    *time.Time `json:"rotated_at,omitempty"`
	IsCompressed bool       `json:"is_compressed"`
	LogType      string     `json:"log_type"` // access, error
	IsActive     bool       `json:"is_active"`
	Location     string     `json:"location"` // local, archive

	// changedAt is the inode change time (ctime): how long the file has been
	// left alone. The archive mover settles on it, not on the modification
	// time, which compression copies from the uncompressed original.
	changedAt time.Time
}

// newRawLogFile describes a directory entry, or returns false when the name
// is not a raw log or the entry is not a regular file (a symlink, say).
func newRawLogFile(info os.FileInfo, location string, allowed func(string) bool) (RawLogFile, bool) {
	name := info.Name()
	if !info.Mode().IsRegular() || !allowed(name) {
		return RawLogFile{}, false
	}
	f := RawLogFile{
		Name:         name,
		Size:         info.Size(),
		ModifiedAt:   info.ModTime(),
		IsCompressed: strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".bz2"),
		LogType:      strings.SplitN(name, "_", 2)[0],
		IsActive:     location == RawLogLocationLocal && IsActiveRawLog(name),
		Location:     location,
		changedAt:    changeTime(info),
	}
	if t, ok := ParseRotatedAt(name); ok {
		f.RotatedAt = &t
	}
	return f, true
}

// ScanRawLogDir lists the raw log files in the local log directory. A missing
// directory is an empty list.
func ScanRawLogDir(dir string) ([]RawLogFile, error) {
	return scanRawLogs(dir, RawLogLocationLocal, IsRawLogFileName)
}

func scanRawLogs(dir, location string, allowed func(string) bool) ([]RawLogFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	files := make([]RawLogFile, 0, len(entries))
	for _, e := range entries {
		if !allowed(e.Name()) {
			continue
		}
		// Lstat, through Info: a symlink is reported as one, never followed.
		info, err := e.Info()
		if err != nil {
			continue
		}
		if f, ok := newRawLogFile(info, location, allowed); ok {
			files = append(files, f)
		}
	}
	return files, nil
}

// scanRawLogsTick is scanRawLogs for a directory that may be large and slow
// (the archive on a NAS): it reads the directory in batches and calls tick
// after each batch and each file, so the caller can tell a long listing that
// is moving from one that hangs. The result is in name order, as ReadDir's.
func scanRawLogsTick(dir, location string, allowed func(string) bool, tick func()) ([]RawLogFile, error) {
	d, err := os.Open(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer d.Close()
	var files []RawLogFile
	for {
		entries, err := d.ReadDir(256)
		tick()
		for _, e := range entries {
			if !allowed(e.Name()) {
				continue
			}
			// Lstat, through Info: a symlink is reported as one, never followed.
			info, ierr := e.Info()
			tick()
			if ierr != nil {
				continue
			}
			if f, ok := newRawLogFile(info, location, allowed); ok {
				files = append(files, f)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// StatRawLogFile describes one file by path without following a symlink.
func StatRawLogFile(path, location string) (RawLogFile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return RawLogFile{}, err
	}
	allowed := IsRawLogFileName
	if location == RawLogLocationArchive {
		allowed = IsArchivedRawLogName
	}
	f, ok := newRawLogFile(info, location, allowed)
	if !ok {
		return RawLogFile{}, os.ErrInvalid
	}
	return f, nil
}

// SortRawLogFiles orders files the way the list shows them: the live files
// first (by name, so they keep their places while nginx writes to them),
// then the newest rotation (or modification) first, then by name.
func SortRawLogFiles(files []RawLogFile) {
	sort.SliceStable(files, func(i, j int) bool {
		a, b := files[i], files[j]
		if a.IsActive != b.IsActive {
			return a.IsActive
		}
		if a.IsActive {
			return a.Name < b.Name
		}
		ta, tb := a.ModifiedAt, b.ModifiedAt
		if a.RotatedAt != nil {
			ta = *a.RotatedAt
		}
		if b.RotatedAt != nil {
			tb = *b.RotatedAt
		}
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
		return a.Name < b.Name
	})
}

// RawLogUsage is the disk use of the raw logs, measured from the files
// themselves. The UI projects it with the retention being edited:
// avg_daily_bytes × retention + live_bytes + pending_bytes.
type RawLogUsage struct {
	// Basis: last_7_days, history (fewer days of rotated files so far) or
	// none (no finished rotated file yet — nothing to average).
	Basis         string `json:"basis"`
	BasisDays     int    `json:"basis_days"`
	AvgDailyBytes int64  `json:"avg_daily_bytes"`
	// LiveBytes: access_raw.log and error_raw.log now.
	LiveBytes int64 `json:"live_bytes"`
	// PendingBytes: rotated files not finished yet — with compression on,
	// the newest rotated file, which is compressed at the next rotation.
	PendingBytes int64 `json:"pending_bytes"`

	LocalBytes   int64 `json:"local_bytes"`
	LocalFiles   int   `json:"local_files"`
	ArchiveBytes int64 `json:"archive_bytes"`
	ArchiveFiles int   `json:"archive_files"`

	RetentionDays        int  `json:"retention_days"`
	Compressed           bool `json:"compressed"`
	ArchiveEnabled       bool `json:"archive_enabled"`
	ArchiveRetentionDays int  `json:"archive_retention_days,omitempty"`

	// Server-side projection with the saved settings. With archiving on,
	// rotated files leave the log disk once settled.
	ProjectedLocalBytes   int64 `json:"projected_local_bytes"`
	ProjectedArchiveBytes int64 `json:"projected_archive_bytes"`

	// The filesystem holding the log directory (statfs; omitted when it
	// could not be measured in time).
	LocalFSType     string `json:"local_fs_type,omitempty"`
	LocalTotalBytes uint64 `json:"local_total_bytes,omitempty"`
	LocalFreeBytes  uint64 `json:"local_free_bytes,omitempty"`
	// The archive's filesystem, from the archiver's last measurement.
	ArchiveTotalBytes uint64 `json:"archive_total_bytes,omitempty"`
	ArchiveFreeBytes  uint64 `json:"archive_free_bytes,omitempty"`
}

// Basis values of RawLogUsage.
const (
	RawLogUsageBasisWeek    = "last_7_days"
	RawLogUsageBasisHistory = "history"
	RawLogUsageBasisNone    = "none"
)

const rawLogUsageWindowDays = 7

// EstimateRawLogUsage averages the finished rotated files (compressed ones
// when compression is on) whose rotation fell on the last 7 local calendar
// days before today — or on the days since the oldest rotated file, when
// history is shorter — local and archived alike, since archived files left
// the log disk but were written all the same.
func EstimateRawLogUsage(local, archive []RawLogFile, now time.Time, rot model.RawLogRotation, archiveOn bool, archiveRetentionDays int) RawLogUsage {
	u := RawLogUsage{
		Basis:          RawLogUsageBasisNone,
		RetentionDays:  rot.RetentionDays,
		Compressed:     rot.Compress,
		ArchiveEnabled: archiveOn,
	}
	if archiveOn {
		u.ArchiveRetentionDays = archiveRetentionDays
	}
	finished := func(f RawLogFile) bool { return f.RotatedAt != nil && (f.IsCompressed || !rot.Compress) }

	for _, f := range local {
		u.LocalBytes += f.Size
		u.LocalFiles++
		switch {
		case f.IsActive:
			u.LiveBytes += f.Size
		case f.RotatedAt != nil && !finished(f):
			u.PendingBytes += f.Size
		}
	}
	for _, f := range archive {
		u.ArchiveBytes += f.Size
		u.ArchiveFiles++
	}

	loc := now.Location()
	today := localDate(now, loc)
	windowStart := today.AddDate(0, 0, -rawLogUsageWindowDays)
	var oldest time.Time
	var windowBytes int64
	var inWindow int
	for _, list := range [][]RawLogFile{local, archive} {
		for _, f := range list {
			if f.RotatedAt == nil {
				continue
			}
			day := localDate(*f.RotatedAt, loc)
			if oldest.IsZero() || day.Before(oldest) {
				oldest = day
			}
			if finished(f) && !day.Before(windowStart) && day.Before(today) {
				windowBytes += f.Size
				inWindow++
			}
		}
	}

	days := rawLogUsageWindowDays
	if !oldest.IsZero() && oldest.After(windowStart) {
		days = daysBetween(oldest, today)
	}
	if inWindow > 0 && days >= 1 {
		u.BasisDays = days
		u.AvgDailyBytes = windowBytes / int64(days)
		u.Basis = RawLogUsageBasisWeek
		if days < rawLogUsageWindowDays {
			u.Basis = RawLogUsageBasisHistory
		}
	}

	u.ProjectedLocalBytes = u.LiveBytes + u.PendingBytes
	if archiveOn {
		u.ProjectedArchiveBytes = u.AvgDailyBytes * int64(archiveRetentionDays)
	} else {
		u.ProjectedLocalBytes += u.AvgDailyBytes * int64(rot.RetentionDays)
	}
	return u
}

func localDate(t time.Time, loc *time.Location) time.Time {
	y, m, d := t.In(loc).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, loc)
}

// daysBetween counts calendar days between two local midnights; rounding
// absorbs the 23- and 25-hour days of DST changes.
func daysBetween(from, to time.Time) int {
	return int(math.Round(to.Sub(from).Hours() / 24))
}

// rawLogStatfs measures the log directory's filesystem without letting a
// stuck mount hold a request.
var rawLogStatfs = newStatfsGuard(statfsNearest, statfsTimeout)

// RawLogFilesystem reports the filesystem holding dir: its type name ("" when
// unknown), size and the bytes available to the nginx user.
func RawLogFilesystem(ctx context.Context, dir string) (fsType string, total, avail uint64, err error) {
	raw, err := rawLogStatfs.stat(ctx, filepath.Clean(dir))
	if err != nil {
		return "", 0, 0, err
	}
	total, _, avail, _ = raw.usage()
	return raw.typeName(), total, avail, nil
}

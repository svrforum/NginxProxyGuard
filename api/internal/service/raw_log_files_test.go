package service

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

const fileMiB = int64(1 << 20)

// rotated builds a rotated file record the way ScanRawLogDir would.
func rotated(at time.Time, size int64, gz bool) RawLogFile {
	name := "access_raw.log-" + at.Format("20060102-150405")
	if gz {
		name += ".gz"
	}
	t := at
	return RawLogFile{Name: name, Size: size, ModifiedAt: at, RotatedAt: &t, IsCompressed: gz, LogType: "access", Location: RawLogLocationLocal}
}

func live(size int64) RawLogFile {
	return RawLogFile{Name: "access_raw.log", Size: size, IsActive: true, LogType: "access", Location: RawLogLocationLocal}
}

func TestEstimateRawLogUsage(t *testing.T) {
	loc := time.FixedZone("KST", 9*3600)
	now := time.Date(2026, 10, 10, 15, 0, 0, 0, loc)
	day := func(daysAgo int) time.Time { return time.Date(2026, 10, 10-daysAgo, 0, 0, 3, 0, loc) }
	rot := model.RawLogRotation{MaxSizeMB: 100, RetentionDays: 30, Compress: true}

	// Seven daily 100 MB .gz files, the live file and the delaycompress file.
	var daily []RawLogFile
	for d := 1; d <= 7; d++ {
		daily = append(daily, rotated(day(d), 100*fileMiB, true))
	}
	// Older files are outside the window and do not count.
	daily = append(daily, rotated(day(20), 900*fileMiB, true))
	files := append(append([]RawLogFile{}, daily...), live(50*fileMiB), rotated(now.Add(-time.Hour), 300*fileMiB, false))

	u := EstimateRawLogUsage(files, nil, now, rot, RawLogArchiveUse{})
	if u.Basis != RawLogUsageBasisWeek || u.BasisDays != 7 || u.AvgDailyBytes != 100*fileMiB {
		t.Fatalf("daily files: basis=%s days=%d avg=%d MiB, want last_7_days/7/100", u.Basis, u.BasisDays, u.AvgDailyBytes/fileMiB)
	}
	if u.LiveBytes != 50*fileMiB || u.PendingBytes != 300*fileMiB {
		t.Fatalf("live=%d pending=%d MiB, want 50/300", u.LiveBytes/fileMiB, u.PendingBytes/fileMiB)
	}
	if want := (3000 + 350) * fileMiB; u.ProjectedLocalBytes != want {
		t.Fatalf("projected local = %d MiB, want %d", u.ProjectedLocalBytes/fileMiB, want/fileMiB)
	}
	if u.LocalFiles != 10 || u.LocalBytes != (700+900+50+300)*fileMiB {
		t.Fatalf("local totals: %d files, %d MiB", u.LocalFiles, u.LocalBytes/fileMiB)
	}

	// Hourly size cuts: 24 files a day of a 24th each — same average.
	var hourly []RawLogFile
	for d := 1; d <= 7; d++ {
		for h := 0; h < 24; h++ {
			at := time.Date(2026, 10, 10-d, h, 0, 1, 0, loc)
			hourly = append(hourly, rotated(at, 100*fileMiB/24, true))
		}
	}
	if u := EstimateRawLogUsage(hourly, nil, now, rot, RawLogArchiveUse{}); u.AvgDailyBytes < 99*fileMiB || u.AvgDailyBytes > 100*fileMiB {
		t.Fatalf("hourly cuts: avg = %d bytes, want about 100 MiB", u.AvgDailyBytes)
	}

	// Compression off: the uncompressed rotated files are the finished ones.
	plain := model.RawLogRotation{MaxSizeMB: 100, RetentionDays: 7}
	var uncompressed []RawLogFile
	for d := 1; d <= 7; d++ {
		uncompressed = append(uncompressed, rotated(day(d), 700*fileMiB, false))
	}
	if u := EstimateRawLogUsage(uncompressed, nil, now, plain, RawLogArchiveUse{}); u.AvgDailyBytes != 700*fileMiB || u.PendingBytes != 0 {
		t.Fatalf("compression off: avg=%d MiB pending=%d, want 700 MiB and 0", u.AvgDailyBytes/fileMiB, u.PendingBytes)
	}
	// ...and with compression on, those same files are only pending.
	if u := EstimateRawLogUsage(uncompressed, nil, now, rot, RawLogArchiveUse{}); u.Basis != RawLogUsageBasisNone || u.PendingBytes != 7*700*fileMiB {
		t.Fatalf("compression on, nothing compressed: basis=%s pending=%d MiB", u.Basis, u.PendingBytes/fileMiB)
	}

	// A fresh install has nothing to average.
	if u := EstimateRawLogUsage([]RawLogFile{live(fileMiB)}, nil, now, rot, RawLogArchiveUse{}); u.Basis != RawLogUsageBasisNone || u.AvgDailyBytes != 0 || u.ProjectedLocalBytes != fileMiB {
		t.Fatalf("fresh install: %+v", u)
	}
	// Rotated only today: still nothing finished before today.
	if u := EstimateRawLogUsage([]RawLogFile{rotated(now.Add(-2*time.Hour), fileMiB, true)}, nil, now, rot, RawLogArchiveUse{}); u.Basis != RawLogUsageBasisNone {
		t.Fatalf("rotated only today: basis = %s", u.Basis)
	}

	// Three days of history: averaged over three days, not seven.
	short := []RawLogFile{rotated(day(3), 30*fileMiB, true), rotated(day(2), 30*fileMiB, true), rotated(day(1), 30*fileMiB, true)}
	if u := EstimateRawLogUsage(short, nil, now, rot, RawLogArchiveUse{}); u.Basis != RawLogUsageBasisHistory || u.BasisDays != 3 || u.AvgDailyBytes != 30*fileMiB {
		t.Fatalf("short history: basis=%s days=%d avg=%d MiB", u.Basis, u.BasisDays, u.AvgDailyBytes/fileMiB)
	}

	// Archiving on: moved files still count toward the average; the log disk
	// keeps only the live and pending files; the archive holds the rest.
	var moved []RawLogFile
	for _, f := range daily[:7] {
		f.Location = RawLogLocationArchive
		moved = append(moved, f)
	}
	current := []RawLogFile{live(50 * fileMiB), rotated(now.Add(-time.Hour), 300*fileMiB, false)}
	u = EstimateRawLogUsage(current, moved, now, rot, RawLogArchiveUse{Enabled: true, Status: ArchiveStatusReady, RetentionDays: 365})
	if u.AvgDailyBytes != 100*fileMiB || u.ProjectedLocalBytes != 350*fileMiB || u.ProjectedArchiveBytes != 365*100*fileMiB || !u.ArchiveInUse {
		t.Fatalf("archive on: avg=%d local=%d archive=%d MiB, in use %v", u.AvgDailyBytes/fileMiB, u.ProjectedLocalBytes/fileMiB, u.ProjectedArchiveBytes/fileMiB, u.ArchiveInUse)
	}
	if u.ArchiveFiles != 7 || u.ArchiveBytes != 700*fileMiB || u.ArchiveRetentionDays != 365 {
		t.Fatalf("archive totals: %+v", u)
	}

	// Archiving on but the archive cannot take files: they stay on the log
	// disk under the local retention, so the projection counts them there.
	for _, status := range []string{ArchiveStatusNotMounted, ArchiveStatusNotInitialized, ArchiveStatusForeign, ArchiveStatusUnwritable, ArchiveStatusInsufficientSpace, ArchiveStatusStalled, ArchiveStatusLogDir, ""} {
		u = EstimateRawLogUsage(current, moved, now, rot, RawLogArchiveUse{Enabled: true, Status: status, RetentionDays: 365})
		if u.ArchiveInUse || !u.ArchiveEnabled || u.ProjectedLocalBytes != 350*fileMiB+int64(rot.RetentionDays)*100*fileMiB || u.ProjectedArchiveBytes != 0 {
			t.Errorf("archive %q: in use %v, local=%d archive=%d MiB; want the files counted on the log disk",
				status, u.ArchiveInUse, u.ProjectedLocalBytes/fileMiB, u.ProjectedArchiveBytes/fileMiB)
		}
	}
}

func TestParseRotatedAt(t *testing.T) {
	cases := map[string]string{
		"access_raw.log-20261009-000000.gz": "2026-10-09 00:00:00", // legacy name migrated to midnight
		"error_raw.log-20261009-134502":     "2026-10-09 13:45:02",
		"access_raw.log-20260919":           "2026-09-19 00:00:00", // before #301
		"access_raw.log-20260919.bz2":       "2026-09-19 00:00:00",
	}
	for name, want := range cases {
		got, ok := ParseRotatedAt(name)
		if !ok || got.Format("2006-01-02 15:04:05") != want || got.Location() != time.Local {
			t.Errorf("ParseRotatedAt(%q) = %v, %v; want %s local", name, got, ok, want)
		}
	}
	for _, name := range []string{"access_raw.log", "access_raw.log.1", "access_raw.log-2026100-000000", "access_raw.log-20261399-000000", "photo.jpg"} {
		if _, ok := ParseRotatedAt(name); ok {
			t.Errorf("ParseRotatedAt(%q) should not parse", name)
		}
	}
}

func TestRawLogNames(t *testing.T) {
	for _, name := range []string{"access_raw.log", "error_raw.log", "access_raw.log-20260919", "access_raw.log-20261009-000004.gz", "error_raw.log-20261009-120000", "access_raw.log.1", "access_raw.log.2.gz", "error_raw.log-20260919.bz2"} {
		if !IsRawLogFileName(name) {
			t.Errorf("%q should be a raw log name", name)
		}
	}
	for _, name := range []string{"../x", "a/b", "photo.jpg", "access_raw.log.part", "access_raw.log-20261009-000004.gz.part", "access.log", ".npg-raw-log-archive", "access_raw.log-garbage", "Access_raw.log", "access_raw.log\x00"} {
		if IsRawLogFileName(name) {
			t.Errorf("%q must not be a raw log name", name)
		}
	}
	// The archive holds only timestamped rotated copies.
	for name, want := range map[string]bool{
		"access_raw.log-20261009-000004.gz": true, "error_raw.log-20261009-120000": true,
		"access_raw.log": false, "access_raw.log-20260919": false, "access_raw.log-20261009-000004.bz2": false,
		"access_raw.log-20261009-000004.gz.part": false,
	} {
		if got := IsArchivedRawLogName(name); got != want {
			t.Errorf("IsArchivedRawLogName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestScanRawLogDirListsOnlyRawLogFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"access_raw.log", "error_raw.log", "access_raw.log-20261009-000000.gz", "access_raw.log-20261010-000001", "notes.txt", "access_raw.log.part"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// nginx writes the live files at any time: their order must not follow it.
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(dir, "error_raw.log"), later, later); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/stdout", filepath.Join(dir, "access_raw.log-20261008-000000")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "error_raw.log-20261007-000000"), 0755); err != nil {
		t.Fatal(err)
	}

	files, err := ScanRawLogDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	SortRawLogFiles(files)
	var got []string
	for _, f := range files {
		got = append(got, fmt.Sprintf("%s active=%v rotated=%v gz=%v %s", f.Name, f.IsActive, f.RotatedAt != nil, f.IsCompressed, f.Location))
	}
	want := []string{
		"access_raw.log active=true rotated=false gz=false local",
		"error_raw.log active=true rotated=false gz=false local",
		"access_raw.log-20261010-000001 active=false rotated=true gz=false local",
		"access_raw.log-20261009-000000.gz active=false rotated=true gz=true local",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("scan:\n got %q\nwant %q", got, want)
	}
	if files, err := ScanRawLogDir(filepath.Join(dir, "missing")); err != nil || len(files) != 0 {
		t.Fatalf("a missing directory must be an empty list, got %v %v", files, err)
	}
}

func TestRawLogFilesystemMeasuresTheLogDirectory(t *testing.T) {
	_, total, avail, err := RawLogFilesystem(t.Context(), t.TempDir())
	if err != nil {
		t.Skipf("statfs unavailable here: %v", err)
	}
	if total == 0 || avail > total {
		t.Fatalf("implausible: total=%d avail=%d", total, avail)
	}
}

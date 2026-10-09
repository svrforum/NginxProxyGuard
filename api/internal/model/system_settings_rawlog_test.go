package model

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func intp(v int) *int { return &v }

// Stored legacy values never block a save: long-running installs carry
// 1825 days / 9999 files, and API clients echo the whole object back.
func TestValidateRawLogSettingsOnlyChecksChangedValues(t *testing.T) {
	cur := &SystemSettings{RawLogRetentionDays: 1825, RawLogRotateCount: 9999, RawLogMaxSizeMB: 5, RawLogArchiveRetentionDays: 365}

	ok := []struct {
		name string
		req  UpdateSystemSettingsRequest
	}{
		{"nothing raw-log related", UpdateSystemSettingsRequest{}},
		{"legacy values echoed back", UpdateSystemSettingsRequest{
			RawLogRetentionDays: intp(1825), RawLogRotateCount: intp(9999), RawLogMaxSizeMB: intp(5),
		}},
		{"lower bounds", UpdateSystemSettingsRequest{
			RawLogRetentionDays: intp(1), RawLogMaxSizeMB: intp(10), RawLogRotateCount: intp(1),
		}},
		{"upper bounds", UpdateSystemSettingsRequest{
			RawLogRetentionDays: intp(3650), RawLogMaxSizeMB: intp(10240), RawLogRotateCount: intp(100000),
		}},
		{"archive retention bounds", UpdateSystemSettingsRequest{RawLogArchiveRetentionDays: intp(1)}},
		{"archive retention max", UpdateSystemSettingsRequest{RawLogArchiveRetentionDays: intp(3650)}},
	}
	for _, tc := range ok {
		req := tc.req
		if err := ValidateRawLogSettings(&req, cur); err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
	}

	bad := []struct {
		name  string
		req   UpdateSystemSettingsRequest
		field string
	}{
		{"retention 0", UpdateSystemSettingsRequest{RawLogRetentionDays: intp(0)}, "raw_log_retention_days"},
		{"retention 3651", UpdateSystemSettingsRequest{RawLogRetentionDays: intp(3651)}, "raw_log_retention_days"},
		{"size 9", UpdateSystemSettingsRequest{RawLogMaxSizeMB: intp(9)}, "raw_log_max_size_mb"},
		{"size 10241", UpdateSystemSettingsRequest{RawLogMaxSizeMB: intp(10241)}, "raw_log_max_size_mb"},
		{"rotate 0", UpdateSystemSettingsRequest{RawLogRotateCount: intp(0)}, "raw_log_rotate_count"},
		{"rotate 100001", UpdateSystemSettingsRequest{RawLogRotateCount: intp(100001)}, "raw_log_rotate_count"},
		{"archive retention 0", UpdateSystemSettingsRequest{RawLogArchiveRetentionDays: intp(0)}, "raw_log_archive_retention_days"},
		{"archive retention 3651", UpdateSystemSettingsRequest{RawLogArchiveRetentionDays: intp(3651)}, "raw_log_archive_retention_days"},
		{"a bad value next to an echoed legacy one", UpdateSystemSettingsRequest{
			RawLogRotateCount: intp(9999), RawLogRetentionDays: intp(-3),
		}, "raw_log_retention_days"},
	}
	for _, tc := range bad {
		req := tc.req
		err := ValidateRawLogSettings(&req, cur)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: want ErrInvalidInput, got %v", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "must be between") {
			t.Errorf("%s: the message must name %s and the range, got %q", tc.name, tc.field, err)
		}
	}

	// No stored row to compare with (should not happen, but must not panic):
	// every given value is then checked.
	if err := ValidateRawLogSettings(&UpdateSystemSettingsRequest{RawLogRetentionDays: intp(0)}, nil); err == nil {
		t.Error("retention 0 without a stored row must still be refused")
	}
}

func TestEffectiveRawLogRotationClampsWhatLogrotateCannotUse(t *testing.T) {
	cases := []struct {
		name        string
		in          SystemSettings
		want        RawLogRotation
		wantClamped bool
	}{
		{"defaults pass through", SystemSettings{RawLogRetentionDays: 7, RawLogMaxSizeMB: 100, RawLogCompressRotated: true},
			RawLogRotation{MaxSizeMB: 100, RetentionDays: 7, Compress: true}, false},
		{"legacy values inside logrotate's range are kept", SystemSettings{RawLogRetentionDays: 1825, RawLogMaxSizeMB: 5},
			RawLogRotation{MaxSizeMB: 5, RetentionDays: 1825}, false},
		{"zeros", SystemSettings{RawLogRetentionDays: 0, RawLogMaxSizeMB: 0},
			RawLogRotation{MaxSizeMB: 100, RetentionDays: 7}, true},
		{"too large", SystemSettings{RawLogRetentionDays: 99999, RawLogMaxSizeMB: 99999},
			RawLogRotation{MaxSizeMB: 10240, RetentionDays: 3650}, true},
	}
	for _, tc := range cases {
		got, clamped := tc.in.EffectiveRawLogRotation()
		if got != tc.want || clamped != tc.wantClamped {
			t.Errorf("%s: got %+v clamped=%v, want %+v clamped=%v", tc.name, got, clamped, tc.want, tc.wantClamped)
		}
	}
}

// The one-time retention handover (B1'): retention only goes up, and never
// past the number of days the install has existed (plus one).
func TestRawLogRetentionHandover(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	daysAgo := func(d float64) time.Time { return now.Add(-time.Duration(d * float64(24*time.Hour))) }

	cases := []struct {
		name              string
		retention, rotate int
		installedAt       time.Time
		want              int
	}{
		// Production: 1825 days / 9999 files, installed about 300 days ago.
		{"production keeps its 1825 days", 1825, 9999, daysAgo(300), 1825},
		{"7 days / 30 files, older than 30 days", 7, 30, daysAgo(400), 30},
		{"7 days / 30 files, 10 days old: only files that can exist", 7, 30, daysAgo(10), 11},
		{"partial days round down", 7, 30, daysAgo(10.9), 11},
		{"count not above retention: untouched", 30, 30, daysAgo(400), 30},
		{"defaults 7 / 5: untouched", 7, 5, daysAgo(400), 7},
		{"retention already at the maximum: untouched", 5000, 9999, daysAgo(4000), 5000},
		{"bounded by 3650", 7, 9999, daysAgo(9000), 3650},
		{"legacy zero retention", 0, 5, daysAgo(100), 5},
		{"fresh install restoring an old backup", 7, 30, now, 7},
		{"install date unknown: the count alone bounds it", 7, 30, time.Time{}, 30},
		{"install date in the future: nothing to protect", 7, 30, now.Add(48 * time.Hour), 7},
	}
	for _, tc := range cases {
		if got := RawLogRetentionHandover(tc.retention, tc.rotate, tc.installedAt, now); got != tc.want {
			t.Errorf("%s: RawLogRetentionHandover(%d, %d) = %d, want %d", tc.name, tc.retention, tc.rotate, got, tc.want)
		}
	}
}

func TestCoerceRawLogImportRepairsZeroValues(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	installed := now.AddDate(-2, 0, 0)
	archived := false

	ss := &SystemSettingsExport{RawLogArchiveEnabled: &archived}
	CoerceRawLogImport(ss, installed, now)
	if !ss.RawLogEnabled || ss.RawLogRetentionDays != 7 || ss.RawLogMaxSizeMB != 100 || ss.RawLogRotateCount != 5 {
		t.Fatalf("zero values were not replaced by the defaults: %+v", ss)
	}

	zero := 0
	ss = &SystemSettingsExport{RawLogArchiveEnabled: &archived, RawLogArchiveRetentionDays: &zero}
	CoerceRawLogImport(ss, installed, now)
	if *ss.RawLogArchiveRetentionDays != 365 {
		t.Fatalf("archive retention 0 must import as 365, got %d", *ss.RawLogArchiveRetentionDays)
	}

	kept := &SystemSettingsExport{RawLogEnabled: true, RawLogRetentionDays: 1825, RawLogMaxSizeMB: 5, RawLogRotateCount: 9999, RawLogArchiveEnabled: &archived}
	CoerceRawLogImport(kept, installed, now)
	if kept.RawLogRetentionDays != 1825 || kept.RawLogMaxSizeMB != 5 || kept.RawLogRotateCount != 9999 || kept.RawLogArchiveRetentionDays != nil {
		t.Fatalf("valid stored values must be imported as they are: %+v", kept)
	}

	CoerceRawLogImport(nil, installed, now) // must not panic
}

// A backup from before the archive columns (archive fields absent) gets the
// same retention handover as an upgrading install, bounded by the age of the
// install it is restored into. A newer backup is restored as it is.
func TestCoerceRawLogImportHandsOverOldBackups(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	daysAgo := func(d int) time.Time { return now.AddDate(0, 0, -d) }

	cases := []struct {
		name              string
		retention, rotate int
		installedAt       time.Time
		want              int
	}{
		{"production-shaped backup onto a 300-day-old install", 1825, 9999, daysAgo(300), 1825},
		{"7 days / 30 files onto an install older than 30 days", 7, 30, daysAgo(400), 30},
		{"7 days / 30 files onto a 10-day-old install", 7, 30, daysAgo(10), 11},
		{"7 days / 30 files onto a fresh install", 7, 30, now, 7},
		{"zero retention, 30 files, old install", 0, 30, daysAgo(400), 30},
	}
	for _, tc := range cases {
		old := &SystemSettingsExport{RawLogRetentionDays: tc.retention, RawLogRotateCount: tc.rotate, RawLogMaxSizeMB: 100}
		CoerceRawLogImport(old, tc.installedAt, now)
		if old.RawLogRetentionDays != tc.want {
			t.Errorf("%s: retention %d, want %d", tc.name, old.RawLogRetentionDays, tc.want)
		}
	}

	archived := true
	newer := &SystemSettingsExport{RawLogRetentionDays: 7, RawLogRotateCount: 30, RawLogMaxSizeMB: 100, RawLogArchiveEnabled: &archived}
	CoerceRawLogImport(newer, daysAgo(400), now)
	if newer.RawLogRetentionDays != 7 {
		t.Fatalf("a backup with archive fields was made after the handover; its retention must be kept, got %d", newer.RawLogRetentionDays)
	}
}

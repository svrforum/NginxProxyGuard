package model

import (
	"fmt"
	"math"
	"time"
)

// Raw nginx log files (system_settings.raw_log_*): the ranges the server
// accepts. The UI uses the same numbers, so it can never offer a value the
// server refuses.
const (
	// Rotated files older than this are deleted by logrotate's maxage at the
	// next rotation. The floor matters: logrotate reads `maxage 0` as "never
	// delete".
	RawLogRetentionDaysMin     = 1
	RawLogRetentionDaysMax     = 3650
	RawLogRetentionDaysDefault = 7

	// The live file is rotated early once it is larger than this (checked
	// every hour).
	RawLogMaxSizeMBMin     = 10
	RawLogMaxSizeMBMax     = 10240
	RawLogMaxSizeMBDefault = 100

	// Deprecated: the logrotate config no longer renders the rotated-file
	// count (retention is by age). It is still accepted, stored and backed up
	// for older clients. The floor of 1 protects a downgrade: an older NPG
	// would render `rotate 0`, which deletes every rotated file.
	RawLogRotateCountMin     = 1
	RawLogRotateCountMax     = 100000
	RawLogRotateCountDefault = 5

	// Archived files (raw_log_archive_*) older than this — by the time in
	// their name — are deleted from the archive directory.
	RawLogArchiveRetentionDaysMin     = 1
	RawLogArchiveRetentionDaysMax     = 3650
	RawLogArchiveRetentionDaysDefault = 365
)

// RawLogRotation is what the raw-log logrotate stanza is rendered from.
type RawLogRotation struct {
	MaxSizeMB     int
	RetentionDays int
	Compress      bool
}

// EffectiveRawLogRotation returns the stored rotation settings with values
// logrotate cannot use replaced: a retention below 1 day (maxage 0 would keep
// files forever) or above the maximum, and a size below 1 MB or above the
// maximum. clamped reports whether anything was replaced, so the caller can
// say so once. Stored legacy values that are merely outside the UI's range
// (a 5 MB size, say) are used as they are.
func (s *SystemSettings) EffectiveRawLogRotation() (r RawLogRotation, clamped bool) {
	r = RawLogRotation{
		MaxSizeMB:     s.RawLogMaxSizeMB,
		RetentionDays: s.RawLogRetentionDays,
		Compress:      s.RawLogCompressRotated,
	}
	switch {
	case r.RetentionDays < RawLogRetentionDaysMin:
		r.RetentionDays, clamped = RawLogRetentionDaysDefault, true
	case r.RetentionDays > RawLogRetentionDaysMax:
		r.RetentionDays, clamped = RawLogRetentionDaysMax, true
	}
	switch {
	case r.MaxSizeMB < 1:
		r.MaxSizeMB, clamped = RawLogMaxSizeMBDefault, true
	case r.MaxSizeMB > RawLogMaxSizeMBMax:
		r.MaxSizeMB, clamped = RawLogMaxSizeMBMax, true
	}
	return r, clamped
}

// ValidateRawLogSettings refuses a raw-log value only when this request
// changes it to something out of range. A value equal to the stored one is
// always accepted: the UI sends only edited fields, but API clients may echo
// the whole object back, and installs carry legacy values (1825 days and 9999
// files on long-running ones) that must never block saving anything else.
func ValidateRawLogSettings(req *UpdateSystemSettingsRequest, cur *SystemSettings) error {
	if req == nil {
		return nil
	}
	// Without a stored row there is nothing to compare with, so every value
	// given is checked.
	storedOf := func(get func(*SystemSettings) int) *int {
		if cur == nil {
			return nil
		}
		v := get(cur)
		return &v
	}
	checks := []struct {
		name     string
		value    *int
		stored   *int
		min, max int
	}{
		{"raw_log_retention_days", req.RawLogRetentionDays, storedOf(func(s *SystemSettings) int { return s.RawLogRetentionDays }), RawLogRetentionDaysMin, RawLogRetentionDaysMax},
		{"raw_log_max_size_mb", req.RawLogMaxSizeMB, storedOf(func(s *SystemSettings) int { return s.RawLogMaxSizeMB }), RawLogMaxSizeMBMin, RawLogMaxSizeMBMax},
		{"raw_log_rotate_count", req.RawLogRotateCount, storedOf(func(s *SystemSettings) int { return s.RawLogRotateCount }), RawLogRotateCountMin, RawLogRotateCountMax},
		{"raw_log_archive_retention_days", req.RawLogArchiveRetentionDays, storedOf(func(s *SystemSettings) int { return s.RawLogArchiveRetentionDays }), RawLogArchiveRetentionDaysMin, RawLogArchiveRetentionDaysMax},
	}
	for _, c := range checks {
		if err := checkRawLogRange(c.name, c.value, c.stored, c.min, c.max); err != nil {
			return err
		}
	}
	return nil
}

func checkRawLogRange(name string, value, stored *int, min, max int) error {
	if value == nil || (stored != nil && *value == *stored) {
		return nil
	}
	if *value < min || *value > max {
		return fmt.Errorf("%w: %s must be between %d and %d (got %d)", ErrInvalidInput, name, min, max, *value)
	}
	return nil
}

// RawLogRetentionHandover is the one-time rule that moves an install from
// "keep N rotated files" to "keep files for N days" (marker
// raw_log_retention_by_days_v1 in database/migration.go, and backups made
// before the archive columns existed, on import — see CoerceRawLogImport). Under the old config logrotate cut one file a day, so a
// file count N kept about N days — more than the retention in days whenever
// the count was larger. Raising retention to the count would keep every file
// the old config kept, but a count is no promise about files that cannot
// exist: none is older than the install. So the count is bounded by the
// install's age in whole days plus one, and retention only ever goes up:
//
//	retention = max(retention, min(count, floor(age days) + 1, 3650))
//	            only when count > retention and retention < 3650
//
// A 1825-day / 9999-file install that is 300 days old keeps 1825; a 7-day /
// 30-file one older than 30 days gets 30. installedAt is the zero time when
// the install date is unknown; the bound then falls back to the count. The
// SQL in migration.go computes exactly this (floor of the age in seconds over
// 86400, like Postgres' floor(extract(epoch ...)/86400)).
func RawLogRetentionHandover(retentionDays, rotateCount int, installedAt, now time.Time) int {
	if rotateCount <= retentionDays || retentionDays >= RawLogRetentionDaysMax {
		return retentionDays
	}
	bound := min(rotateCount, RawLogRetentionDaysMax)
	if !installedAt.IsZero() {
		ageDays := int(math.Floor(now.Sub(installedAt).Seconds() / 86400))
		bound = min(bound, ageDays+1)
	}
	return max(retentionDays, bound)
}

// CoerceRawLogImport repairs raw-log values a backup can carry but the
// server never accepts: zero values from backups written before a field
// existed, and raw_log_enabled=false (raw log files are mandatory since
// v2.17.1; the update handler coerces it the same way).
//
// A backup made before the archive columns existed (RawLogArchiveEnabled is
// nil) was also made before retention-by-days, so it gets the same one-time
// handover an upgrading install gets — bounded by the age of the install it
// is restored INTO (installedAt: that install's system_settings.created_at),
// since no older file can exist there.
func CoerceRawLogImport(ss *SystemSettingsExport, installedAt, now time.Time) {
	if ss == nil {
		return
	}
	ss.RawLogEnabled = true
	if ss.RawLogRetentionDays < RawLogRetentionDaysMin {
		ss.RawLogRetentionDays = RawLogRetentionDaysDefault
	}
	if ss.RawLogMaxSizeMB < 1 {
		ss.RawLogMaxSizeMB = RawLogMaxSizeMBDefault
	}
	if ss.RawLogRotateCount < RawLogRotateCountMin {
		ss.RawLogRotateCount = RawLogRotateCountDefault
	}
	if ss.RawLogArchiveEnabled == nil {
		ss.RawLogRetentionDays = RawLogRetentionHandover(ss.RawLogRetentionDays, ss.RawLogRotateCount, installedAt, now)
	}
	if ss.RawLogArchiveRetentionDays != nil && *ss.RawLogArchiveRetentionDays < RawLogArchiveRetentionDaysMin {
		v := RawLogArchiveRetentionDaysDefault
		ss.RawLogArchiveRetentionDays = &v
	}
}

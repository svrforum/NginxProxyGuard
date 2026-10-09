package scheduler

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"nginx-proxy-guard/internal/nginx"
)

// scheduledRotator is the part of nginx.Manager the scheduler drives.
type scheduledRotator interface {
	RotateLogsScheduled(ctx context.Context, force bool) (rotated bool, err error)
}

// LogRotateScheduler rotates the raw nginx logs at the top of every local
// hour: forced at 00:00, so every day gets its own file, and non-forced the
// rest of the day, which cuts a file only once it is past the size limit (or
// was not rotated yet today). There is no crond in the nginx container, so
// this is what enforces the size limit at all.
//
// It logs only when a file was cut or a run failed; an hourly "nothing to do"
// would drown the API's log. npg_raw_log_rotate_runs_total counts every run.
type LogRotateScheduler struct {
	stopCh   chan struct{}
	stopOnce sync.Once
	nginx    scheduledRotator
	// afterRotate runs after every hourly run, whatever its result — the raw
	// log archiver's wake-up. May be nil.
	afterRotate func()

	configMissingLogged bool
}

// NewLogRotateScheduler builds the scheduler. afterRotate may be nil.
func NewLogRotateScheduler(nginxManager *nginx.Manager, afterRotate func()) *LogRotateScheduler {
	s := &LogRotateScheduler{
		stopCh:      make(chan struct{}),
		afterRotate: afterRotate,
	}
	if nginxManager != nil { // a nil *Manager in the interface would not compare equal to nil
		s.nginx = nginxManager
	}
	return s
}

// nextRotationTick is the next local top of the hour after now, and whether
// that run is forced (it starts a new local day).
//
// It adds what is left of the current local hour instead of building the
// wall-clock time with time.Date: on a spring-forward day time.Date
// normalizes the missing 02:00 to 01:00, before now, and the loop would spin
// for half an hour; on a fall-back day it skips an hour. DST shifts happen on
// the hour, so the minutes left in the hour do not change across one, and
// +05:30 zones get their own :00. A zone that skips midnight itself still
// gets its forced run, on the first hour of the new day.
func nextRotationTick(now time.Time) (next time.Time, forced bool) {
	intoHour := time.Duration(now.Minute())*time.Minute +
		time.Duration(now.Second())*time.Second +
		time.Duration(now.Nanosecond())
	next = now.Add(time.Hour - intoHour)
	y1, m1, d1 := now.Date()
	y2, m2, d2 := next.Date()
	return next, next.Hour() == 0 || y1 != y2 || m1 != m2 || d1 != d2
}

func (s *LogRotateScheduler) Start() {
	log.Println("[LogRotateScheduler] Started (size/day check hourly, forced rotation at 00:00)")

	go func() {
		for {
			next, forced := nextRotationTick(time.Now())
			timer := time.NewTimer(time.Until(next))
			select {
			case <-timer.C:
			case <-s.stopCh:
				timer.Stop()
				log.Println("[LogRotateScheduler] Stopped")
				return
			}
			s.runOnce(context.Background(), forced)
		}
	}()
}

// Stop ends the loop. Safe to call more than once.
func (s *LogRotateScheduler) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// runOnce performs one scheduled run and then wakes afterRotate.
func (s *LogRotateScheduler) runOnce(ctx context.Context, forced bool) {
	if s.afterRotate != nil {
		defer s.afterRotate()
	}
	if s.nginx == nil {
		return
	}

	rotated, err := s.nginx.RotateLogsScheduled(ctx, forced)
	switch {
	case err == nil:
		s.configMissingLogged = false
		if rotated {
			if forced {
				log.Println("[LogRotateScheduler] Raw logs rotated (daily)")
			} else {
				log.Println("[LogRotateScheduler] Raw logs rotated (size limit or new day)")
			}
		}
	case errors.Is(err, nginx.ErrLogrotateConfigMissing):
		// Raw log files were never enabled. Say so once, not every hour.
		if !s.configMissingLogged {
			log.Println("[LogRotateScheduler] Logrotate config not found yet, skipping until it exists")
			s.configMissingLogged = true
		}
	case errors.Is(err, nginx.ErrLogrotateNothingToRotate):
		// Empty logs: nothing to cut, nothing to say.
	case errors.Is(err, nginx.ErrLogrotateAlreadyRotated), errors.Is(err, nginx.ErrLogrotateBusy):
		// A manual rotation in the same second, or one still running inside
		// the nginx container. Worth a line only for the daily cut.
		if forced {
			log.Printf("[LogRotateScheduler] Daily rotation skipped: %v", err)
		}
	default:
		log.Printf("[LogRotateScheduler] Logrotate failed: %v", err)
	}
}

package bootstrap

import (
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/scheduler"
)

// Schedulers bundles the background scheduler goroutines.
type Schedulers struct {
	Renewal       *scheduler.RenewalScheduler
	Partition     *scheduler.PartitionScheduler
	LogRotate     *scheduler.LogRotateScheduler
	Backup        *scheduler.BackupScheduler
	FilterRefresh *scheduler.FilterRefreshScheduler
}

// NewSchedulers constructs (but does not start) each scheduler.
func NewSchedulers(cfg *config.Config, db *database.DB, repos *Repositories, svcs *Services) *Schedulers {
	return &Schedulers{
		Renewal: scheduler.NewRenewalScheduler(
			repos.Certificate,
			svcs.Certificate,
			6*time.Hour,
			30,
		),
		Partition: scheduler.NewPartitionScheduler(
			db.DB,
			repos.SystemSettings,
			repos.SystemLog,
			repos.Dashboard,
		),
		LogRotate:     scheduler.NewLogRotateScheduler(),
		Backup:        scheduler.NewBackupScheduler(repos.Backup, repos.SystemSettings, cfg.BackupPath),
		FilterRefresh: scheduler.NewFilterRefreshScheduler(svcs.FilterSubscription),
	}
}

// Start launches every scheduler.
func (s *Schedulers) Start() {
	s.Renewal.Start()
	s.Partition.Start()
	s.LogRotate.Start()
	s.Backup.Start()
	s.FilterRefresh.Start()
}

// Stop signals every scheduler to stop.
func (s *Schedulers) Stop() {
	if s == nil {
		return
	}
	s.Renewal.Stop()
	s.Partition.Stop()
	s.FilterRefresh.Stop()
	// LogRotateScheduler and BackupScheduler also expose Stop, but the
	// original main.go did not call them on shutdown. Keep the original
	// semantics for minimal behavior change.
}

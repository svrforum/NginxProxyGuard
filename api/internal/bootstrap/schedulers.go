package bootstrap

import (
	"os"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/scheduler"
)

// Schedulers bundles the background scheduler goroutines.
type Schedulers struct {
	Renewal            *scheduler.RenewalScheduler
	Partition          *scheduler.PartitionScheduler
	LogRotate          *scheduler.LogRotateScheduler
	Backup             *scheduler.BackupScheduler
	FilterRefresh      *scheduler.FilterRefreshScheduler
	ContainerReconcile *scheduler.ContainerReconcileScheduler
	DDNS               *scheduler.DDNSScheduler
}

// ddnsInterval reads NPG_DDNS_INTERVAL (a Go duration string, e.g. "5m"); it
// falls back to config.DDNSCheckInterval when unset or invalid. (#154)
func ddnsInterval() time.Duration {
	const def = config.DDNSCheckInterval
	v := os.Getenv("NPG_DDNS_INTERVAL")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// containerReconcileInterval reads NPG_CONTAINER_RECONCILE_INTERVAL (a Go
// duration string, e.g. "30s", "2m"); it falls back to 30s when unset or
// invalid. (#150)
func containerReconcileInterval() time.Duration {
	const def = 30 * time.Second
	v := os.Getenv("NPG_CONTAINER_RECONCILE_INTERVAL")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
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
		ContainerReconcile: scheduler.NewContainerReconcileScheduler(
			svcs.ProxyHost,
			svcs.DockerStats,
			containerReconcileInterval(),
		),
		DDNS: scheduler.NewDDNSScheduler(svcs.DDNS, ddnsInterval()),
	}
}

// Start launches every scheduler.
func (s *Schedulers) Start() {
	s.Renewal.Start()
	s.Partition.Start()
	s.LogRotate.Start()
	s.Backup.Start()
	s.FilterRefresh.Start()
	s.ContainerReconcile.Start()
	s.DDNS.Start()
}

// Stop signals every scheduler to stop.
func (s *Schedulers) Stop() {
	if s == nil {
		return
	}
	s.Renewal.Stop()
	s.Partition.Stop()
	s.FilterRefresh.Stop()
	s.ContainerReconcile.Stop()
	s.DDNS.Stop()
	// LogRotateScheduler and BackupScheduler also expose Stop, but the
	// original main.go did not call them on shutdown. Keep the original
	// semantics for minimal behavior change.
}

package bootstrap

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// DiskGuard environment (D1-D4). Every knob is optional; the defaults are the
// shipped behaviour, and there is deliberately no UI setting (no
// system_settings column, no migration, nothing to back up).
//
//	NPG_DISK_GUARD_DISABLED=1          turn the whole guard off
//	NPG_DISK_GUARD_INTERVAL=1m         tick (minimum 15s)
//	NPG_DISK_WARN_PERCENT=85           disk.space_low
//	NPG_DISK_CRITICAL_PERCENT=90       disk.space_critical + emergency compression
//	NPG_DISK_RECOVER_PERCENT=80        disk.space_recovered
//	NPG_DISK_ALERT_COOLDOWN=6h         hold a new "low" this long after a recovery
//	NPG_DISK_EMERGENCY_COMPRESS=on     on | off | dryrun
//	NPG_DB_CONTAINER=                  database container name, when discovery fails
func diskGuardDisabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("NPG_DISK_GUARD_DISABLED")))
	return v == "1" || v == "true" || v == "yes"
}

func diskEnvFloat(key string, def float64) float64 {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		log.Printf("[DiskGuard] ignoring %s=%q: not a number", key, v)
	}
	return def
}

func diskEnvDuration(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		log.Printf("[DiskGuard] ignoring %s=%q: not a duration", key, v)
	}
	return def
}

func diskThresholdsFromEnv() service.DiskThresholds {
	t := service.DiskThresholds{
		Warn:     diskEnvFloat("NPG_DISK_WARN_PERCENT", service.DefaultDiskThresholds.Warn),
		Critical: diskEnvFloat("NPG_DISK_CRITICAL_PERCENT", service.DefaultDiskThresholds.Critical),
		Recover:  diskEnvFloat("NPG_DISK_RECOVER_PERCENT", service.DefaultDiskThresholds.Recover),
	}
	if !t.Valid() {
		d := service.DefaultDiskThresholds
		log.Printf("[DiskGuard] thresholds warn=%g critical=%g recover=%g are not 0 < recover < warn < critical < 100; using %g/%g/%g",
			t.Warn, t.Critical, t.Recover, d.Warn, d.Critical, d.Recover)
		return d
	}
	return t
}

// diskGuardInterval is NPG_DISK_GUARD_INTERVAL, floored by the scheduler.
func diskGuardInterval() time.Duration {
	return diskEnvDuration("NPG_DISK_GUARD_INTERVAL", time.Minute)
}

// diskEmergencyMode is NPG_DISK_EMERGENCY_COMPRESS; an unknown value is
// reported and treated as the default, on.
func diskEmergencyMode() service.EmergencyMode {
	v := os.Getenv("NPG_DISK_EMERGENCY_COMPRESS")
	mode, ok := service.ParseEmergencyMode(v)
	if !ok {
		log.Printf("[DiskGuard] ignoring NPG_DISK_EMERGENCY_COMPRESS=%q: use on, off or dryrun", v)
	}
	return mode
}

// newDiskUsageProvider measures the disks DiskGuard watches: the nginx log
// volume, the backups, Docker's storage, the database's disk through docker
// exec, and the raw-log archive (B6) as the archiver last measured it. DiskGuard
// never runs statfs on the archive itself: a hung NAS would freeze every disk
// alert with it.
func newDiskUsageProvider(cfg *config.Config, maint *repository.StorageMaintenanceRepository, archiver *service.RawLogArchiver) *service.HostUsageProvider {
	// The nginx log volume as the API mounts it. NGINX_ACCESS_LOG outside
	// /etc/nginx (the dev compose's /var/log/nginx) is not that volume.
	logsDir := "/etc/nginx/logs"
	if p := resolveAccessLogPath(); strings.HasPrefix(p, "/etc/nginx/") {
		logsDir = filepath.Dir(p)
	}
	provider := service.NewHostUsageProvider(logsDir, cfg.BackupPath, os.Getenv("NPG_DB_CONTAINER"), cfg.DatabaseURL,
		func(ctx context.Context) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return maint.DataDirectory(ctx)
		})
	provider.SetArchiveUsage(service.ArchiveUsageSource(archiver))
	return provider
}

// initDiskGuard builds DiskGuard and its emergency compressor and wires them
// into the stats collector and the dashboard. It reads the raw-log archive
// through svcs.RawLogArchiver, which must be built first. It leaves
// svcs.DiskGuard nil when the guard is disabled.
func initDiskGuard(cfg *config.Config, db *database.DB, repos *Repositories, svcs *Services) {
	if diskGuardDisabled() {
		log.Println("[DiskGuard] disabled by NPG_DISK_GUARD_DISABLED: no disk alerts and no storage warning on the dashboard")
		return
	}
	metrics.RegisterDiskMetrics()

	maint := repository.NewStorageMaintenanceRepository(db.DB)
	provider := newDiskUsageProvider(cfg, maint, svcs.RawLogArchiver)

	// Stopping the scheduler cancels this, which also ends an emergency pass
	// in flight: the chunk being compressed rolls back cleanly (verified).
	svcs.diskGuardCtx, svcs.diskGuardCancel = context.WithCancel(context.Background())
	emerg := service.NewEmergencyCompressor(svcs.diskGuardCtx, maint, provider.MeasureDB, diskEmergencyMode())
	emerg.SetSystemLog(func(level repository.SystemLogLevel, msg string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = repos.SystemLog.Create(ctx, &repository.SystemLog{
			Source: repository.SourceScheduler, Level: level, Message: msg, Component: "disk-guard",
		})
	})

	th := diskThresholdsFromEnv()
	svcs.DiskGuard = service.NewDiskGuard(provider, svcs.Notification, repos.Notification, repos.Dashboard,
		service.DiskGuardOptions{
			Thresholds:     th,
			ConfirmSamples: 2,
			Cooldown:       diskEnvDuration("NPG_DISK_ALERT_COOLDOWN", 6*time.Hour),
		})
	svcs.DiskGuard.SetEmergencyCompressor(emerg)
	svcs.StatsCollector.SetDiskSource(svcs.DiskGuard)
	svcs.Settings.SetDiskSource(svcs.DiskGuard)
	log.Printf("[DiskGuard] watching NPG's disks: warn %g%%, critical %g%%, recovered below %g%%, emergency compression %s",
		th.Warn, th.Critical, th.Recover, emerg.Mode())
}

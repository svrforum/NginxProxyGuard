package scheduler

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	"nginx-proxy-guard/internal/repository"
)

// PartitionScheduler manages log partitions and retention
type PartitionScheduler struct {
	db                 *sql.DB
	systemSettingsRepo *repository.SystemSettingsRepository
	systemLogRepo      *repository.SystemLogRepository
	interval           time.Duration
	stopCh             chan struct{}
}

func NewPartitionScheduler(
	db *sql.DB,
	systemSettingsRepo *repository.SystemSettingsRepository,
	systemLogRepo *repository.SystemLogRepository,
) *PartitionScheduler {
	return &PartitionScheduler{
		db:                 db,
		systemSettingsRepo: systemSettingsRepo,
		systemLogRepo:      systemLogRepo,
		interval:           24 * time.Hour, // Check daily
		stopCh:             make(chan struct{}),
	}
}

func (s *PartitionScheduler) Start() {
	log.Println("[PartitionScheduler] Started (checks daily at midnight for partitions and retention)")

	// Initial check on startup
	s.run()

	go func() {
		// Calculate time until next midnight
		now := time.Now()
		nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
		initialDelay := nextMidnight.Sub(now)

		log.Printf("[PartitionScheduler] Next run scheduled in %v (at midnight)", initialDelay)

		// Wait until midnight
		select {
		case <-time.After(initialDelay):
			s.run()
		case <-s.stopCh:
			return
		}

		// Then run daily
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.run()
			case <-s.stopCh:
				log.Println("[PartitionScheduler] Stopped")
				return
			}
		}
	}()
}

func (s *PartitionScheduler) Stop() {
	close(s.stopCh)
}

func (s *PartitionScheduler) run() {
	s.createPartitions()
	s.enforceRetention()
	s.cleanupLogsTable()
}

func (s *PartitionScheduler) createPartitions() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	// Create partitions for logs_partitioned (3 months ahead)
	_, err := s.db.ExecContext(ctx, `SELECT create_monthly_partitions('logs_partitioned', 'logs_p', 3)`)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to create log partitions: %v", err)
	}

	// Create partitions for dashboard_stats_hourly_partitioned (3 months ahead)
	_, err = s.db.ExecContext(ctx, `SELECT create_monthly_partitions('dashboard_stats_hourly_partitioned', 'stats_hourly_p', 3)`)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to create stats partitions: %v", err)
	}

	// Log partition statistics for monitoring
	s.logPartitionStats(ctx)
}

func (s *PartitionScheduler) logPartitionStats(ctx context.Context) {
	// Count log partitions
	var logPartitionCount int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM pg_tables
		WHERE tablename LIKE 'logs_p%' AND schemaname = 'public'
	`).Scan(&logPartitionCount)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to count log partitions: %v", err)
		return
	}

	// Count stats partitions
	var statsPartitionCount int
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM pg_tables
		WHERE tablename LIKE 'stats_hourly_p%' AND schemaname = 'public'
	`).Scan(&statsPartitionCount)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to count stats partitions: %v", err)
		return
	}

	// Check default partition sizes (should be empty if date ranges are correct)
	var logsDefaultSize int64
	_ = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(pg_total_relation_size('logs_p_default'), 0)
	`).Scan(&logsDefaultSize)

	log.Printf("[PartitionScheduler] Partition stats: logs=%d partitions, stats=%d partitions, logs_default_size=%d bytes",
		logPartitionCount, statsPartitionCount, logsDefaultSize)

	// Warn if default partition has data (indicates date range issues)
	if logsDefaultSize > 8192 { // More than just empty table overhead
		log.Printf("[PartitionScheduler] WARNING: logs_p_default partition has data (%d bytes) - check partition date ranges", logsDefaultSize)
	}
}

func (s *PartitionScheduler) enforceRetention() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// 1. Get current retention settings
	settings, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to get system settings for retention: %v", err)
		return
	}

	// 2. Cleanup System Logs (table system_logs)
	// Uses specific retention days from settings
	deleted, err := s.systemLogRepo.Cleanup(ctx, settings.SystemLogRetentionDays)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to cleanup system logs: %v", err)
	} else if deleted > 0 {
		log.Printf("[PartitionScheduler] Cleaned up %d old system logs (retention: %d days)", deleted, settings.SystemLogRetentionDays)
	}

	// 3. Drop old log partitions (logs_partitioned)
	// Access logs, Error logs, WAF logs share the same partitioned table.
	// We use the maximum retention period among them to be safe, or just AccessLogRetentionDays as it's the main volume.
	// Since partitions are monthly, we convert days to months.
	// Default to 1095 days (3 years) ~ 36 months if not set.
	logRetentionMonths := settings.AccessLogRetentionDays / 30
	if logRetentionMonths < 1 {
		logRetentionMonths = 1
	}

	var droppedLogs int
	err = s.db.QueryRowContext(ctx, `SELECT drop_old_partitions('logs_p', $1)`, logRetentionMonths).Scan(&droppedLogs)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to drop old log partitions: %v", err)
	} else if droppedLogs > 0 {
		log.Printf("[PartitionScheduler] Dropped %d old log partitions (retention: %d months)", droppedLogs, logRetentionMonths)
	}

	// 4. Drop old stats partitions (dashboard_stats_hourly_partitioned)
	statsRetentionMonths := settings.StatsRetentionDays / 30
	if statsRetentionMonths < 1 {
		statsRetentionMonths = 1
	}

	var droppedStats int
	err = s.db.QueryRowContext(ctx, `SELECT drop_old_partitions('stats_hourly_p', $1)`, statsRetentionMonths).Scan(&droppedStats)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to drop old stats partitions: %v", err)
	} else if droppedStats > 0 {
		log.Printf("[PartitionScheduler] Dropped %d old stats partitions (retention: %d months)", droppedStats, statsRetentionMonths)
	}
}

// cleanupLogsTable deletes old records from the legacy non-partitioned logs table
// This is only needed for upgrades from older versions that had the logs table
func (s *PartitionScheduler) cleanupLogsTable() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Check if legacy logs table exists
	var exists bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'logs'
		)
	`).Scan(&exists)
	if err != nil || !exists {
		return // No legacy logs table, nothing to clean up
	}

	settings, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to get system settings for logs cleanup: %v", err)
		return
	}

	retentionDays := settings.AccessLogRetentionDays
	if retentionDays <= 0 {
		retentionDays = 1825 // Default 5 years
	}

	// Delete old logs in batches to avoid long-running transactions
	batchSize := 10000
	totalDeleted := int64(0)

	for {
		result, err := s.db.ExecContext(ctx, `
			DELETE FROM logs
			WHERE id IN (
				SELECT id FROM logs
				WHERE timestamp < NOW() - ($1 || ' days')::INTERVAL
				LIMIT $2
			)
		`, retentionDays, batchSize)

		if err != nil {
			// Table might have been dropped by migration, silently return
			if strings.Contains(err.Error(), "does not exist") {
				return
			}
			log.Printf("[PartitionScheduler] Failed to cleanup logs table: %v", err)
			return
		}

		deleted, _ := result.RowsAffected()
		totalDeleted += deleted

		if deleted < int64(batchSize) {
			break // No more rows to delete
		}

		// Small delay to reduce database load
		time.Sleep(100 * time.Millisecond)
	}

	if totalDeleted > 0 {
		log.Printf("[PartitionScheduler] Cleaned up %d old logs from legacy logs table (retention: %d days)", totalDeleted, retentionDays)
	}
}

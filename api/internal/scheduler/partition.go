package scheduler

import (
	"context"
	"database/sql"
	"fmt"
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
	dashboardRepo      *repository.DashboardRepository
	interval           time.Duration
	stopCh             chan struct{}
}

func NewPartitionScheduler(
	db *sql.DB,
	systemSettingsRepo *repository.SystemSettingsRepository,
	systemLogRepo *repository.SystemLogRepository,
	dashboardRepo *repository.DashboardRepository,
) *PartitionScheduler {
	return &PartitionScheduler{
		db:                 db,
		systemSettingsRepo: systemSettingsRepo,
		systemLogRepo:      systemLogRepo,
		dashboardRepo:      dashboardRepo,
		interval:           24 * time.Hour, // Check daily
		stopCh:             make(chan struct{}),
	}
}

func (s *PartitionScheduler) Start() {
	log.Println("[PartitionScheduler] Started (checks daily at midnight for partitions and retention)")

	go func() {
		// Run initial check in background (non-blocking to avoid delaying server startup)
		s.run()

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
	s.cleanupDashboardStats()
}

func (s *PartitionScheduler) cleanupDashboardStats() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	settings, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to get system settings for dashboard stats cleanup: %v", err)
		return
	}

	hourlyRetention := settings.StatsRetentionDays
	if hourlyRetention <= 0 {
		hourlyRetention = 90
	}
	dailyRetention := hourlyRetention * 2

	if err := s.dashboardRepo.CleanupOldStats(ctx, hourlyRetention, dailyRetention); err != nil {
		log.Printf("[PartitionScheduler] Failed to cleanup dashboard stats: %v", err)
	} else {
		log.Printf("[PartitionScheduler] Cleaned up dashboard stats (hourly retention: %d days, daily retention: %d days)", hourlyRetention, dailyRetention)
	}
}

func (s *PartitionScheduler) createPartitions() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create partitions for current month and next 2 months
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		target := now.AddDate(0, i, 0)
		year := target.Year()
		month := target.Month()

		partName := fmt.Sprintf("logs_p%d_%02d", year, int(month))
		startDate := fmt.Sprintf("%d-%02d-01", year, int(month))

		nextMonth := target.AddDate(0, 1, 0)
		endDate := fmt.Sprintf("%d-%02d-01", nextMonth.Year(), int(nextMonth.Month()))

		query := fmt.Sprintf(`
			DO $$ BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM pg_tables
					WHERE schemaname = 'public' AND tablename = '%s'
				) THEN
					CREATE TABLE IF NOT EXISTS %s PARTITION OF logs_partitioned
						FOR VALUES FROM ('%s') TO ('%s');
					RAISE NOTICE 'Created partition %s';
				END IF;
			END $$;
		`, partName, partName, startDate, endDate, partName)

		if _, err := s.db.ExecContext(ctx, query); err != nil {
			log.Printf("[PartitionScheduler] Failed to create partition %s: %v", partName, err)
		} else {
			log.Printf("[PartitionScheduler] Ensured partition exists: %s (%s to %s)", partName, startDate, endDate)
		}
	}

	// Migrate data from logs_p_default to proper partitions
	var defaultExists bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM pg_tables
			WHERE tablename = 'logs_p_default' AND schemaname = 'public'
		)
	`).Scan(&defaultExists)
	if err != nil {
		log.Printf("[PartitionScheduler] Failed to check logs_p_default existence: %v", err)
	} else if defaultExists {
		var defaultCount int64
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM logs_p_default`).Scan(&defaultCount)
		if defaultCount > 0 {
			// Create partitions for all months that have data in the default partition
			rows, qErr := s.db.QueryContext(ctx, `
				SELECT DISTINCT date_trunc('month', created_at) FROM logs_p_default
			`)
			if qErr == nil {
				for rows.Next() {
					var monthStart time.Time
					if rows.Scan(&monthStart) == nil {
						pn := fmt.Sprintf("logs_p%d_%02d", monthStart.Year(), int(monthStart.Month()))
						ed := monthStart.AddDate(0, 1, 0)
						s.db.ExecContext(ctx, fmt.Sprintf(`
							DO $$ BEGIN
								IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename='%s') THEN
									CREATE TABLE IF NOT EXISTS %s PARTITION OF logs_partitioned
										FOR VALUES FROM ('%s') TO ('%s');
								END IF;
							END $$;
						`, pn, pn, monthStart.Format("2006-01-02"), ed.Format("2006-01-02")))
					}
				}
				rows.Close()
			}
			log.Printf("[PartitionScheduler] Found %d rows in logs_p_default, migrating to proper partitions...", defaultCount)
			totalMoved := int64(0)
			for {
				result, err := s.db.ExecContext(ctx, `
					WITH moved AS (
						DELETE FROM logs_p_default
						WHERE id IN (SELECT id FROM logs_p_default LIMIT 10000)
						RETURNING *
					)
					INSERT INTO logs_partitioned SELECT * FROM moved
				`)
				if err != nil {
					log.Printf("[PartitionScheduler] Failed to migrate batch from logs_p_default: %v", err)
					break
				}
				n, _ := result.RowsAffected()
				totalMoved += n
				log.Printf("[PartitionScheduler] Migrated %d rows from logs_p_default (total: %d)", n, totalMoved)
				if n < 10000 {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			log.Printf("[PartitionScheduler] Finished migrating %d rows from logs_p_default", totalMoved)
		}
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
	// Note: logs_p_default may not exist if logs_partitioned is a TimescaleDB hypertable
	var logsDefaultExists bool
	err = s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM pg_tables
			WHERE tablename = 'logs_p_default' AND schemaname = 'public'
		)
	`).Scan(&logsDefaultExists)

	var logsDefaultSize int64
	if err == nil && logsDefaultExists {
		_ = s.db.QueryRowContext(ctx, `
			SELECT COALESCE(pg_total_relation_size('logs_p_default'), 0)
		`).Scan(&logsDefaultSize)
	}

	log.Printf("[PartitionScheduler] Partition stats: logs=%d partitions, stats=%d partitions, logs_default_size=%d bytes",
		logPartitionCount, statsPartitionCount, logsDefaultSize)

	// Warn if default partition has data (indicates date range issues)
	// Only applicable when using native PostgreSQL partitioning (not TimescaleDB)
	if logsDefaultExists && logsDefaultSize > 8192 { // More than just empty table overhead
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

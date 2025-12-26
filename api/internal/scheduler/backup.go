package scheduler

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/robfig/cron/v3"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// BackupScheduler handles automatic backups based on cron schedule
type BackupScheduler struct {
	backupRepo       *repository.BackupRepository
	systemSettings   *repository.SystemSettingsRepository
	backupPath       string
	cronScheduler    *cron.Cron
	currentEntryID   cron.EntryID
	currentSchedule  string
	wasEnabled       bool  // Track if auto backup was previously enabled
	stopChan         chan struct{}
	running          bool
}

// NewBackupScheduler creates a new backup scheduler
func NewBackupScheduler(
	backupRepo *repository.BackupRepository,
	systemSettings *repository.SystemSettingsRepository,
	backupPath string,
) *BackupScheduler {
	return &BackupScheduler{
		backupRepo:     backupRepo,
		systemSettings: systemSettings,
		backupPath:     backupPath,
		cronScheduler:  cron.New(),
		stopChan:       make(chan struct{}),
	}
}

// Start begins the backup scheduler
func (s *BackupScheduler) Start() {
	if s.running {
		return
	}
	s.running = true

	// Start the cron scheduler
	s.cronScheduler.Start()

	// Initial schedule setup
	s.updateSchedule()

	// Monitor for schedule changes every minute
	go s.monitorSettings()

	log.Println("[BackupScheduler] Auto backup scheduler started")
}

// RunNow triggers an immediate backup (for testing or manual trigger)
func (s *BackupScheduler) RunNow() {
	go s.runBackup()
}

// Stop stops the backup scheduler
func (s *BackupScheduler) Stop() {
	if !s.running {
		return
	}
	s.cronScheduler.Stop()
	close(s.stopChan)
	s.running = false
	log.Println("[BackupScheduler] Auto backup scheduler stopped")
}

// monitorSettings checks for settings changes periodically
func (s *BackupScheduler) monitorSettings() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.updateSchedule()
		case <-s.stopChan:
			return
		}
	}
}

// updateSchedule updates the cron schedule based on current settings
func (s *BackupScheduler) updateSchedule() {
	ctx := context.Background()

	settings, err := s.systemSettings.Get(ctx)
	if err != nil {
		log.Printf("[BackupScheduler] Failed to get settings: %v", err)
		return
	}

	// If auto backup is disabled, remove any existing schedule
	if !settings.AutoBackupEnabled {
		if s.currentEntryID != 0 {
			s.cronScheduler.Remove(s.currentEntryID)
			s.currentEntryID = 0
			s.currentSchedule = ""
			log.Println("[BackupScheduler] Auto backup disabled, schedule removed")
		}
		s.wasEnabled = false
		return
	}

	// Check if auto backup was just enabled (transition from disabled to enabled)
	justEnabled := !s.wasEnabled && settings.AutoBackupEnabled
	s.wasEnabled = true

	// Get schedule, default to "0 2 * * *" (daily at 2 AM)
	schedule := settings.AutoBackupSchedule
	if schedule == "" {
		schedule = "0 2 * * *"
	}

	// If schedule hasn't changed and wasn't just enabled, do nothing
	if schedule == s.currentSchedule && !justEnabled {
		return
	}

	// Remove old schedule if exists
	if s.currentEntryID != 0 {
		s.cronScheduler.Remove(s.currentEntryID)
	}

	// Add new schedule
	entryID, err := s.cronScheduler.AddFunc(schedule, s.runBackup)
	if err != nil {
		log.Printf("[BackupScheduler] Invalid cron schedule '%s': %v", schedule, err)
		return
	}

	s.currentEntryID = entryID
	s.currentSchedule = schedule

	// Log the next scheduled run time
	entries := s.cronScheduler.Entries()
	for _, entry := range entries {
		if entry.ID == entryID {
			log.Printf("[BackupScheduler] Auto backup schedule updated: %s (next run: %s)", schedule, entry.Next.Format("2006-01-02 15:04:05"))
			break
		}
	}

	// Run immediate backup when auto backup is first enabled
	if justEnabled {
		log.Println("[BackupScheduler] Auto backup just enabled, running immediate backup...")
		go s.runBackup()
	}
}

// runBackup performs the actual backup
func (s *BackupScheduler) runBackup() {
	ctx := context.Background()
	log.Println("[BackupScheduler] Starting scheduled backup...")

	// Get retention settings
	settings, err := s.systemSettings.Get(ctx)
	if err != nil {
		log.Printf("[BackupScheduler] Failed to get settings: %v", err)
		return
	}

	// Double check auto backup is still enabled
	if !settings.AutoBackupEnabled {
		log.Println("[BackupScheduler] Auto backup disabled, skipping")
		return
	}

	// Ensure backup directory exists
	if err := os.MkdirAll(s.backupPath, 0755); err != nil {
		log.Printf("[BackupScheduler] Failed to create backup directory: %v", err)
		return
	}

	// Create backup record
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("nginx_guard_auto_backup_%s.tar.gz", timestamp)
	filePath := filepath.Join(s.backupPath, filename)

	backup := &model.Backup{
		Filename:             filename,
		FilePath:             filePath,
		IncludesConfig:       true,
		IncludesCertificates: true,
		IncludesDatabase:     true,
		BackupType:           "auto",
		Description:          "Automated scheduled backup",
		Status:               "in_progress",
	}

	backup, err = s.backupRepo.Create(ctx, backup)
	if err != nil {
		log.Printf("[BackupScheduler] Failed to create backup record: %v", err)
		return
	}

	// Perform the backup
	if err := s.performBackup(ctx, backup); err != nil {
		log.Printf("[BackupScheduler] Backup failed: %v", err)
		s.backupRepo.UpdateStatus(ctx, backup.ID, "failed", err.Error())
		return
	}

	log.Printf("[BackupScheduler] Backup completed successfully: %s", filename)

	// Clean up old backups based on retention count
	retentionCount := settings.BackupRetentionCount
	if retentionCount <= 0 {
		retentionCount = 10 // Default retention
	}
	s.cleanupOldBackups(ctx, retentionCount)
}

// performBackup creates the actual backup file
func (s *BackupScheduler) performBackup(ctx context.Context, backup *model.Backup) error {
	// Create tar.gz file
	file, err := os.Create(backup.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}

	gzWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzWriter)

	// Export database data
	if backup.IncludesDatabase {
		exportData, err := s.backupRepo.ExportAllData(ctx)
		if err != nil {
			tarWriter.Close()
			gzWriter.Close()
			file.Close()
			os.Remove(backup.FilePath)
			return fmt.Errorf("failed to export database: %w", err)
		}

		dataJSON, _ := json.MarshalIndent(exportData, "", "  ")
		header := &tar.Header{
			Name:    "data/export.json",
			Mode:    0644,
			Size:    int64(len(dataJSON)),
			ModTime: time.Now(),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			tarWriter.Close()
			gzWriter.Close()
			file.Close()
			os.Remove(backup.FilePath)
			return fmt.Errorf("failed to write tar header: %w", err)
		}
		if _, err := tarWriter.Write(dataJSON); err != nil {
			tarWriter.Close()
			gzWriter.Close()
			file.Close()
			os.Remove(backup.FilePath)
			return fmt.Errorf("failed to write export data: %w", err)
		}
	}

	// Add config files
	if backup.IncludesConfig {
		if err := s.addDirectoryToTar(tarWriter, "/etc/nginx/conf.d", "config/conf.d"); err != nil {
			log.Printf("[BackupScheduler] Warning: failed to add config files: %v", err)
		}
	}

	// Add certificates
	if backup.IncludesCertificates {
		if err := s.addDirectoryToTar(tarWriter, "/etc/nginx/certs", "certs"); err != nil {
			log.Printf("[BackupScheduler] Warning: failed to add certificates: %v", err)
		}
	}

	// Close writers in order to flush all data
	tarWriter.Close()
	gzWriter.Close()
	file.Close()

	// Calculate checksum from completed file
	checksum := ""
	if file, err := os.Open(backup.FilePath); err == nil {
		hasher := sha256.New()
		io.Copy(hasher, file)
		checksum = hex.EncodeToString(hasher.Sum(nil))
		file.Close()
	}

	// Get file size
	var fileSize int64
	if fileInfo, err := os.Stat(backup.FilePath); err == nil {
		fileSize = fileInfo.Size()
	}

	// Update backup record
	return s.backupRepo.Complete(ctx, backup.ID, fileSize, checksum)
}

// addDirectoryToTar adds a directory and its contents to the tar archive
func (s *BackupScheduler) addDirectoryToTar(tw *tar.Writer, srcDir, destPrefix string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		// Get relative path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return nil
		}

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil
		}

		header.Name = filepath.Join(destPrefix, relPath)

		if err := tw.WriteHeader(header); err != nil {
			return nil
		}

		// If it's a file, copy its contents
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return nil
			}
		}

		return nil
	})
}

// cleanupOldBackups removes old auto backups beyond the retention count
func (s *BackupScheduler) cleanupOldBackups(ctx context.Context, retentionCount int) {
	// Get all auto backups sorted by creation time (newest first)
	backups, err := s.backupRepo.ListByType(ctx, "auto")
	if err != nil {
		log.Printf("[BackupScheduler] Failed to list backups for cleanup: %v", err)
		return
	}

	// Sort by created_at descending (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	// Delete backups beyond retention count
	if len(backups) > retentionCount {
		toDelete := backups[retentionCount:]
		for _, backup := range toDelete {
			// Delete the file
			if err := os.Remove(backup.FilePath); err != nil && !os.IsNotExist(err) {
				log.Printf("[BackupScheduler] Failed to delete backup file %s: %v", backup.FilePath, err)
			}

			// Delete the record
			if err := s.backupRepo.Delete(ctx, backup.ID); err != nil {
				log.Printf("[BackupScheduler] Failed to delete backup record %s: %v", backup.ID, err)
			} else {
				log.Printf("[BackupScheduler] Deleted old backup: %s", backup.Filename)
			}
		}
	}
}

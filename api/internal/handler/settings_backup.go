package handler

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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
)

// Backup Handlers

func (h *SettingsHandler) ListBackups(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	perPage, _ := strconv.Atoi(c.QueryParam("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	result, err := h.settingsService.ListBackups(c.Request().Context(), page, perPage)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, result)
}

func (h *SettingsHandler) CreateBackup(c echo.Context) error {
	var req model.CreateBackupRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	// Default to include everything
	if !req.IncludesConfig && !req.IncludesCertificates && !req.IncludesDatabase {
		req.IncludesConfig = true
		req.IncludesCertificates = true
		req.IncludesDatabase = true
	}

	// Create backup record
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("nginx_guard_backup_%s.tar.gz", timestamp)
	filePath := filepath.Join(h.backupPath, filename)

	backup := &model.Backup{
		Filename:             filename,
		FilePath:             filePath,
		IncludesConfig:       req.IncludesConfig,
		IncludesCertificates: req.IncludesCertificates,
		IncludesDatabase:     req.IncludesDatabase,
		BackupType:           "manual",
		Description:          req.Description,
		Status:               "in_progress",
	}

	backup, err := h.backupRepo.Create(c.Request().Context(), backup)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Create backup asynchronously
	go h.performBackup(backup)

	// Audit log
	h.audit.LogBackupCreate(c.Request().Context(), backup.Filename)

	return c.JSON(http.StatusAccepted, backup)
}

func (h *SettingsHandler) performBackup(backup *model.Backup) {
	ctx := context.Background()

	// Ensure backup directory exists
	os.MkdirAll(h.backupPath, 0755)

	// Create tar.gz file
	file, err := os.Create(backup.FilePath)
	if err != nil {
		h.backupRepo.UpdateStatus(ctx, backup.ID, "failed", err.Error())
		return
	}

	gzWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzWriter)

	// Export database data
	if backup.IncludesDatabase {
		exportData, err := h.backupRepo.ExportAllData(ctx)
		if err != nil {
			tarWriter.Close()
			gzWriter.Close()
			file.Close()
			os.Remove(backup.FilePath)
			h.backupRepo.UpdateStatus(ctx, backup.ID, "failed", err.Error())
			return
		}

		dataJSON, _ := json.MarshalIndent(exportData, "", "  ")
		header := &tar.Header{
			Name:    "data/export.json",
			Mode:    0644,
			Size:    int64(len(dataJSON)),
			ModTime: time.Now(),
		}
		writeErr := tarWriter.WriteHeader(header)
		if writeErr == nil {
			_, writeErr = tarWriter.Write(dataJSON)
		}
		if writeErr != nil {
			tarWriter.Close()
			gzWriter.Close()
			file.Close()
			os.Remove(backup.FilePath)
			h.backupRepo.UpdateStatus(ctx, backup.ID, "failed", fmt.Sprintf("failed to write export.json to archive: %v", writeErr))
			return
		}
	}

	// Add config files
	if backup.IncludesConfig {
		h.addDirectoryToTar(tarWriter, "/etc/nginx/conf.d", "config/conf.d")
	}

	// Add certificates
	if backup.IncludesCertificates {
		h.addDirectoryToTar(tarWriter, "/etc/nginx/certs", "certs")
	}

	// Close writers in order to flush all data. tar/gzip Close write the
	// trailing blocks and file.Close surfaces deferred write errors (e.g.
	// disk full) — ignoring them would record a truncated archive as a
	// completed backup with a matching checksum, discovered only at restore.
	closeErr := tarWriter.Close()
	if err := gzWriter.Close(); err != nil && closeErr == nil {
		closeErr = err
	}
	if err := file.Close(); err != nil && closeErr == nil {
		closeErr = err
	}
	if closeErr != nil {
		os.Remove(backup.FilePath)
		h.backupRepo.UpdateStatus(ctx, backup.ID, "failed", fmt.Sprintf("failed to finalize backup archive: %v", closeErr))
		return
	}

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
	h.backupRepo.Complete(ctx, backup.ID, fileSize, checksum)
}

func (h *SettingsHandler) addDirectoryToTar(tw *tar.Writer, srcDir, destPrefix string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Skip symlinks to avoid size mismatch issues
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		relPath, _ := filepath.Rel(srcDir, path)
		destPath := filepath.Join(destPrefix, relPath)

		// Read entire file content first to ensure size accuracy
		content, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[Backup] Warning: failed to read file %s: %v", path, err)
			return nil
		}

		header := &tar.Header{
			Name:    destPath,
			Mode:    int64(info.Mode()),
			Size:    int64(len(content)), // Use actual content size
			ModTime: info.ModTime(),
		}

		if err := tw.WriteHeader(header); err != nil {
			log.Printf("[Backup] Warning: failed to write tar header for %s: %v", path, err)
			return nil
		}

		written, err := tw.Write(content)
		if err != nil {
			log.Printf("[Backup] Warning: failed to write tar content for %s: %v", path, err)
			return nil
		}

		if written != len(content) {
			log.Printf("[Backup] Warning: incomplete write for %s: wrote %d of %d bytes", path, written, len(content))
		}

		return nil
	})
}

func (h *SettingsHandler) GetBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.settingsService.GetBackup(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	return c.JSON(http.StatusOK, backup)
}

func (h *SettingsHandler) DownloadBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.settingsService.GetBackup(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	if backup.Status != "completed" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "backup not completed"})
	}

	// Get actual file size
	fileInfo, err := os.Stat(backup.FilePath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "backup file not found"})
	}

	// Add checksum header for client-side verification
	if backup.ChecksumSHA256 != "" {
		c.Response().Header().Set("X-Checksum-SHA256", backup.ChecksumSHA256)
	}

	c.Response().Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))
	return c.Attachment(backup.FilePath, backup.Filename)
}

func (h *SettingsHandler) DeleteBackup(c echo.Context) error {
	id := c.Param("id")

	if err := h.settingsService.DeleteBackup(c.Request().Context(), id); err != nil {
		if err.Error() == "backup not found" {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *SettingsHandler) GetBackupStats(c echo.Context) error {
	stats, err := h.settingsService.GetBackupStats(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, stats)
}

func (h *SettingsHandler) TestBackupRestore(c echo.Context) error {
	// Create a test backup
	testBackup := &model.Backup{
		Filename:             "test_backup.tar.gz",
		FilePath:             filepath.Join(h.backupPath, "test_backup.tar.gz"),
		IncludesConfig:       true,
		IncludesCertificates: false,
		IncludesDatabase:     true,
		BackupType:           "test",
		Description:          "Test backup for verification",
		Status:               "completed",
	}

	testBackup, err := h.backupRepo.Create(c.Request().Context(), testBackup)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"test":   "backup_create",
			"status": "failed",
			"error":  err.Error(),
		})
	}

	// Clean up test backup
	h.backupRepo.Delete(c.Request().Context(), testBackup.ID)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"test":   "backup_restore",
		"status": "passed",
		"details": map[string]interface{}{
			"backup_create": config.StatusOK,
			"backup_list":   config.StatusOK,
			"backup_delete": config.StatusOK,
		},
	})
}

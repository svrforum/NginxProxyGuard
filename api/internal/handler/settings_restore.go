package handler

import (
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
	"strings"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/model"
)

func (h *SettingsHandler) RestoreBackup(c echo.Context) error {
	id := c.Param("id")

	backup, err := h.backupRepo.GetByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	if backup == nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "backup not found"})
	}

	if backup.Status != "completed" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "backup not completed"})
	}

	// Perform restore and get detailed result
	result, err := h.performRestore(c.Request().Context(), backup)
	if err != nil {
		// Critical failure - return error response with partial result if available
		response := map[string]interface{}{
			"error":   "restore failed",
			"details": err.Error(),
		}
		if result != nil {
			response["result"] = result
		}
		return c.JSON(http.StatusInternalServerError, response)
	}

	// Audit log
	h.audit.LogBackupRestore(c.Request().Context(), backup.Filename)

	// Return detailed result with appropriate HTTP status
	httpStatus := http.StatusOK
	if result.Status == "partial" {
		httpStatus = http.StatusPartialContent // HTTP 206
	}

	return c.JSON(httpStatus, result)
}

func (h *SettingsHandler) performRestore(ctx context.Context, backup *model.Backup) (*model.RestoreResult, error) {
	result := model.NewRestoreResult()

	// Verify checksum before restore if available
	if backup.ChecksumSHA256 != "" {
		if err := h.verifyBackupChecksum(backup.FilePath, backup.ChecksumSHA256); err != nil {
			result.Status = "failed"
			result.Message = "Backup integrity check failed"
			return result, fmt.Errorf("backup integrity check failed: %w", err)
		}
	}

	// PHASE 1: Read and import database data FIRST
	// This ensures DB is consistent before touching any files
	var exportData *model.ExportData
	if backup.IncludesDatabase {
		data, err := h.extractExportJSON(backup.FilePath)
		if err != nil {
			result.DatabaseError = err.Error()
			result.DetermineStatus()
			return result, fmt.Errorf("failed to read export.json: %w", err)
		}
		if data != nil {
			exportData = &model.ExportData{}
			if err := json.Unmarshal(data, exportData); err != nil {
				result.DatabaseError = err.Error()
				result.DetermineStatus()
				return result, fmt.Errorf("failed to parse export.json: %w", err)
			}
			// Import database data first - if this fails, no files are touched
			if err := h.backupRepo.ImportAllData(ctx, exportData); err != nil {
				result.DatabaseError = err.Error()
				result.DetermineStatus()
				return result, fmt.Errorf("failed to import database data: %w", err)
			}
			result.DatabaseRestored = true
			log.Printf("[Backup] Database import completed successfully")
		}
	}

	// PHASE 2: Restore files only after DB import succeeds
	filesRestored, fileErrors := h.restoreFilesFromBackupDetailed(backup)
	result.FilesRestored = filesRestored
	result.FileErrors = fileErrors
	if len(fileErrors) > 0 {
		log.Printf("[Backup] Warning: file restoration had %d errors", len(fileErrors))
	}

	// Regenerate nginx configs from restored database
	if h.nginxManager != nil {
		// Create certificate symlinks for new IDs pointing to existing cert files
		if h.certificateRepo != nil {
			certs, _, err := h.certificateRepo.List(ctx, 1, 1000, "", "", "", "", "")
			if err != nil {
				log.Printf("[Backup] Warning: failed to list certificates: %v", err)
			} else {
				certsPath := h.nginxManager.GetCertsPath()
				for _, cert := range certs {
					// Check if certificate_path references a different directory than the new ID
					if cert.CertificatePath != nil && *cert.CertificatePath != "" {
						// Extract the original ID from the path (e.g., /etc/nginx/certs/{orig_id}/fullchain.pem)
						pathParts := strings.Split(*cert.CertificatePath, "/")
						if len(pathParts) >= 2 {
							origID := pathParts[len(pathParts)-2]
							newIDPath := filepath.Join(certsPath, cert.ID)
							origIDPath := filepath.Join(certsPath, origID)

							// Create symlink if original path exists and new path doesn't
							if origID != cert.ID {
								if _, err := os.Stat(origIDPath); err == nil {
									if _, err := os.Stat(newIDPath); os.IsNotExist(err) {
										if err := os.Symlink(origIDPath, newIDPath); err != nil {
											log.Printf("[Backup] Warning: failed to create cert symlink %s -> %s: %v", newIDPath, origIDPath, err)
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Regenerate Proxy Host configs with safe error handling
		if h.proxyHostRepo != nil {
			proxyHosts, _, err := h.proxyHostRepo.List(ctx, 1, 1000, "", "", "")
			if err != nil {
				log.Printf("[Backup] Warning: failed to list proxy hosts for config regeneration: %v", err)
			} else {
				result.ProxyHostsTotal = len(proxyHosts)
				// Generate configs one by one so we can handle failures gracefully
				for _, host := range proxyHosts {
					// Use BuildConfigData to include all related settings (GeoRestriction, RateLimit, BotFilter, etc.)
					configData, err := h.proxyHostService.BuildConfigData(ctx, &host)
					if err != nil {
						log.Printf("[Backup] Warning: failed to load config data for host %s: %v", host.ID, err)
						result.ProxyHostsFailed = append(result.ProxyHostsFailed, host.ID)
						continue
					}
					if err := h.nginxManager.GenerateConfigFull(ctx, configData); err != nil {
						log.Printf("[Backup] Warning: failed to regenerate config for host %s: %v", host.ID, err)
						result.ProxyHostsFailed = append(result.ProxyHostsFailed, host.ID)
						continue
					}
					// Generate WAF config if enabled
					if host.WAFEnabled {
						// Get merged WAF exclusions (host + global) from database
						exclusions := h.getMergedWAFExclusions(ctx, host.ID)
						// Get Priority Allow IPs from configData
						var allowedIPs []string
						if configData.GeoRestriction != nil {
							allowedIPs = configData.GeoRestriction.AllowedIPs
						}
						if err := h.nginxManager.GenerateHostWAFConfig(ctx, &host, exclusions, allowedIPs); err != nil {
							log.Printf("[Backup] Warning: failed to regenerate WAF config for host %s: %v", host.ID, err)
							// Remove the main config if WAF config fails
							_ = h.nginxManager.RemoveConfig(ctx, &host)
							result.ProxyHostsFailed = append(result.ProxyHostsFailed, host.ID)
							continue
						}
					}
					result.ProxyHostsSuccess++
				}
			}
		}

		// Regenerate Redirect Host configs
		if h.redirectHostRepo != nil {
			redirectHosts, _, err := h.redirectHostRepo.List(ctx, 1, 1000)
			if err != nil {
				log.Printf("[Backup] Warning: failed to list redirect hosts for config regeneration: %v", err)
			} else {
				result.RedirectHostsTotal = len(redirectHosts)
				if err := h.nginxManager.GenerateAllRedirectConfigs(ctx, redirectHosts); err != nil {
					log.Printf("[Backup] Warning: failed to regenerate redirect host configs: %v", err)
					for _, rh := range redirectHosts {
						result.RedirectHostsFailed = append(result.RedirectHostsFailed, rh.ID)
					}
				} else {
					result.RedirectHostsSuccess = len(redirectHosts)
				}
			}
		}

		// Test nginx config before reload
		if err := h.nginxManager.TestConfig(ctx); err != nil {
			log.Printf("[Backup] ERROR: nginx config test failed: %v", err)
			result.NginxConfigValid = false
			result.NginxConfigError = err.Error()
			log.Printf("[Backup] Attempting to remove failed host configs and retry...")

			// Remove configs for failed hosts
			for _, hostID := range result.ProxyHostsFailed {
				configFile := filepath.Join("/etc/nginx/conf.d", fmt.Sprintf("proxy_host_%s.conf", hostID))
				if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
					log.Printf("[Backup] Warning: failed to remove config for host %s: %v", hostID, err)
				}
			}

			// Test again after removing failed configs
			if err := h.nginxManager.TestConfig(ctx); err != nil {
				log.Printf("[Backup] ERROR: nginx config test still failing after cleanup: %v", err)
				log.Printf("[Backup] nginx reload skipped to prevent container issues")
				result.NginxConfigValid = false
				result.NginxConfigError = err.Error()
				result.DetermineStatus()
				// Return partial success instead of silently ignoring the error
				return result, nil
			}
			// Config test passed after cleanup
			result.NginxConfigValid = true
			result.NginxConfigError = ""
		}

		// Reload nginx only if config test passes
		if err := h.nginxManager.ReloadNginx(ctx); err != nil {
			log.Printf("[Backup] Warning: failed to reload nginx after restore: %v", err)
			result.NginxReloaded = false
			result.NginxReloadError = err.Error()
		} else {
			log.Printf("[Backup] nginx reloaded successfully")
			result.NginxReloaded = true
		}
	}

	result.DetermineStatus()
	return result, nil
}

// UploadAndRestoreBackup handles backup file upload and restore
func (h *SettingsHandler) UploadAndRestoreBackup(c echo.Context) error {
	// Get uploaded file
	file, err := c.FormFile("backup")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "backup file required"})
	}

	// Validate file extension
	if !strings.HasSuffix(file.Filename, ".tar.gz") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid file format, expected .tar.gz"})
	}

	// Open uploaded file
	src, err := file.Open()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to read uploaded file"})
	}
	defer src.Close()

	// Ensure backup directory exists
	os.MkdirAll(h.backupPath, 0755)

	// Save to backup directory
	destPath := filepath.Join(h.backupPath, file.Filename)
	dst, err := os.Create(destPath)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save backup file"})
	}

	// Calculate checksum while copying
	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)
	size, err := io.Copy(writer, src)
	dst.Close()

	if err != nil {
		os.Remove(destPath)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to save backup file"})
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))

	// Create backup record
	backup := &model.Backup{
		Filename:             file.Filename,
		FilePath:             destPath,
		FileSize:             size,
		IncludesConfig:       true,
		IncludesCertificates: true,
		IncludesDatabase:     true,
		BackupType:           "uploaded",
		Description:          "Uploaded backup for restore",
		Status:               "completed",
		ChecksumSHA256:       checksum,
	}

	backup, err = h.backupRepo.Create(c.Request().Context(), backup)
	if err != nil {
		os.Remove(destPath)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to create backup record"})
	}

	// Perform restore and get detailed result
	result, err := h.performRestore(c.Request().Context(), backup)
	if err != nil {
		response := map[string]interface{}{
			"error":   "restore failed",
			"details": err.Error(),
		}
		if result != nil {
			response["result"] = result
		}
		return c.JSON(http.StatusInternalServerError, response)
	}

	// Audit log
	h.audit.LogBackupRestore(c.Request().Context(), backup.Filename)

	// Determine HTTP status based on result
	httpStatus := http.StatusOK
	if result.Status == "partial" {
		httpStatus = http.StatusPartialContent
	}

	return c.JSON(httpStatus, map[string]interface{}{
		"status":  result.Status,
		"message": result.Message,
		"backup":  backup,
		"result":  result,
	})
}

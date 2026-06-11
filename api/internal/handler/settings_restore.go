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

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/pkg/acme"
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
	var certIDMap map[string]string // old backup cert ID -> newly generated ID
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
			certIDMap, err = h.backupRepo.ImportAllData(ctx, exportData)
			if err != nil {
				result.DatabaseError = err.Error()
				result.DetermineStatus()
				return result, fmt.Errorf("failed to import database data: %w", err)
			}
			result.DatabaseRestored = true
			log.Printf("[Backup] Database import completed successfully")
			// The raw-SQL import bypasses the repositories' per-write cache
			// invalidation — flush Valkey caches so reads don't serve
			// pre-restore data for the remainder of the cache TTL.
			h.invalidateCachesAfterImport(ctx)
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
		// Materialize certificate files from the PEMs carried in export.json.
		// Database-only backups have no cert files in the archive, so without
		// this every SSL host would silently fall back to HTTP-only on a
		// fresh server even though the key material is in the database.
		if exportData != nil && len(certIDMap) > 0 {
			certsPath := h.nginxManager.GetCertsPath()
			for _, cert := range exportData.Certificates {
				if cert.Status != model.CertStatusIssued || cert.CertificatePEM == "" || cert.PrivateKeyPEM == "" {
					continue
				}
				newID, ok := certIDMap[cert.ID]
				if !ok {
					continue
				}
				certDir, err := safeJoinUnderBase(certsPath, newID)
				if err != nil {
					log.Printf("[Backup] Warning: skipping cert file materialization for %s: %v", newID, err)
					continue
				}
				fullchainPath := filepath.Join(certDir, "fullchain.pem")
				privkeyPath := filepath.Join(certDir, "privkey.pem")
				// Skip if a prior materialization (e.g. a re-run of restore) already
				// wrote files under this new ID. Archive-restored PEMs land under
				// the ORIGINAL ID and are served via the symlink path below, so this
				// Stat only guards re-runs, not the archive case.
				if _, err := os.Stat(fullchainPath); err == nil {
					continue
				}
				if err := os.MkdirAll(certDir, 0755); err != nil {
					log.Printf("[Backup] Warning: failed to create cert directory for %s: %v", newID, err)
					continue
				}
				// Write privkey first, fullchain last. The nginx config generator
				// keys its SSL-existence check on fullchain.pem alone, so if
				// fullchain were written first and privkey then failed, SSL would
				// be enabled pointing at a missing key. On a fullchain failure we
				// also remove the orphan privkey so a partial materialization can
				// never present a keyless cert.
				if err := os.WriteFile(privkeyPath, []byte(cert.PrivateKeyPEM), 0600); err != nil {
					log.Printf("[Backup] Warning: failed to write privkey.pem for cert %s: %v", newID, err)
					continue
				}
				fullchain := acme.BuildFullchain(cert.CertificatePEM, cert.IssuerCertificatePEM)
				if err := os.WriteFile(fullchainPath, []byte(fullchain), 0644); err != nil {
					log.Printf("[Backup] Warning: failed to write fullchain.pem for cert %s: %v", newID, err)
					_ = os.Remove(privkeyPath)
					continue
				}
				log.Printf("[Backup] Materialized certificate files for %s from backup data", newID)
			}
		}

		// Create certificate symlinks for new IDs pointing to existing cert files
		if h.certificateRepo != nil {
			certs, _, err := h.certificateRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "", "", "")
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
							// certificate_path comes from untrusted backup JSON —
							// enforce containment under certsPath (and reject
							// segments like "..", "." or "") before symlinking.
							origIDPath, pathErr := safeJoinUnderBase(certsPath, origID)
							if pathErr != nil || origIDPath == filepath.Clean(certsPath) {
								log.Printf("[Backup] Warning: skipping cert symlink for %s: unsafe path segment %q in backup", cert.ID, origID)
								continue
							}

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

		// Regenerate Proxy Host configs with safe error handling.
		// failedHosts keeps the full host structs so the -t failure cleanup
		// below can derive the real (domain-based) config filenames.
		var failedHosts []model.ProxyHost
		if h.proxyHostRepo != nil {
			proxyHosts, _, err := h.proxyHostRepo.List(ctx, 1, config.MaxWAFRulesLimit, "", "", "")
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
						failedHosts = append(failedHosts, host)
						continue
					}
					if err := h.nginxManager.GenerateConfigFull(ctx, configData); err != nil {
						log.Printf("[Backup] Warning: failed to regenerate config for host %s: %v", host.ID, err)
						result.ProxyHostsFailed = append(result.ProxyHostsFailed, host.ID)
						failedHosts = append(failedHosts, host)
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
							failedHosts = append(failedHosts, host)
							continue
						}
					}
					result.ProxyHostsSuccess++
				}
			}
		}

		// Regenerate Redirect Host configs
		if h.redirectHostRepo != nil {
			redirectHosts, _, err := h.redirectHostRepo.List(ctx, 1, config.MaxWAFRulesLimit)
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

			// Remove configs for failed hosts. RemoveConfig derives the real
			// (domain-based) config filename and also covers stream hosts and
			// leftover WAF configs — an ID-based filename guess never matches
			// the files actually written for normal hosts.
			for i := range failedHosts {
				if err := h.nginxManager.RemoveConfig(ctx, &failedHosts[i]); err != nil {
					log.Printf("[Backup] Warning: failed to remove config for host %s: %v", failedHosts[i].ID, err)
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

// invalidateCachesAfterImport flushes the Valkey caches that could otherwise
// serve pre-restore data after ImportAllData's raw-SQL import (which bypasses
// the repositories' per-write invalidation). Per-ID caches (certificate, geo,
// bot filter) need no flush: import recreates every row with a new UUID, so
// the stale entries are keyed by IDs nothing references anymore. Singleton
// and namespace caches are the ones that go stale.
func (h *SettingsHandler) invalidateCachesAfterImport(ctx context.Context) {
	if h.redisCache == nil {
		return
	}
	_ = h.redisCache.InvalidateSystemSettings(ctx)
	_ = h.redisCache.InvalidateGlobalSettings(ctx)
	_ = h.redisCache.InvalidateExploitRules(ctx)
	_ = h.redisCache.InvalidateAllExploitExclusions(ctx)
	_ = h.redisCache.InvalidateAllProxyHostConfigs(ctx)
	_ = h.redisCache.InvalidateAllURIBlocks(ctx)
	log.Printf("[Backup] Valkey caches invalidated after database import")
}

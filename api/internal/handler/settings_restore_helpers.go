package handler

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"nginx-proxy-guard/internal/model"
)

// safeJoinUnderBase joins relPath onto base and verifies the result stays
// within base, blocking path-traversal entries (e.g. "../conf.d/evil.conf")
// in untrusted backup archives. Returns the cleaned destination path or an
// error if it escapes base.
func safeJoinUnderBase(base, relPath string) (string, error) {
	cleanBase := filepath.Clean(base)
	dest := filepath.Clean(filepath.Join(cleanBase, relPath))
	if dest != cleanBase && !strings.HasPrefix(dest, cleanBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal blocked: %q escapes %q", relPath, cleanBase)
	}
	return dest, nil
}

// secureFileMode returns the permission bits to use when restoring a backup
// entry, ignoring the (untrusted) archive header mode. Private keys are forced
// to 0600 so they are never restored world-readable; everything else is 0644.
func secureFileMode(destPath string) os.FileMode {
	base := filepath.Base(destPath)
	if base == "privkey.pem" || strings.HasSuffix(base, ".key") {
		return 0600
	}
	return 0644
}

// restoreRootDir is the only filesystem subtree backup files may be written
// into. Both config (conf.d) and certificate restores live under it.
const restoreRootDir = "/etc/nginx"

// chmodFile applies mode to an already-open file. It is a package-level
// variable only so tests can force the chmod failure that restoreFileAtomic
// has to survive without damaging the destination.
var chmodFile = func(f *os.File, mode os.FileMode) error { return f.Chmod(mode) }

func (h *SettingsHandler) extractFile(tarReader *tar.Reader, destPath string, header *tar.Header) error {
	// Defense-in-depth: reject any destination that escapes the nginx tree,
	// even if a caller forgot to sanitize the relative path (path traversal).
	cleanDest := filepath.Clean(destPath)
	if cleanDest != restoreRootDir && !strings.HasPrefix(cleanDest, restoreRootDir+string(os.PathSeparator)) {
		return fmt.Errorf("path traversal blocked: %q escapes %q", destPath, restoreRootDir)
	}

	return restoreFileAtomic(tarReader, destPath, header.Size)
}

// restoreFileAtomic writes size bytes from src to destPath without ever
// truncating destPath first: the bytes go into a temporary file in the same
// directory, which is then renamed over the destination. The destination is
// touched only by that final rename, so every failure path leaves the previous
// file byte-for-byte intact.
//
// This ordering is load-bearing. The API container runs with cap_drop ALL +
// cap_add DAC_OVERRIDE, so it may write files it does not own — but chmod on a
// file owned by another uid needs CAP_FOWNER, which is dropped, and
// certs/default-selfsigned.{crt,key} are owned by the nginx container's uid
// 101. The previous open(O_TRUNC)-then-chmod order therefore emptied those two
// files and returned the chmod error before copying a single byte, leaving
// 0-byte certificates that break `nginx -t` for the whole proxy.
//
// Writing into a temp file we own keeps the security guarantee (the mode from
// secureFileMode is applied before any bytes land, so a restored private key is
// never world-readable, not even briefly) because chmod on our own file always
// succeeds. Renaming over a file owned by someone else only needs write+search
// on the directory, which DAC_OVERRIDE grants — the cert/conf.d dirs are mode
// 755 and not sticky, so no CAP_FOWNER is involved.
func restoreFileAtomic(src io.Reader, destPath string, size int64) error {
	destDir := filepath.Dir(destPath)

	// Ensure parent directory exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	// Remove existing symlink or file if it exists
	if info, err := os.Lstat(destPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			// It's a symlink, remove it
			os.Remove(destPath)
		} else if info.IsDir() {
			// It's a directory, skip (don't overwrite directories)
			return nil
		}
	}

	// Force secure permissions regardless of the archive header mode so
	// restored private keys are never world-readable.
	mode := secureFileMode(destPath)

	// Same directory as the destination => same filesystem => atomic rename.
	// The dot prefix and .tmp suffix keep a leftover from ever being mistaken
	// for a real certificate, and os.CreateTemp's random suffix keeps
	// concurrent restores from colliding.
	tmpFile, err := os.CreateTemp(destDir, ".npg-restore-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	renamed := false
	defer func() {
		tmpFile.Close() // no-op after the explicit Close on the success path
		if !renamed {
			os.Remove(tmpPath)
		}
	}()

	// os.CreateTemp always creates with 0600, so apply the restore policy mode
	// explicitly. This file is ours, so a failure here is a real one — and it
	// still leaves the destination untouched.
	if err := chmodFile(tmpFile, mode); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	// Use LimitReader to read exactly the expected amount
	written, err := io.Copy(tmpFile, io.LimitReader(src, size))
	if err != nil {
		return fmt.Errorf("copy error after %d bytes (expected %d): %w", written, size, err)
	}

	if written != size {
		return fmt.Errorf("size mismatch: wrote %d bytes, expected %d", written, size)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	renamed = true

	return nil
}

// extractExportJSON reads only the export.json from a backup file
func (h *SettingsHandler) extractExportJSON(backupPath string) ([]byte, error) {
	file, err := os.Open(backupPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry: %w", err)
		}

		if header.Name == "data/export.json" {
			return io.ReadAll(tarReader)
		}
	}

	return nil, nil // No export.json found
}

// restoreFilesFromBackup restores config and certificate files from backup
func (h *SettingsHandler) restoreFilesFromBackup(backup *model.Backup) error {
	file, err := os.Open(backup.FilePath)
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var restoreErrors []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		// Skip directories and symlinks
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			continue
		}

		// Skip entries with zero size (likely directories without proper type flag)
		if header.Size == 0 {
			continue
		}

		// Skip export.json (already processed in phase 1)
		if header.Name == "data/export.json" {
			continue
		}

		switch {
		case filepath.Dir(header.Name) == "config/conf.d":
			// Restore config files
			if backup.IncludesConfig && !strings.HasSuffix(header.Name, "/") {
				destPath := filepath.Join("/etc/nginx/conf.d", filepath.Base(header.Name))
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("config %s: %v", header.Name, err))
				}
			}

		case filepath.HasPrefix(header.Name, "certs/"):
			// Restore certificates
			if backup.IncludesCertificates && !strings.HasSuffix(header.Name, "/") && strings.Contains(filepath.Base(header.Name), ".") {
				relPath := header.Name[6:] // Remove "certs/" prefix
				// Block path traversal (e.g. "certs/../conf.d/evil.conf").
				// Cert layout is always certs/<id>/<file>, so only safe segments.
				destPath, err := safeJoinUnderBase("/etc/nginx/certs", relPath)
				if err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("cert %s: %v", header.Name, err))
					continue
				}
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("cert %s: %v", header.Name, err))
				}
			}
		}
	}

	if len(restoreErrors) > 0 {
		return fmt.Errorf("file restore errors: %v", restoreErrors)
	}

	return nil
}

// restoreFilesFromBackupDetailed restores files and returns detailed results
func (h *SettingsHandler) restoreFilesFromBackupDetailed(backup *model.Backup) (int, []string) {
	file, err := os.Open(backup.FilePath)
	if err != nil {
		return 0, []string{fmt.Sprintf("failed to open backup file: %v", err)}
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return 0, []string{fmt.Sprintf("failed to create gzip reader: %v", err)}
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var restoreErrors []string
	var filesRestored int

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			restoreErrors = append(restoreErrors, fmt.Sprintf("tar read error: %v", err))
			break
		}

		// Skip directories, symlinks, zero-size entries, export.json
		if header.Typeflag == tar.TypeDir || header.Typeflag == tar.TypeSymlink ||
			header.Typeflag == tar.TypeLink || header.Size == 0 ||
			header.Name == "data/export.json" {
			continue
		}

		switch {
		case filepath.Dir(header.Name) == "config/conf.d":
			if backup.IncludesConfig && !strings.HasSuffix(header.Name, "/") {
				destPath := filepath.Join("/etc/nginx/conf.d", filepath.Base(header.Name))
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("config %s: %v", header.Name, err))
				} else {
					filesRestored++
				}
			}

		case filepath.HasPrefix(header.Name, "certs/"):
			if backup.IncludesCertificates && !strings.HasSuffix(header.Name, "/") &&
				strings.Contains(filepath.Base(header.Name), ".") {
				relPath := header.Name[6:]
				// Block path traversal (e.g. "certs/../conf.d/evil.conf").
				// Cert layout is always certs/<id>/<file>, so only safe segments.
				destPath, err := safeJoinUnderBase("/etc/nginx/certs", relPath)
				if err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("cert %s: %v", header.Name, err))
					continue
				}
				if err := h.extractFile(tarReader, destPath, header); err != nil {
					restoreErrors = append(restoreErrors, fmt.Sprintf("cert %s: %v", header.Name, err))
				} else {
					filesRestored++
				}
			}
		}
	}

	return filesRestored, restoreErrors
}

// verifyBackupChecksum verifies the SHA256 checksum of a backup file
func (h *SettingsHandler) verifyBackupChecksum(filePath, expectedChecksum string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for checksum verification: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// getMergedWAFExclusions returns merged WAF exclusions (host-specific + global)
// This is used during backup restore to regenerate WAF configs correctly
func (h *SettingsHandler) getMergedWAFExclusions(ctx context.Context, hostID string) []model.WAFRuleExclusion {
	if h.wafRepo == nil {
		return nil
	}

	// Get host-specific exclusions
	hostExclusions, err := h.wafRepo.GetExclusionsByProxyHost(ctx, hostID)
	if err != nil {
		log.Printf("[Backup] Warning: failed to get host WAF exclusions for %s: %v", hostID, err)
		hostExclusions = nil
	}

	// Get global exclusions
	globalExclusions, err := h.wafRepo.GetGlobalExclusions(ctx)
	if err != nil {
		log.Printf("[Backup] Warning: failed to get global WAF exclusions: %v", err)
		return hostExclusions // Return host-only if global fails
	}

	// Create a map of host exclusions to avoid duplicates
	hostExclusionMap := make(map[int]bool)
	for _, ex := range hostExclusions {
		hostExclusionMap[ex.RuleID] = true
	}

	// Merge: start with host exclusions
	merged := make([]model.WAFRuleExclusion, len(hostExclusions))
	copy(merged, hostExclusions)

	// Add global exclusions that are not already in host exclusions
	for _, gex := range globalExclusions {
		if !hostExclusionMap[gex.RuleID] {
			merged = append(merged, model.WAFRuleExclusion{
				ID:              gex.ID,
				ProxyHostID:     "global",
				RuleID:          gex.RuleID,
				RuleCategory:    gex.RuleCategory,
				RuleDescription: gex.RuleDescription,
				Reason:          gex.Reason + " (global)",
				DisabledBy:      gex.DisabledBy,
				CreatedAt:       gex.CreatedAt,
			})
		}
	}

	return merged
}

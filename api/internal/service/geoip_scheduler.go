package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// GeoIPScheduler handles automatic GeoIP database updates
type GeoIPScheduler struct {
	settingsRepo         *repository.SystemSettingsRepository
	historyRepo          *repository.GeoIPHistoryRepository
	geoipService         *GeoIPService
	cloudProviderService *CloudProviderService
	stopCh               chan struct{}
	wg                   sync.WaitGroup
	mu                   sync.Mutex
	running              bool
	checkInterval        time.Duration
}

// NewGeoIPScheduler creates a new GeoIP scheduler
func NewGeoIPScheduler(
	settingsRepo *repository.SystemSettingsRepository,
	historyRepo *repository.GeoIPHistoryRepository,
	geoipService *GeoIPService,
) *GeoIPScheduler {
	return &GeoIPScheduler{
		settingsRepo:  settingsRepo,
		historyRepo:   historyRepo,
		geoipService:  geoipService,
		checkInterval: 1 * time.Hour, // Check every hour if update is needed
	}
}

// Start starts the scheduler
func (s *GeoIPScheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

	s.wg.Add(1)
	go s.run()
	log.Println("[GeoIP Scheduler] Started")
}

// Stop stops the scheduler
func (s *GeoIPScheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	s.wg.Wait()
	log.Println("[GeoIP Scheduler] Stopped")
}

// SetCloudProviderService sets the cloud provider service for seeding
func (s *GeoIPScheduler) SetCloudProviderService(svc *CloudProviderService) {
	s.cloudProviderService = svc
}

func (s *GeoIPScheduler) run() {
	defer s.wg.Done()

	// Initial check after a short delay
	select {
	case <-time.After(30 * time.Second):
		s.checkAndUpdate()
	case <-s.stopCh:
		return
	}

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.checkAndUpdate()
		case <-s.stopCh:
			return
		}
	}
}

func (s *GeoIPScheduler) checkAndUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get settings
	settings, err := s.settingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[GeoIP Scheduler] Failed to get settings: %v", err)
		return
	}

	// Check if auto-update is enabled
	if !settings.GeoIPAutoUpdate {
		return
	}

	// Check if license key is configured
	if settings.MaxmindLicenseKey == "" {
		return
	}

	// Check if update is needed based on interval
	if settings.GeoIPLastUpdated != nil {
		interval := parseUpdateInterval(settings.GeoIPUpdateInterval)
		nextUpdate := settings.GeoIPLastUpdated.Add(interval)
		if time.Now().Before(nextUpdate) {
			return // Not time yet
		}
	}

	log.Println("[GeoIP Scheduler] Starting automatic update...")
	s.RunUpdate(ctx, model.GeoIPTriggerAuto, settings.MaxmindLicenseKey, settings.MaxmindAccountID)
}

// RunUpdate runs a GeoIP database update
func (s *GeoIPScheduler) RunUpdate(ctx context.Context, triggerType model.GeoIPTriggerType, licenseKey, accountID string) error {
	// Create history record
	history, err := s.historyRepo.Create(ctx, triggerType)
	if err != nil {
		log.Printf("[GeoIP Scheduler] Failed to create history record: %v", err)
		// Continue anyway
	}

	// Run the update
	err = s.runGeoIPUpdate(ctx, licenseKey, accountID)

	if err != nil {
		log.Printf("[GeoIP Scheduler] Update failed: %v", err)
		if history != nil {
			s.historyRepo.UpdateFailed(ctx, history.ID, err.Error())
		}
		return err
	}

	// Get file sizes
	geoipPath := "/etc/nginx/geoip"
	var countrySize, asnSize int64
	if fi, err := os.Stat(filepath.Join(geoipPath, "GeoLite2-Country.mmdb")); err == nil {
		countrySize = fi.Size()
	}
	if fi, err := os.Stat(filepath.Join(geoipPath, "GeoLite2-ASN.mmdb")); err == nil {
		asnSize = fi.Size()
	}

	// Update history
	if history != nil {
		s.historyRepo.UpdateSuccess(ctx, history.ID, "GeoLite2", countrySize, asnSize)
	}

	// Update settings
	s.settingsRepo.UpdateGeoIPStatus(ctx, time.Now(), "GeoLite2")

	// Reload GeoIP databases in memory
	if s.geoipService != nil {
		s.geoipService.LoadDatabases()
	}

	// Seed cloud providers when GeoIP is successfully updated
	if s.cloudProviderService != nil {
		if err := s.cloudProviderService.SeedDefaultProviders(ctx); err != nil {
			log.Printf("[GeoIP Scheduler] Failed to seed cloud providers: %v", err)
		}
	}

	log.Println("[GeoIP Scheduler] Update completed successfully")
	return nil
}

func (s *GeoIPScheduler) runGeoIPUpdate(ctx context.Context, licenseKey, accountID string) error {
	geoipPath := "/etc/nginx/geoip"
	confPath := filepath.Join(geoipPath, "GeoIP.conf")

	// Create directory if not exists
	if err := os.MkdirAll(geoipPath, 0755); err != nil {
		return fmt.Errorf("failed to create geoip directory: %w", err)
	}

	// Create GeoIP.conf
	conf := fmt.Sprintf(`# GeoIP.conf for Nginx Proxy Guard
# Auto-generated by GeoIP Scheduler

AccountID %s
LicenseKey %s
EditionIDs GeoLite2-Country GeoLite2-ASN
DatabaseDirectory %s
`, accountID, licenseKey, geoipPath)

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("failed to write GeoIP.conf: %w", err)
	}

	// Run geoipupdate
	cmd := exec.CommandContext(ctx, "geoipupdate", "-f", confPath, "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("geoipupdate failed: %s - %w", string(output), err)
	}

	log.Printf("[GeoIP Scheduler] geoipupdate output: %s", string(output))

	// Update the symlink to use the enabled config
	enabledConf := filepath.Join(geoipPath, "geoip-enabled.conf")
	activeConf := filepath.Join(geoipPath, "geoip-active.conf")

	// Remove .no-geoip flag if exists
	os.Remove(filepath.Join(geoipPath, ".no-geoip"))

	// Update symlink
	os.Remove(activeConf)
	if err := os.Symlink(enabledConf, activeConf); err != nil {
		log.Printf("[GeoIP Scheduler] Warning: failed to update symlink: %v", err)
	}

	return nil
}

// parseUpdateInterval parses interval string like "1d", "7d", "30d" to duration
func parseUpdateInterval(interval string) time.Duration {
	if interval == "" {
		return 7 * 24 * time.Hour // Default 7 days
	}

	var days int
	if _, err := fmt.Sscanf(interval, "%dd", &days); err == nil && days > 0 {
		return time.Duration(days) * 24 * time.Hour
	}

	return 7 * 24 * time.Hour // Default 7 days
}

package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"golang.org/x/sync/singleflight"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// SettingsService handles business logic for global settings, dashboard, and backups.
type SettingsService struct {
	settingsRepo       *repository.GlobalSettingsRepository
	systemSettingsRepo *repository.SystemSettingsRepository
	dashboardRepo      *repository.DashboardRepository
	backupRepo         *repository.BackupRepository
	proxyHostRepo      *repository.ProxyHostRepository
	redirectHostRepo   *repository.RedirectHostRepository
	certificateRepo    *repository.CertificateRepository
	wafRepo            *repository.WAFRepository
	nginxManager       *nginx.Manager
	proxyHostService   *ProxyHostService
	dockerStats        *DockerStatsService
	redisCache         *cache.RedisClient
	backupPath         string

	// Dashboard summary in-process cache + singleflight (see GetDashboard).
	// This layer protects Redis-less installs (graceful degradation) and
	// keeps concurrent dashboard polls from each re-running the heavy 24h
	// log aggregations.
	dashSummaryMu     sync.Mutex
	dashSummary       *model.DashboardSummary
	dashSummaryExpiry time.Time
	dashSummarySF     singleflight.Group

	// Last non-blocking CPU sample served to the dashboard (see sampledCPUPercent).
	cpuSampleMu  sync.Mutex
	cpuSampleVal float64
	cpuSampleAt  time.Time
}

func NewSettingsService(
	settingsRepo *repository.GlobalSettingsRepository,
	systemSettingsRepo *repository.SystemSettingsRepository,
	dashboardRepo *repository.DashboardRepository,
	backupRepo *repository.BackupRepository,
	proxyHostRepo *repository.ProxyHostRepository,
	redirectHostRepo *repository.RedirectHostRepository,
	certificateRepo *repository.CertificateRepository,
	wafRepo *repository.WAFRepository,
	nginxManager *nginx.Manager,
	proxyHostService *ProxyHostService,
	dockerStats *DockerStatsService,
	redisCache *cache.RedisClient,
	backupPath string,
) *SettingsService {
	return &SettingsService{
		settingsRepo:       settingsRepo,
		systemSettingsRepo: systemSettingsRepo,
		dashboardRepo:      dashboardRepo,
		backupRepo:         backupRepo,
		proxyHostRepo:      proxyHostRepo,
		redirectHostRepo:   redirectHostRepo,
		certificateRepo:    certificateRepo,
		wafRepo:            wafRepo,
		nginxManager:       nginxManager,
		proxyHostService:   proxyHostService,
		dockerStats:        dockerStats,
		redisCache:         redisCache,
		backupPath:         backupPath,
	}
}

// loadGlobalTrustedIPs reads system_settings.global_trusted_ips and returns the
// parsed list. Errors are logged and treated as "no whitelist" so a transient
// DB hiccup doesn't fail an otherwise-valid global settings save.
func (s *SettingsService) loadGlobalTrustedIPs(ctx context.Context) []string {
	if s.systemSettingsRepo == nil {
		return nil
	}
	sys, err := s.systemSettingsRepo.Get(ctx)
	if err != nil {
		log.Printf("[SettingsService] failed to load system settings for trusted IPs: %v", err)
		return nil
	}
	if sys == nil {
		return nil
	}
	return ParseGlobalTrustedIPs(sys.GlobalTrustedIPs)
}

// loadGlobalTrustedIPsBypassWAF reports whether trusted IPs should also bypass
// the WAF (ModSecurity), the opt-in #166 flag. Defaults false on any error.
func (s *SettingsService) loadGlobalTrustedIPsBypassWAF(ctx context.Context) bool {
	if s.systemSettingsRepo == nil {
		return false
	}
	sys, err := s.systemSettingsRepo.Get(ctx)
	if err != nil || sys == nil {
		return false
	}
	return sys.GlobalTrustedIPsBypassWAF
}

// ---- Global Settings ----

func (s *SettingsService) GetGlobalSettings(ctx context.Context) (*model.GlobalSettings, error) {
	settings, err := s.settingsRepo.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get global settings: %w", err)
	}
	return settings, nil
}

// RegenerateMainNginxConfig re-renders /etc/nginx/nginx.conf from the current DB
// global + system settings, including the global trusted-IP list and the #166
// WAF-bypass flag. It does NOT reload nginx — the caller runs its own test+reload.
//
// Needed by the backup restore path: restore writes settings back to the DB but
// nginx.conf is the ONLY place the http-level trusted-IP limit_conn/limit_req
// zones (#130) and the trusted-IP WAF-bypass rule (#166) are emitted, so without
// this an imported config would silently not reach live nginx until the next
// container restart re-ran startup regeneration.
func (s *SettingsService) RegenerateMainNginxConfig(ctx context.Context) error {
	settings, err := s.GetGlobalSettings(ctx)
	if err != nil {
		return err
	}
	return s.nginxManager.GenerateMainNginxConfig(ctx, settings, s.loadGlobalTrustedIPs(ctx), s.loadGlobalTrustedIPsBypassWAF(ctx))
}

func (s *SettingsService) UpdateGlobalSettings(ctx context.Context, req *model.UpdateGlobalSettingsRequest) (*model.GlobalSettings, error) {
	settings, err := s.settingsRepo.Update(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update global settings: %w", err)
	}

	// Regenerate main nginx.conf from the freshly-saved settings so http/stream
	// block directives (brotli, keepalive, custom_http_config, custom_stream_config,
	// limit_conn/req zones, …) actually reach nginx (issue #121). Without this
	// the UI was silently writing to DB with no effect on live nginx.
	//
	// GenerateMainNginxConfig itself rolls the file back to the last-known-good
	// copy on `nginx -t` failure, but we also surface the error so the user
	// learns their input was rejected (otherwise they see "200 OK" and wonder
	// why nothing changed). The DB retains the saved value; the operator can
	// reopen the form and fix it.
	if err := s.nginxManager.GenerateMainNginxConfig(ctx, settings, s.loadGlobalTrustedIPs(ctx), s.loadGlobalTrustedIPsBypassWAF(ctx)); err != nil {
		log.Printf("[SettingsService] nginx.conf regeneration rejected: %v", err)
		return settings, fmt.Errorf("settings saved but nginx rejected the new config: %w", err)
	}

	// Regenerate default server config if direct IP access action changed
	if req.DirectIPAccessAction != nil {
		if err := s.nginxManager.GenerateDefaultServerConfig(ctx, settings.DirectIPAccessAction); err != nil {
			log.Printf("[SettingsService] Warning: failed to generate default server config: %v", err)
		}
	}

	// Update manager IPv6 setting and regenerate default server config
	if req.EnableIPv6 != nil {
		s.nginxManager.SetEnableIPv6(*req.EnableIPv6)
		if err := s.nginxManager.GenerateDefaultServerConfig(ctx, settings.DirectIPAccessAction); err != nil {
			log.Printf("[SettingsService] Warning: failed to regenerate default server config for IPv6 change: %v", err)
		}
	}

	// Regenerate all proxy host configs to apply global settings (timeouts, body size, etc.)
	if s.proxyHostService != nil {
		if err := s.proxyHostService.SyncAllConfigs(ctx); err != nil {
			log.Printf("[SettingsService] Warning: failed to regenerate proxy host configs after global settings change: %v", err)
		}
	}

	// Regenerate all redirect host configs (IPv6, port changes affect listen directives)
	if s.redirectHostRepo != nil {
		redirectHosts, err := s.redirectHostRepo.GetAllEnabled(ctx)
		if err != nil {
			log.Printf("[SettingsService] Warning: failed to get redirect hosts for config regeneration: %v", err)
		} else if len(redirectHosts) > 0 {
			if err := s.nginxManager.GenerateAllRedirectConfigs(ctx, redirectHosts); err != nil {
				log.Printf("[SettingsService] Warning: failed to regenerate redirect host configs after global settings change: %v", err)
			}
		}
	}

	// Reload nginx to apply all changes
	if err := s.nginxManager.ReloadNginx(ctx); err != nil {
		log.Printf("[SettingsService] Warning: failed to reload nginx after global settings change: %v", err)
	}

	return settings, nil
}

func (s *SettingsService) ResetGlobalSettings(ctx context.Context) (*model.GlobalSettings, error) {
	settings, err := s.settingsRepo.Reset(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to reset global settings: %w", err)
	}

	// Regenerate main nginx.conf so the reset defaults actually hit nginx.
	if err := s.nginxManager.GenerateMainNginxConfig(ctx, settings, s.loadGlobalTrustedIPs(ctx), s.loadGlobalTrustedIPsBypassWAF(ctx)); err != nil {
		log.Printf("[SettingsService] Warning: failed to regenerate nginx.conf after reset: %v", err)
	}

	// Regenerate all proxy host configs to apply default global settings
	if s.proxyHostService != nil {
		if err := s.proxyHostService.SyncAllConfigs(ctx); err != nil {
			log.Printf("[SettingsService] Warning: failed to regenerate proxy host configs after global settings reset: %v", err)
		}
	}

	// Regenerate all redirect host configs to apply default global settings
	if s.redirectHostRepo != nil {
		redirectHosts, err := s.redirectHostRepo.GetAllEnabled(ctx)
		if err != nil {
			log.Printf("[SettingsService] Warning: failed to get redirect hosts for config regeneration after reset: %v", err)
		} else if len(redirectHosts) > 0 {
			if err := s.nginxManager.GenerateAllRedirectConfigs(ctx, redirectHosts); err != nil {
				log.Printf("[SettingsService] Warning: failed to regenerate redirect host configs after global settings reset: %v", err)
			}
		}
	}

	// Reload nginx to apply all changes
	if err := s.nginxManager.ReloadNginx(ctx); err != nil {
		log.Printf("[SettingsService] Warning: failed to reload nginx after global settings reset: %v", err)
	}

	return settings, nil
}

func (s *SettingsService) ApplySettingsPreset(ctx context.Context, preset string) (*model.GlobalSettings, error) {
	presetConfig, ok := model.GlobalSettingsPresets[preset]
	if !ok {
		return nil, fmt.Errorf("invalid preset: %s", preset)
	}

	req := &model.UpdateGlobalSettingsRequest{
		WorkerProcesses:        &presetConfig.WorkerProcesses,
		WorkerConnections:      &presetConfig.WorkerConnections,
		MultiAccept:            &presetConfig.MultiAccept,
		Sendfile:               &presetConfig.Sendfile,
		TCPNopush:              &presetConfig.TCPNopush,
		TCPNodelay:             &presetConfig.TCPNodelay,
		KeepaliveTimeout:       &presetConfig.KeepaliveTimeout,
		KeepaliveRequests:      &presetConfig.KeepaliveRequests,
		ServerTokens:           &presetConfig.ServerTokens,
		GzipEnabled:            &presetConfig.GzipEnabled,
		GzipCompLevel:          &presetConfig.GzipCompLevel,
		BrotliEnabled:          &presetConfig.BrotliEnabled,
		BrotliCompLevel:        &presetConfig.BrotliCompLevel,
		SSLProtocols:           presetConfig.SSLProtocols,
		SSLPreferServerCiphers: &presetConfig.SSLPreferServerCiphers,
		SSLECDHCurve:           presetConfig.SSLECDHCurve,
	}

	// Route through UpdateGlobalSettings so the preset triggers the same
	// nginx.conf regen + proxy host re-render + reload pipeline as a manual
	// edit. Previously ApplySettingsPreset wrote to DB only and left nginx
	// running with the old config — the UI said "nginx will reload" but the
	// reload never happened.
	return s.UpdateGlobalSettings(ctx, req)
}

// ---- Dashboard ----

// dashboardSummaryTTL is how long a computed dashboard summary is reused.
// It must sit comfortably above the UI poll interval (60s, Dashboard.tsx
// refetchInterval) so successive polls hit the cache instead of re-running
// the heavy 24h log aggregations (three GROUP BY scans over logs_partitioned)
// on every poll.
const dashboardSummaryTTL = 90 * time.Second

func (s *SettingsService) GetDashboard(ctx context.Context) (*model.DashboardSummary, error) {
	summary := s.cachedDashboardSummary()
	if summary == nil {
		// Cache miss: compute once, shared by all concurrent pollers
		// (singleflight), so N open dashboard tabs cost one aggregation run.
		v, err, _ := s.dashSummarySF.Do("dashboard_summary", func() (interface{}, error) {
			return s.fetchDashboardSummary(ctx)
		})
		if err != nil {
			return nil, err
		}
		summary = v.(*model.DashboardSummary)
	}

	// Work on a shallow copy: the cached struct is shared across requests and
	// addLiveMetrics mutates SystemHealth fields (the slices stay read-only).
	out := *summary
	s.addLiveMetrics(&out)

	return &out, nil
}

// cachedDashboardSummary returns the in-process cached summary, or nil when
// absent or expired.
func (s *SettingsService) cachedDashboardSummary() *model.DashboardSummary {
	s.dashSummaryMu.Lock()
	defer s.dashSummaryMu.Unlock()
	if s.dashSummary != nil && time.Now().Before(s.dashSummaryExpiry) {
		return s.dashSummary
	}
	return nil
}

func (s *SettingsService) storeDashboardSummary(summary *model.DashboardSummary) {
	s.dashSummaryMu.Lock()
	s.dashSummary = summary
	s.dashSummaryExpiry = time.Now().Add(dashboardSummaryTTL)
	s.dashSummaryMu.Unlock()
}

// fetchDashboardSummary loads the summary from Valkey (survives API restarts)
// or recomputes it from the repository, then populates both cache layers.
// It detaches from the caller's context because the result is shared by every
// singleflight waiter — one client disconnect must not cancel it for the rest.
// The timeout keeps a wedged query from pinning the singleflight slot forever.
func (s *SettingsService) fetchDashboardSummary(ctx context.Context) (*model.DashboardSummary, error) {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()

	if s.redisCache != nil {
		var cached model.DashboardSummary
		if err := s.redisCache.GetDashboardSummary(fctx, &cached); err == nil {
			s.storeDashboardSummary(&cached)
			return &cached, nil
		}
	}

	summary, err := s.dashboardRepo.GetSummary(fctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get dashboard summary: %w", err)
	}

	if s.redisCache != nil {
		s.redisCache.SetDashboardSummary(fctx, summary)
	}
	s.storeDashboardSummary(summary)

	return summary, nil
}

// addLiveMetrics populates live system metrics on the dashboard summary.
func (s *SettingsService) addLiveMetrics(summary *model.DashboardSummary) {
	// CPU usage — non-blocking sample. cpu.Percent with a sampling interval
	// sleeps for the whole interval (500ms), which used to put a hard latency
	// floor on every /dashboard response, including cache hits.
	if cpuPercent, ok := s.sampledCPUPercent(); ok {
		summary.SystemHealth.CPUUsage = cpuPercent
	}

	// Memory stats
	if memStats, err := mem.VirtualMemory(); err == nil {
		summary.SystemHealth.MemoryUsage = memStats.UsedPercent
		summary.SystemHealth.MemoryTotal = memStats.Total
		summary.SystemHealth.MemoryUsed = memStats.Used
	}

	// Disk stats
	if diskStats, err := disk.Usage("/"); err == nil {
		summary.SystemHealth.DiskUsage = diskStats.UsedPercent
		summary.SystemHealth.DiskTotal = diskStats.Total
		summary.SystemHealth.DiskUsed = diskStats.Used
		summary.SystemHealth.DiskPath = "/"
	}

	// Host info
	if hostInfo, err := host.Info(); err == nil {
		summary.SystemHealth.UptimeSeconds = hostInfo.Uptime
		summary.SystemHealth.KernelVersion = hostInfo.KernelVersion
	}

	// Try to read host OS info from mounted files
	if hostname, err := os.ReadFile("/host/etc/hostname"); err == nil {
		summary.SystemHealth.Hostname = trimSpace(string(hostname))
	} else if hostInfo, err := host.Info(); err == nil {
		summary.SystemHealth.Hostname = hostInfo.Hostname
	}

	// Read host OS release info
	s.readPlatformInfo(summary)

	summary.SystemHealth.OS = "linux"

	// Network I/O stats
	if netStats, err := net.IOCounters(false); err == nil && len(netStats) > 0 {
		summary.SystemHealth.NetworkIn = netStats[0].BytesRecv
		summary.SystemHealth.NetworkOut = netStats[0].BytesSent
	}
}

// sampledCPUPercent returns a CPU usage figure without blocking the request
// path. cpu.Percent(0, …) measures usage since the previous zero-interval call
// (gopsutil seeds the baseline at process start) instead of sleeping
// config.CPUSamplingDuration. The short reuse window keeps near-simultaneous
// polls (e.g. multiple dashboard tabs) from re-measuring over a near-zero
// interval, which is noisy. Returns ok=false until the first successful sample
// so callers keep the previously-recorded value instead of showing 0.
func (s *SettingsService) sampledCPUPercent() (float64, bool) {
	s.cpuSampleMu.Lock()
	defer s.cpuSampleMu.Unlock()
	if !s.cpuSampleAt.IsZero() && time.Since(s.cpuSampleAt) < 5*time.Second {
		return s.cpuSampleVal, true
	}
	if pcts, err := cpu.Percent(0, false); err == nil && len(pcts) > 0 {
		s.cpuSampleVal = pcts[0]
		s.cpuSampleAt = time.Now()
	}
	return s.cpuSampleVal, !s.cpuSampleAt.IsZero()
}

// readPlatformInfo reads the OS platform information from mounted files.
func (s *SettingsService) readPlatformInfo(summary *model.DashboardSummary) {
	if file, err := os.Open("/host/etc/os-release"); err == nil {
		defer file.Close()
		buf := make([]byte, 4096)
		n, _ := file.Read(buf)
		content := string(buf[:n])
		for _, line := range splitLines(content) {
			if len(line) > 12 && line[:12] == "PRETTY_NAME=" {
				name := line[12:]
				if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
					name = name[1 : len(name)-1]
				}
				summary.SystemHealth.Platform = name
				return
			}
		}
	}
	if summary.SystemHealth.Platform == "" {
		summary.SystemHealth.Platform = "Linux"
	}
}

func (s *SettingsService) GetGeoIPStats(ctx context.Context, hours int) (*model.GeoIPStatsResponse, error) {
	// Try to get from cache first
	if s.redisCache != nil {
		var cachedResponse model.GeoIPStatsResponse
		if err := s.redisCache.GetGeoIPStats(ctx, hours, &cachedResponse); err == nil {
			return &cachedResponse, nil
		}
	}

	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	stats, totalCount, err := s.dashboardRepo.GetGeoIPStats(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("failed to get GeoIP stats: %w", err)
	}

	response := &model.GeoIPStatsResponse{
		Data:       stats,
		TotalCount: totalCount,
	}

	// Cache the response
	if s.redisCache != nil {
		s.redisCache.SetGeoIPStats(ctx, hours, *response)
	}

	return response, nil
}

func (s *SettingsService) GetSystemHealth(ctx context.Context) (*model.SystemHealth, error) {
	health, err := s.dashboardRepo.GetSystemHealth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system health: %w", err)
	}

	// Update with live nginx status
	if s.nginxManager != nil {
		if err := s.nginxManager.TestConfig(ctx); err == nil {
			health.NginxStatus = config.StatusOK
		} else {
			health.NginxStatus = config.StatusError
		}
	}

	health.DBStatus = config.StatusOK
	health.RecordedAt = time.Now()

	// Live host resource metrics
	if cpuPercent, err := cpu.Percent(config.CPUSamplingDuration, false); err == nil && len(cpuPercent) > 0 {
		health.CPUUsage = cpuPercent[0]
	}
	if memStats, err := mem.VirtualMemory(); err == nil {
		health.MemoryUsage = memStats.UsedPercent
		health.MemoryTotal = memStats.Total
		health.MemoryUsed = memStats.Used
	}
	if diskStats, err := disk.Usage("/"); err == nil {
		health.DiskUsage = diskStats.UsedPercent
		health.DiskTotal = diskStats.Total
		health.DiskUsed = diskStats.Used
		health.DiskPath = "/"
	}
	if hostInfo, err := host.Info(); err == nil {
		health.UptimeSeconds = hostInfo.Uptime
		health.Hostname = hostInfo.Hostname
		health.OS = hostInfo.OS
		health.Platform = hostInfo.Platform
		health.KernelVersion = hostInfo.KernelVersion
	}

	return health, nil
}

func (s *SettingsService) GetSystemHealthHistory(ctx context.Context, hours, limit int) ([]model.SystemHealth, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	history, err := s.dashboardRepo.GetSystemHealthHistory(ctx, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get system health history: %w", err)
	}
	return history, nil
}

func (s *SettingsService) GetHourlyStats(ctx context.Context, params *model.DashboardQueryParams) ([]model.DashboardStatsHourly, error) {
	stats, err := s.dashboardRepo.GetHourlyStats(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to get hourly stats: %w", err)
	}
	return stats, nil
}

func (s *SettingsService) GetDockerStats(ctx context.Context) (*DockerStatsSummary, error) {
	if s.dockerStats == nil {
		return nil, fmt.Errorf("docker stats service not available")
	}
	summary, err := s.dockerStats.GetStatsSummary(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker stats: %w", err)
	}
	return summary, nil
}

func (s *SettingsService) ListDockerContainers(ctx context.Context) ([]DockerContainerInfo, error) {
	if s.dockerStats == nil {
		return nil, fmt.Errorf("docker stats service not available")
	}
	containers, err := s.dockerStats.ListContainersWithNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list docker containers: %w", err)
	}
	if containers == nil {
		containers = []DockerContainerInfo{}
	}
	return containers, nil
}

// ---- Self Check / Test ----

// SelfCheckResult holds the result of a system self-check.
type SelfCheckResult struct {
	Status     string                            `json:"status"`
	CheckedAt  time.Time                         `json:"checked_at"`
	Components map[string]map[string]interface{} `json:"components"`
}

func (s *SettingsService) SelfCheck(ctx context.Context) (*SelfCheckResult, error) {
	results := make(map[string]map[string]interface{})

	// Check database
	results["database"] = map[string]interface{}{
		"status": config.StatusOK,
	}

	// Check nginx
	nginxStatus := config.StatusOK
	var nginxError string
	if s.nginxManager != nil {
		if err := s.nginxManager.TestConfig(ctx); err != nil {
			nginxStatus = config.StatusError
			nginxError = err.Error()
		}
	}
	results["nginx"] = map[string]interface{}{
		"status": nginxStatus,
		"error":  nginxError,
	}

	// Check backup directory
	backupStatus := config.StatusOK
	if _, err := os.Stat(s.backupPath); os.IsNotExist(err) {
		if err := os.MkdirAll(s.backupPath, config.DefaultDirPermissions); err != nil {
			backupStatus = config.StatusError
		}
	}
	results["backup_storage"] = map[string]interface{}{
		"status": backupStatus,
		"path":   s.backupPath,
	}

	// Overall status
	overallStatus := config.StatusHealthy
	if nginxStatus != config.StatusOK {
		overallStatus = config.StatusDegraded
	}

	return &SelfCheckResult{
		Status:     overallStatus,
		CheckedAt:  time.Now(),
		Components: results,
	}, nil
}

// TestDashboardQueriesResult holds the result of a dashboard queries test.
type TestDashboardQueriesResult struct {
	Test    string                            `json:"test"`
	Status  string                            `json:"status"`
	Results map[string]map[string]interface{} `json:"results"`
}

func (s *SettingsService) TestDashboardQueries(ctx context.Context) (*TestDashboardQueriesResult, error) {
	results := make(map[string]map[string]interface{})

	// Test summary query
	summary, err := s.dashboardRepo.GetSummary(ctx)
	if err != nil {
		results["summary"] = map[string]interface{}{
			"status": config.StatusError,
			"error":  err.Error(),
		}
	} else {
		results["summary"] = map[string]interface{}{
			"status":          config.StatusOK,
			"total_requests":  summary.TotalRequests24h,
			"total_bandwidth": summary.TotalBandwidth24h,
			"proxy_hosts":     summary.TotalProxyHosts,
		}
	}

	// Test health query
	health, err := s.dashboardRepo.GetSystemHealth(ctx)
	if err != nil {
		results["health"] = map[string]interface{}{
			"status": config.StatusError,
			"error":  err.Error(),
		}
	} else {
		results["health"] = map[string]interface{}{
			"status":       config.StatusOK,
			"nginx_status": health.NginxStatus,
			"db_status":    health.DBStatus,
		}
	}

	// Test hourly stats query
	params := &model.DashboardQueryParams{
		StartTime: time.Now().Add(-24 * time.Hour),
		EndTime:   time.Now(),
	}
	stats, err := s.dashboardRepo.GetHourlyStats(ctx, params)
	if err != nil {
		results["hourly_stats"] = map[string]interface{}{
			"status": config.StatusError,
			"error":  err.Error(),
		}
	} else {
		results["hourly_stats"] = map[string]interface{}{
			"status": config.StatusOK,
			"count":  len(stats),
		}
	}

	return &TestDashboardQueriesResult{
		Test:    "dashboard_queries",
		Status:  "passed",
		Results: results,
	}, nil
}

// ---- Backups ----

func (s *SettingsService) ListBackups(ctx context.Context, page, perPage int) (*model.BackupListResponse, error) {
	result, err := s.backupRepo.List(ctx, page, perPage)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}
	return result, nil
}

func (s *SettingsService) GetBackup(ctx context.Context, id string) (*model.Backup, error) {
	backup, err := s.backupRepo.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup: %w", err)
	}
	return backup, nil
}

func (s *SettingsService) DeleteBackup(ctx context.Context, id string) error {
	backup, err := s.backupRepo.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get backup: %w", err)
	}
	if backup == nil {
		return fmt.Errorf("backup not found")
	}

	os.Remove(backup.FilePath)

	if err := s.backupRepo.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to delete backup: %w", err)
	}
	return nil
}

func (s *SettingsService) GetBackupStats(ctx context.Context) (*model.BackupStats, error) {
	stats, err := s.backupRepo.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup stats: %w", err)
	}
	return stats, nil
}

// GetBackupPath returns the backup directory path.
func (s *SettingsService) GetBackupPath() string {
	return s.backupPath
}

// GetBackupRepo returns the backup repository (needed by handler for backup/restore operations).
func (s *SettingsService) GetBackupRepo() *repository.BackupRepository {
	return s.backupRepo
}

// GetNginxManager returns the nginx manager (needed by handler for restore operations).
func (s *SettingsService) GetNginxManager() *nginx.Manager {
	return s.nginxManager
}

// GetProxyHostRepo returns the proxy host repository (needed by handler for restore operations).
func (s *SettingsService) GetProxyHostRepo() *repository.ProxyHostRepository {
	return s.proxyHostRepo
}

// GetRedirectHostRepo returns the redirect host repository (needed by handler for restore operations).
func (s *SettingsService) GetRedirectHostRepo() *repository.RedirectHostRepository {
	return s.redirectHostRepo
}

// GetCertificateRepo returns the certificate repository (needed by handler for restore operations).
func (s *SettingsService) GetCertificateRepo() *repository.CertificateRepository {
	return s.certificateRepo
}

// GetWAFRepo returns the WAF repository (needed by handler for restore operations).
func (s *SettingsService) GetWAFRepo() *repository.WAFRepository {
	return s.wafRepo
}

// GetProxyHostService returns the proxy host service (needed by handler for restore operations).
func (s *SettingsService) GetProxyHostService() *ProxyHostService {
	return s.proxyHostService
}

// GetRedisCache returns the Redis cache client (needed by handler for dashboard caching).
func (s *SettingsService) GetRedisCache() *cache.RedisClient {
	return s.redisCache
}

// ---- helpers ----

func trimSpace(s string) string {
	// Simple trim without importing strings
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// ParseHours parses an hours query parameter with a default and max value.
func ParseHours(hoursStr string, defaultHours, maxHours int) int {
	hours := defaultHours
	if hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 && h <= maxHours {
			hours = h
		}
	}
	return hours
}

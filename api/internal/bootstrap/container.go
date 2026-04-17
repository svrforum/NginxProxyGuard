package bootstrap

import (
	"context"
	"os"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/pkg/cache"
)

// Container is the composition root.  It owns every long-lived dependency
// (database, cache, nginx manager, repositories, services, handlers,
// schedulers) and provides a single entry point for startup and shutdown.
type Container struct {
	Config       *config.Config
	DB           *database.DB
	Cache        *cache.RedisClient
	Nginx        *nginx.Manager
	Repositories *Repositories
	Services     *Services
	Handlers     *Handlers
	Schedulers   *Schedulers
}

// NewContainer wires the full dependency graph in the exact order used by
// the original main.go:
//
//	DB → Cache → Nginx → Repositories → Services → cross-service callbacks
//	   → Handlers → Schedulers.
func NewContainer(cfg *config.Config) (*Container, error) {
	// Register Prometheus metrics with the default registry exactly once.
	// Register is sync.Once-guarded so additional calls are no-ops.
	metrics.Register()

	db, err := InitDB(cfg)
	if err != nil {
		return nil, err
	}

	redisCache := InitCache(cfg)

	nginxManager := nginx.NewManager(cfg.NginxConfigPath, cfg.NginxCertsPath)

	// Post-reload health probe (opt-out via NPG_HEALTH_PROBE=false)
	probeDisabled := os.Getenv("NPG_HEALTH_PROBE") == "false"
	nginxContainer := os.Getenv("NGINX_CONTAINER")
	if nginxContainer == "" {
		nginxContainer = "npg-proxy"
	}
	nginxHTTPPort := os.Getenv("NGINX_HTTP_PORT")
	if nginxHTTPPort == "" {
		nginxHTTPPort = "80"
	}
	nginxManager.SetHealthProber(nginx.NewHealthProber(nginxContainer, nginxHTTPPort, probeDisabled))

	repos := InitRepositories(db, redisCache)
	svcs := InitServices(cfg, db, redisCache, nginxManager, repos)
	wireServiceCallbacks(svcs, repos)
	handlers := InitHandlers(repos, svcs, nginxManager, redisCache)
	schedulers := NewSchedulers(cfg, db, repos, svcs)

	return &Container{
		Config:       cfg,
		DB:           db,
		Cache:        redisCache,
		Nginx:        nginxManager,
		Repositories: repos,
		Services:     svcs,
		Handlers:     handlers,
		Schedulers:   schedulers,
	}, nil
}

// Startup performs one-time startup side effects and launches background
// services.  Errors from individual startup steps are logged but not
// returned — the auto-recovery code path already treats sync errors as
// best-effort.
func (c *Container) Startup(ctx context.Context) error {
	startupCtx, cancel := context.WithTimeout(ctx, config.ContextTimeout)
	defer cancel()
	if err := runStartup(startupCtx, c); err != nil {
		return err
	}

	startBackgroundServices(ctx, c)
	return nil
}

// StartSchedulers launches the scheduler goroutines.  Split from
// Startup so the router can be wired up before schedulers begin firing.
func (c *Container) StartSchedulers(_ context.Context) {
	c.Schedulers.Start()
}

// StopAll signals every background service and scheduler to stop.
func (c *Container) StopAll() {
	c.Services.StopBackgroundServices()
	c.Schedulers.Stop()
}

// Close releases low-level resources (DB, cache).  Call from defer in
// main so resources are freed even if startup fails.
func (c *Container) Close() {
	if c.Cache != nil {
		_ = c.Cache.Close()
	}
	if c.DB != nil {
		_ = c.DB.Close()
	}
}

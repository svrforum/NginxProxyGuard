package scheduler

import (
	"context"
	"log"
	"time"

	"nginx-proxy-guard/internal/service"
)

// ipChanged reports whether a re-resolved IP differs and is usable. An empty
// newIP means resolution failed — keep the last-known-good config (no regen). (#150)
func ipChanged(current, newIP string) bool {
	return newIP != "" && newIP != current
}

// ContainerReconcileScheduler periodically re-resolves the IP of each
// container-backed proxy host and regenerates that host's config (via the
// existing fail-safe path) whenever the IP has changed. (#150)
type ContainerReconcileScheduler struct {
	proxyHostService *service.ProxyHostService
	resolver         service.ContainerResolver
	interval         time.Duration
	stopChan         chan struct{}
	running          bool
}

// NewContainerReconcileScheduler constructs (but does not start) the scheduler.
// A zero interval defaults to 30s.
func NewContainerReconcileScheduler(phs *service.ProxyHostService, resolver service.ContainerResolver, interval time.Duration) *ContainerReconcileScheduler {
	if interval == 0 {
		interval = 30 * time.Second
	}
	return &ContainerReconcileScheduler{proxyHostService: phs, resolver: resolver, interval: interval, stopChan: make(chan struct{})}
}

// Start launches the reconcile loop. It is a no-op when already running or when
// no resolver is available (defensive: e.g. no docker access).
func (s *ContainerReconcileScheduler) Start() {
	if s.running || s.resolver == nil {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] Container reconcile scheduler started (interval: %v)", s.interval)
}

// Stop signals the reconcile loop to exit.
func (s *ContainerReconcileScheduler) Stop() {
	if s.running {
		close(s.stopChan)
		s.running = false
	}
}

func (s *ContainerReconcileScheduler) run() {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopChan:
			return
		case <-t.C:
			s.reconcileOnce(context.Background())
		}
	}
}

// reconcileOnce re-resolves each container-backed host; on a changed IP it
// updates forward_host + regenerates that host's config via the fail-safe path.
// Resolution failures are logged and skipped (keep last-known-good). (#150)
func (s *ContainerReconcileScheduler) reconcileOnce(ctx context.Context) {
	hosts, err := s.proxyHostService.ListContainerBackedHosts(ctx)
	if err != nil {
		log.Printf("[ContainerReconcile] list failed: %v", err)
		return
	}
	for _, h := range hosts {
		newIP, err := s.resolver.ResolveContainerIP(ctx, *h.ForwardContainerName)
		if err != nil {
			log.Printf("[ContainerReconcile] WARN: resolve %q failed, keeping current config: %v", *h.ForwardContainerName, err)
			continue
		}
		if ipChanged(h.ForwardHost, newIP) {
			log.Printf("[ContainerReconcile] %s: container %q IP %s -> %s; regenerating", h.ID, *h.ForwardContainerName, h.ForwardHost, newIP)
			if err := s.proxyHostService.UpdateForwardHostAndReload(ctx, h.ID, newIP); err != nil {
				log.Printf("[ContainerReconcile] regen failed for %s: %v (config unchanged)", h.ID, err)
			}
		}
	}
}

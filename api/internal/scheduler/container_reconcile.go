package scheduler

import (
	"context"
	"log"
	"os"
	"time"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/internal/service"
)

// ipChanged reports whether a re-resolved IP differs and is usable. An empty
// newIP means resolution failed — keep the last-known-good config (no regen). (#150)
func ipChanged(current, newIP string) bool {
	return newIP != "" && newIP != current
}

// containerReconcileService is the narrow subset of ProxyHostService that
// reconcileOnce needs. Defined as an interface so the legacy-skip behavior
// (Issue #151) can be unit-tested without standing up a real DB-backed
// service. ProxyHostService satisfies it by virtue of its existing methods.
type containerReconcileService interface {
	ListContainerBackedHosts(ctx context.Context) ([]*model.ProxyHost, error)
	UpdateForwardHostAndReload(ctx context.Context, id string, newIP string) error
}

// batchContainerResolver is the optional fast path satisfied by
// *service.DockerStatsService: take ONE container snapshot per reconcile tick
// (a single `docker ps` + a single batched `docker inspect`) and resolve every
// container-backed host against it. Without this, every tick cost
// hosts × (1 docker ps + 1 docker inspect per running container) subprocess
// forks. Resolvers that implement only service.ContainerResolver (e.g. test
// fakes) get the per-host path; resolution semantics (#150/#151 network
// pinning) are identical on both paths.
type batchContainerResolver interface {
	ListContainersWithNetworks(ctx context.Context) ([]service.DockerContainerInfo, error)
	ResolveContainerIPFromList(containers []service.DockerContainerInfo, name string, network string) (string, error)
}

// authProviderReconcileService is the narrow subset of AuthProviderService needed to
// re-resolve container-backed ForwardAuth verify endpoints (#181). Optional — nil when
// auth providers aren't wired. Interface for unit-testing the same way as hosts.
type authProviderReconcileService interface {
	ListContainerBacked(ctx context.Context) ([]model.AuthProvider, error)
	ReconcileContainerProvider(ctx context.Context, p model.AuthProvider, newIP string) (bool, error)
	RecordReconcileStatus(ctx context.Context, id, status, ip, errMsg string) error
}

// ContainerReconcileScheduler periodically re-resolves the IP of each
// container-backed proxy host and regenerates that host's config (via the
// existing fail-safe path) whenever the IP has changed. (#150)
type ContainerReconcileScheduler struct {
	proxyHostService containerReconcileService
	authProviders    authProviderReconcileService // optional (#181)
	systemLog        *repository.SystemLogRepository // optional: surface reconcile events to the Logs view (#181 follow-up)
	resolver         service.ContainerResolver
	interval         time.Duration
	stopChan         chan struct{}
	running          bool
}

// SetSystemLogRepo enables writing reconcile state changes (IP change, container
// unreachable) to the system log so operators see them in the Logs view, not just
// container stdout. Optional. (#181 follow-up)
func (s *ContainerReconcileScheduler) SetSystemLogRepo(r *repository.SystemLogRepository) {
	s.systemLog = r
}

// logSystem writes a reconcile event to the system log (no-op if not wired).
func (s *ContainerReconcileScheduler) logSystem(ctx context.Context, level repository.SystemLogLevel, msg string) {
	if s.systemLog == nil {
		return
	}
	_ = s.systemLog.Create(ctx, &repository.SystemLog{
		Source:    repository.SourceScheduler,
		Level:     level,
		Message:   msg,
		Component: "container-reconcile",
	})
}

// NewContainerReconcileScheduler constructs (but does not start) the scheduler.
// A zero interval defaults to 30s. aps may be nil (auth-provider reconcile disabled).
func NewContainerReconcileScheduler(phs *service.ProxyHostService, aps *service.AuthProviderService, resolver service.ContainerResolver, interval time.Duration) *ContainerReconcileScheduler {
	if interval == 0 {
		interval = 30 * time.Second
	}
	s := &ContainerReconcileScheduler{proxyHostService: phs, resolver: resolver, interval: interval, stopChan: make(chan struct{})}
	if aps != nil { // avoid a non-nil interface wrapping a nil pointer
		s.authProviders = aps
	}
	return s
}

// Start launches the reconcile loop. It is a no-op when already running or when
// no resolver is available (defensive: e.g. no docker access). When the
// environment variable NPG_CONTAINER_RECONCILE_DISABLED is "1" or "true" the
// scheduler is fully disabled (kill switch added with Issue #151 for operators
// who want to opt out of background reconciliation entirely).
func (s *ContainerReconcileScheduler) Start() {
	if s.running || s.resolver == nil {
		return
	}
	if v := os.Getenv("NPG_CONTAINER_RECONCILE_DISABLED"); v == "1" || v == "true" {
		log.Printf("[Scheduler] Container reconcile DISABLED via NPG_CONTAINER_RECONCILE_DISABLED")
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
//
// Issue #151 SAFE MODE: hosts whose forward_container_network is NULL/empty
// (legacy v2.20.0 rows where the user picked a container before this fix
// existed) are SKIPPED. Without a stored network we cannot know which IP the
// user originally picked on a multi-network container, so any resolved IP
// could be the wrong one — overriding it would defeat the user's choice and
// reproduce the very regression we're fixing. Users must re-select the
// container in the UI to opt back into auto-resolve.
func (s *ContainerReconcileScheduler) reconcileOnce(ctx context.Context) {
	hosts, err := s.proxyHostService.ListContainerBackedHosts(ctx)
	if err != nil {
		log.Printf("[ContainerReconcile] list failed: %v", err)
		return
	}

	// One docker snapshot per tick, taken lazily on the first eligible host so
	// ticks with no reconcilable hosts fork no docker subprocesses at all.
	batch, canBatch := s.resolver.(batchContainerResolver)
	var (
		snapshot      []service.DockerContainerInfo
		snapshotErr   error
		snapshotTaken bool
	)
	resolveIP := func(name, network string) (string, error) {
		if !canBatch {
			return s.resolver.ResolveContainerIP(ctx, name, network)
		}
		if !snapshotTaken {
			snapshot, snapshotErr = batch.ListContainersWithNetworks(ctx)
			snapshotTaken = true
		}
		if snapshotErr != nil {
			return "", snapshotErr
		}
		return batch.ResolveContainerIPFromList(snapshot, name, network)
	}

	for _, h := range hosts {
		if h.ForwardContainerNetwork == nil || *h.ForwardContainerNetwork == "" {
			log.Printf("[ContainerReconcile] WARN: host %s has container target %q without a stored network (legacy v2.20.0 row); re-select the container in the UI to enable auto-resolve. Skipping to prevent overriding the user IP.", h.ID, *h.ForwardContainerName)
			continue
		}
		newIP, err := resolveIP(*h.ForwardContainerName, *h.ForwardContainerNetwork)
		if err != nil {
			log.Printf("[ContainerReconcile] WARN: resolve %q on network %q failed, keeping current config: %v", *h.ForwardContainerName, *h.ForwardContainerNetwork, err)
			continue
		}
		if ipChanged(h.ForwardHost, newIP) {
			log.Printf("[ContainerReconcile] %s: container %q (network %q) IP %s -> %s; regenerating", h.ID, *h.ForwardContainerName, *h.ForwardContainerNetwork, h.ForwardHost, newIP)
			if err := s.proxyHostService.UpdateForwardHostAndReload(ctx, h.ID, newIP); err != nil {
				log.Printf("[ContainerReconcile] regen failed for %s: %v (config unchanged)", h.ID, err)
			}
		}
	}

	// Auth providers (#181) share the same snapshot via resolveIP, so a tick with
	// no container-backed hosts but a container-backed provider still forks at most
	// one docker snapshot.
	if s.authProviders != nil {
		s.reconcileAuthProviders(ctx, resolveIP)
	}
}

// reconcileAuthProviders re-resolves each container-backed ForwardAuth provider; on a
// changed verify IP it rewrites provider_url and regenerates every dependent host's
// config (fail-safe). Same #151 safe-mode as hosts: providers with no stored network
// are skipped. (#181)
func (s *ContainerReconcileScheduler) reconcileAuthProviders(ctx context.Context, resolveIP func(name, network string) (string, error)) {
	providers, err := s.authProviders.ListContainerBacked(ctx)
	if err != nil {
		log.Printf("[ContainerReconcile] auth provider list failed: %v", err)
		return
	}
	for _, p := range providers {
		if p.ContainerName == nil || *p.ContainerName == "" {
			continue
		}
		prevStatus := p.LastReconcileStatus
		// record persists reconcile health and emits a system-log line only on a
		// TRANSITION into failure (avoids logging every 30s while a container is down).
		record := func(status, ip, errMsg string) {
			if rerr := s.authProviders.RecordReconcileStatus(ctx, p.ID, status, ip, errMsg); rerr != nil {
				log.Printf("[ContainerReconcile] auth provider %s status write failed: %v", p.ID, rerr)
			}
			if status == "failed" && prevStatus != "failed" {
				s.logSystem(ctx, repository.LevelWarn, "ForwardAuth provider \""+p.Name+"\": "+errMsg+" — host stays protected; auth will fail until resolved")
			}
		}

		if p.ContainerNetwork == nil || *p.ContainerNetwork == "" {
			log.Printf("[ContainerReconcile] WARN: auth provider %s has container target %q without a stored network; re-select the container in the UI to enable auto-resolve. Skipping.", p.ID, *p.ContainerName)
			record("failed", "", "container \""+*p.ContainerName+"\" has no stored network — re-select the container in the UI")
			continue
		}
		newIP, err := resolveIP(*p.ContainerName, *p.ContainerNetwork)
		if err != nil {
			log.Printf("[ContainerReconcile] WARN: auth provider %s resolve %q on network %q failed, keeping current URL: %v", p.ID, *p.ContainerName, *p.ContainerNetwork, err)
			record("failed", "", "could not resolve container \""+*p.ContainerName+"\" on network \""+*p.ContainerNetwork+"\" (stopped or removed?)")
			continue
		}
		if newIP == "" {
			record("failed", "", "container \""+*p.ContainerName+"\" not found on network \""+*p.ContainerNetwork+"\"")
			continue
		}
		changed, err := s.authProviders.ReconcileContainerProvider(ctx, p, newIP)
		if err != nil {
			log.Printf("[ContainerReconcile] auth provider %s regen failed: %v (config unchanged)", p.ID, err)
			record("failed", newIP, "nginx config regeneration failed; kept previous config")
			continue
		}
		record("ok", newIP, "")
		if changed {
			log.Printf("[ContainerReconcile] auth provider %s: container %q (network %q) IP -> %s; regenerated dependent hosts", p.ID, *p.ContainerName, *p.ContainerNetwork, newIP)
			s.logSystem(ctx, repository.LevelInfo, "ForwardAuth provider \""+p.Name+"\": container \""+*p.ContainerName+"\" IP updated to "+newIP+"; dependent hosts regenerated")
		}
	}
}

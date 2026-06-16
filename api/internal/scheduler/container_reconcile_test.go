package scheduler

import (
	"context"
	"errors"
	"testing"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

func TestIPChanged(t *testing.T) {
	if !ipChanged("172.18.0.5", "172.18.0.9") {
		t.Fatal("different IPs must be a change")
	}
	if ipChanged("172.18.0.5", "172.18.0.5") {
		t.Fatal("same IP must not be a change")
	}
	if ipChanged("172.18.0.5", "") {
		t.Fatal("empty new IP (resolve fail) must NOT trigger regen")
	}
}

// fakeReconcileService implements containerReconcileService for tests. It
// records UpdateForwardHostAndReload calls so the test can assert whether
// reconcileOnce decided to regenerate.
type fakeReconcileService struct {
	hosts       []*model.ProxyHost
	listErr     error
	updateCalls []updateCall
	updateErr   error
}

type updateCall struct {
	id    string
	newIP string
}

func (f *fakeReconcileService) ListContainerBackedHosts(ctx context.Context) ([]*model.ProxyHost, error) {
	return f.hosts, f.listErr
}

func (f *fakeReconcileService) UpdateForwardHostAndReload(ctx context.Context, id string, newIP string) error {
	f.updateCalls = append(f.updateCalls, updateCall{id: id, newIP: newIP})
	return f.updateErr
}

// fakeNetworkAwareResolver implements service.ContainerResolver. It records
// every call so the test can assert that legacy rows DID NOT trigger a
// resolver call at all (the safe-mode guard kicks in BEFORE resolution).
type fakeNetworkAwareResolver struct {
	ip        string
	err       error
	callCount int
	gotName   string
	gotNet    string
}

func (f *fakeNetworkAwareResolver) ResolveContainerIP(ctx context.Context, name string, network string) (string, error) {
	f.callCount++
	f.gotName = name
	f.gotNet = network
	return f.ip, f.err
}

func strPtr(s string) *string { return &s }

// TestReconcileOnceSkipsLegacyRows is the Issue #151 safety guarantee in test
// form: a container-backed host with forward_container_network == nil (legacy
// v2.20.0 row) MUST be skipped — no resolver call, no UpdateForwardHostAndReload
// — so the user's manually-picked IP is preserved.
func TestReconcileOnceSkipsLegacyRows(t *testing.T) {
	svc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{
				ID:                   "legacy-host",
				ForwardHost:          "172.24.0.4",
				ForwardContainerName: strPtr("immich_server_a"),
				// ForwardContainerNetwork is nil → legacy v2.20.0 row
			},
		},
	}
	resolver := &fakeNetworkAwareResolver{ip: "172.19.0.18"} // would be the "wrong" IP
	s := &ContainerReconcileScheduler{
		proxyHostService: svc,
		resolver:         resolver,
	}

	s.reconcileOnce(context.Background())

	if resolver.callCount != 0 {
		t.Fatalf("legacy row must NOT trigger resolver call; got %d call(s)", resolver.callCount)
	}
	if len(svc.updateCalls) != 0 {
		t.Fatalf("legacy row must NOT trigger UpdateForwardHostAndReload; got %d call(s)", len(svc.updateCalls))
	}
}

// TestReconcileOnceSkipsEmptyNetwork covers the empty-string case (defensive
// alongside the nil case) — same safety semantics.
func TestReconcileOnceSkipsEmptyNetwork(t *testing.T) {
	svc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{
				ID:                      "host-empty-net",
				ForwardHost:             "172.24.0.4",
				ForwardContainerName:    strPtr("immich_server_a"),
				ForwardContainerNetwork: strPtr(""),
			},
		},
	}
	resolver := &fakeNetworkAwareResolver{ip: "172.19.0.18"}
	s := &ContainerReconcileScheduler{proxyHostService: svc, resolver: resolver}

	s.reconcileOnce(context.Background())

	if resolver.callCount != 0 {
		t.Fatalf("empty-network row must NOT trigger resolver call; got %d", resolver.callCount)
	}
	if len(svc.updateCalls) != 0 {
		t.Fatalf("empty-network row must NOT trigger regen; got %d", len(svc.updateCalls))
	}
}

// TestReconcileOnceResolvesNetworkAware verifies the happy path post-#151:
// when a network IS stored, resolver is called WITH that network, and the
// regen is triggered on IP change.
func TestReconcileOnceResolvesNetworkAware(t *testing.T) {
	svc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{
				ID:                      "host-with-net",
				ForwardHost:             "172.24.0.4",
				ForwardContainerName:    strPtr("immich_server_a"),
				ForwardContainerNetwork: strPtr("bebe"),
			},
		},
	}
	resolver := &fakeNetworkAwareResolver{ip: "172.24.0.5"} // simulate IP change on the SAME network
	s := &ContainerReconcileScheduler{proxyHostService: svc, resolver: resolver}

	s.reconcileOnce(context.Background())

	if resolver.callCount != 1 {
		t.Fatalf("expected 1 resolver call, got %d", resolver.callCount)
	}
	if resolver.gotNet != "bebe" {
		t.Fatalf("resolver must be called with stored network 'bebe', got %q", resolver.gotNet)
	}
	if len(svc.updateCalls) != 1 || svc.updateCalls[0].newIP != "172.24.0.5" {
		t.Fatalf("expected one regen with newIP 172.24.0.5, got %+v", svc.updateCalls)
	}
}

// fakeBatchResolver implements both service.ContainerResolver and the
// scheduler's batchContainerResolver fast path. It records snapshot calls so
// the test can assert ONE docker snapshot per tick, shared across hosts.
type fakeBatchResolver struct {
	containers   []service.DockerContainerInfo
	listCalls    int
	resolveCalls int
}

func (f *fakeBatchResolver) ResolveContainerIP(ctx context.Context, name string, network string) (string, error) {
	f.resolveCalls++
	return "", errors.New("per-host path must not be used when the batch path is available")
}

func (f *fakeBatchResolver) ListContainersWithNetworks(ctx context.Context) ([]service.DockerContainerInfo, error) {
	f.listCalls++
	return f.containers, nil
}

func (f *fakeBatchResolver) ResolveContainerIPFromList(containers []service.DockerContainerInfo, name string, network string) (string, error) {
	for _, c := range containers {
		if c.Name != name {
			continue
		}
		for _, n := range c.Networks {
			if n.Name == network {
				return n.IPAddress, nil
			}
		}
	}
	return "", errors.New("not found in snapshot")
}

// TestReconcileOnceBatchesSnapshotPerTick: when the resolver supports the
// batch path (*service.DockerStatsService does), reconcileOnce must take
// exactly ONE container snapshot per tick and resolve every host against it —
// never the per-host ResolveContainerIP path. Legacy rows (no stored network)
// keep being skipped before any docker work.
func TestReconcileOnceBatchesSnapshotPerTick(t *testing.T) {
	svc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{
				ID:                      "host-a",
				ForwardHost:             "172.24.0.4",
				ForwardContainerName:    strPtr("app-a"),
				ForwardContainerNetwork: strPtr("net-a"),
			},
			{
				ID:                   "legacy-host",
				ForwardHost:          "172.24.0.9",
				ForwardContainerName: strPtr("app-legacy"),
				// no network → must be skipped before resolution
			},
			{
				ID:                      "host-b",
				ForwardHost:             "172.25.0.7",
				ForwardContainerName:    strPtr("app-b"),
				ForwardContainerNetwork: strPtr("net-b"),
			},
		},
	}
	resolver := &fakeBatchResolver{
		containers: []service.DockerContainerInfo{
			{Name: "app-a", Networks: []service.DockerContainerNetwork{{Name: "net-a", IPAddress: "172.24.0.5"}}},
			{Name: "app-b", Networks: []service.DockerContainerNetwork{{Name: "net-b", IPAddress: "172.25.0.8"}}},
		},
	}
	s := &ContainerReconcileScheduler{proxyHostService: svc, resolver: resolver}

	s.reconcileOnce(context.Background())

	if resolver.listCalls != 1 {
		t.Fatalf("expected exactly 1 snapshot per tick, got %d", resolver.listCalls)
	}
	if resolver.resolveCalls != 0 {
		t.Fatalf("per-host ResolveContainerIP must not be called on the batch path; got %d call(s)", resolver.resolveCalls)
	}
	if len(svc.updateCalls) != 2 {
		t.Fatalf("expected 2 regens (host-a, host-b), got %+v", svc.updateCalls)
	}
	if svc.updateCalls[0].id != "host-a" || svc.updateCalls[0].newIP != "172.24.0.5" {
		t.Fatalf("host-a regen mismatch: %+v", svc.updateCalls[0])
	}
	if svc.updateCalls[1].id != "host-b" || svc.updateCalls[1].newIP != "172.25.0.8" {
		t.Fatalf("host-b regen mismatch: %+v", svc.updateCalls[1])
	}
}

// TestReconcileOnceBatchSnapshotLazy: a tick where every host is skipped
// (legacy rows) must not take a snapshot at all — no docker subprocess forks.
func TestReconcileOnceBatchSnapshotLazy(t *testing.T) {
	svc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{
				ID:                   "legacy-only",
				ForwardHost:          "172.24.0.4",
				ForwardContainerName: strPtr("app-legacy"),
			},
		},
	}
	resolver := &fakeBatchResolver{}
	s := &ContainerReconcileScheduler{proxyHostService: svc, resolver: resolver}

	s.reconcileOnce(context.Background())

	if resolver.listCalls != 0 {
		t.Fatalf("no eligible host → no snapshot expected, got %d", resolver.listCalls)
	}
}

func intPtr(i int) *int { return &i }

// fakeAuthProviderReconcile implements authProviderReconcileService (#181).
type fakeAuthProviderReconcile struct {
	providers      []model.AuthProvider
	listErr        error
	reconcileCalls []reconcileCall
	changed        bool
	reconcileErr   error
}

type reconcileCall struct {
	id    string
	newIP string
}

func (f *fakeAuthProviderReconcile) ListContainerBacked(ctx context.Context) ([]model.AuthProvider, error) {
	return f.providers, f.listErr
}

func (f *fakeAuthProviderReconcile) ReconcileContainerProvider(ctx context.Context, p model.AuthProvider, newIP string) (bool, error) {
	f.reconcileCalls = append(f.reconcileCalls, reconcileCall{id: p.ID, newIP: newIP})
	return f.changed, f.reconcileErr
}

// TestReconcileAuthProvidersSkipsNoNetwork: #151 safe-mode applies to auth
// providers too — a container-backed provider with no stored network must be
// skipped before any resolver call or reconcile.
func TestReconcileAuthProvidersSkipsNoNetwork(t *testing.T) {
	ap := &fakeAuthProviderReconcile{
		providers: []model.AuthProvider{
			{ID: "ap-legacy", ContainerName: strPtr("authelia"), ProviderURL: "http://172.19.0.7:9091"},
			// ContainerNetwork nil → skip
		},
	}
	resolver := &fakeNetworkAwareResolver{ip: "172.19.0.99"}
	s := &ContainerReconcileScheduler{
		proxyHostService: &fakeReconcileService{},
		authProviders:    ap,
		resolver:         resolver,
	}

	s.reconcileOnce(context.Background())

	if resolver.callCount != 0 {
		t.Fatalf("no-network provider must NOT trigger resolver call; got %d", resolver.callCount)
	}
	if len(ap.reconcileCalls) != 0 {
		t.Fatalf("no-network provider must NOT trigger reconcile; got %d", len(ap.reconcileCalls))
	}
}

// TestReconcileAuthProvidersHappyPath: a provider WITH a stored network is
// resolved against that network and reconciled with the new IP.
func TestReconcileAuthProvidersHappyPath(t *testing.T) {
	ap := &fakeAuthProviderReconcile{
		providers: []model.AuthProvider{
			{
				ID:               "ap-1",
				ContainerName:    strPtr("authelia"),
				ContainerNetwork: strPtr("fa-net"),
				ContainerPort:    intPtr(9091),
				ContainerScheme:  strPtr("http"),
				ProviderURL:      "http://172.19.0.7:9091",
			},
		},
		changed: true,
	}
	resolver := &fakeNetworkAwareResolver{ip: "172.19.0.42"}
	s := &ContainerReconcileScheduler{
		proxyHostService: &fakeReconcileService{},
		authProviders:    ap,
		resolver:         resolver,
	}

	s.reconcileOnce(context.Background())

	if resolver.callCount != 1 || resolver.gotNet != "fa-net" {
		t.Fatalf("expected 1 resolve on network 'fa-net', got count=%d net=%q", resolver.callCount, resolver.gotNet)
	}
	if len(ap.reconcileCalls) != 1 || ap.reconcileCalls[0].id != "ap-1" || ap.reconcileCalls[0].newIP != "172.19.0.42" {
		t.Fatalf("expected one reconcile for ap-1 with newIP 172.19.0.42, got %+v", ap.reconcileCalls)
	}
}

// TestReconcileSharesSnapshotAcrossHostsAndProviders: on the batch path, hosts
// and auth providers resolve against ONE docker snapshot per tick.
func TestReconcileSharesSnapshotAcrossHostsAndProviders(t *testing.T) {
	hostSvc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{ID: "host-a", ForwardHost: "172.24.0.4", ForwardContainerName: strPtr("app-a"), ForwardContainerNetwork: strPtr("net-a")},
		},
	}
	ap := &fakeAuthProviderReconcile{
		providers: []model.AuthProvider{
			{ID: "ap-1", ContainerName: strPtr("authelia"), ContainerNetwork: strPtr("net-a"), ContainerPort: intPtr(9091), ProviderURL: "http://x:9091"},
		},
		changed: true,
	}
	resolver := &fakeBatchResolver{
		containers: []service.DockerContainerInfo{
			{Name: "app-a", Networks: []service.DockerContainerNetwork{{Name: "net-a", IPAddress: "172.24.0.5"}}},
			{Name: "authelia", Networks: []service.DockerContainerNetwork{{Name: "net-a", IPAddress: "172.24.0.6"}}},
		},
	}
	s := &ContainerReconcileScheduler{proxyHostService: hostSvc, authProviders: ap, resolver: resolver}

	s.reconcileOnce(context.Background())

	if resolver.listCalls != 1 {
		t.Fatalf("expected ONE shared snapshot for hosts+providers, got %d", resolver.listCalls)
	}
	if len(hostSvc.updateCalls) != 1 || len(ap.reconcileCalls) != 1 {
		t.Fatalf("expected 1 host regen and 1 provider reconcile, got hosts=%d providers=%d", len(hostSvc.updateCalls), len(ap.reconcileCalls))
	}
	if ap.reconcileCalls[0].newIP != "172.24.0.6" {
		t.Fatalf("provider should resolve to 172.24.0.6 from the shared snapshot, got %s", ap.reconcileCalls[0].newIP)
	}
}

// TestReconcileOnceResolverErrorKeepsConfig: when the network-aware resolver
// fails (e.g. container temporarily off the network), keep last-known-good —
// no regen.
func TestReconcileOnceResolverErrorKeepsConfig(t *testing.T) {
	svc := &fakeReconcileService{
		hosts: []*model.ProxyHost{
			{
				ID:                      "host-broken",
				ForwardHost:             "172.24.0.4",
				ForwardContainerName:    strPtr("immich_server_a"),
				ForwardContainerNetwork: strPtr("bebe"),
			},
		},
	}
	resolver := &fakeNetworkAwareResolver{err: errors.New("not attached to network")}
	s := &ContainerReconcileScheduler{proxyHostService: svc, resolver: resolver}

	s.reconcileOnce(context.Background())

	if len(svc.updateCalls) != 0 {
		t.Fatalf("resolver error must NOT trigger regen; got %d", len(svc.updateCalls))
	}
}

package scheduler

import (
	"context"
	"errors"
	"testing"

	"nginx-proxy-guard/internal/model"
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

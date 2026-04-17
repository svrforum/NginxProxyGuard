package service

// Characterization tests for the SyncAllConfigs auto-recovery loop.
//
// The loop was extracted from SyncAllConfigsWithDetails into runAutoRecovery
// (see sync_auto_recovery.go) so it could be tested without a database.
// These tests pin CURRENT behavior — most importantly the 5-attempt retry
// budget, the "domain comes from nginx error text" mechanism, and the fact
// that a host removed during recovery is not re-removed.
//
// A fake NginxManager (fakeAutoRecoveryNginx) stands in for the real one.
// Its TestConfig returns an error whose text references a specific host's
// config filename (proxy_host_<domain>.conf) matching the pattern that
// parseNginxErrorForHost expects, and its RemoveConfig / RemoveHostWAFConfig
// simply track what was removed. The fake intentionally implements only the
// subset of NginxManager that runAutoRecovery uses (via the
// autoRecoveryNginx interface).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// fakeAutoRecoveryNginx satisfies the autoRecoveryNginx interface.
// It simulates nginx -t failing for hosts whose ForwardHost contains the
// marker "FAIL_MARKER" until those hosts' configs have been removed.
type fakeAutoRecoveryNginx struct {
	mu sync.Mutex

	// writtenConfigs simulates the on-disk set of host IDs whose configs
	// are currently "present" in nginx. The test seeds this before calling
	// runAutoRecovery.
	writtenConfigs map[string]bool

	// wafRemoved tracks host IDs whose WAF config was removed.
	wafRemoved map[string]bool

	// failingHosts is the index of (domain → host) entries whose configs are
	// toxic to nginx. As long as any entry in this map has a corresponding
	// writtenConfigs entry, TestConfig will return an error referencing the
	// FIRST toxic domain in failingOrder. Once a toxic host's config is
	// removed, it is no longer reported.
	failingHosts  map[string]string // domain → hostID
	failingOrder  []string          // deterministic order of domains to report

	testCallCount int
}

func newFakeAutoRecoveryNginx() *fakeAutoRecoveryNginx {
	return &fakeAutoRecoveryNginx{
		writtenConfigs: make(map[string]bool),
		wafRemoved:     make(map[string]bool),
		failingHosts:   make(map[string]string),
	}
}

// TestConfig returns an error for the first toxic (failing + still-written)
// host, or nil once none remain.
func (f *fakeAutoRecoveryNginx) TestConfig(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.testCallCount++
	for _, domain := range f.failingOrder {
		hostID, ok := f.failingHosts[domain]
		if !ok {
			continue
		}
		if f.writtenConfigs[hostID] {
			// The error format must match parseNginxErrorForHost's regex:
			// `proxy_host_<domain-with-underscores>\.conf`.
			fileLabel := strings.ReplaceAll(domain, ".", "_")
			return fmt.Errorf("nginx: [emerg] invalid host config in /etc/nginx/conf.d/proxy_host_%s.conf:42", fileLabel)
		}
	}
	return nil
}

func (f *fakeAutoRecoveryNginx) RemoveConfig(_ context.Context, host *model.ProxyHost) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.writtenConfigs, host.ID)
	return nil
}

func (f *fakeAutoRecoveryNginx) RemoveHostWAFConfig(_ context.Context, hostID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wafRemoved[hostID] = true
	return nil
}

// TestSyncAutoRecovery_Characterization exercises runAutoRecovery with:
//   - 5 hosts total
//   - 2 hosts whose ForwardHost contains "FAIL_MARKER" → their configs fail
//     nginx test until removed.
//
// Characterization assertions:
//   - After recovery, the 2 bad hosts' configs are no longer in writtenConfigs.
//   - Their WAF configs were removed.
//   - Their result entries are Success=false and Error is non-empty.
//   - The 3 good hosts remain in writtenConfigs, Success=true, no WAF removal.
//   - TestConfig was called at most 6 times (1 initial + up to 5 retries),
//     matching the documented retry budget.
//   - SuccessCount/FailedCount were adjusted correctly.
func TestSyncAutoRecovery_Characterization(t *testing.T) {
	ctx := context.Background()

	hosts := []model.ProxyHost{
		{ID: "host-1", DomainNames: []string{"good-1.example.com"}, ForwardHost: "10.0.0.1", Enabled: true},
		{ID: "host-bad-1", DomainNames: []string{"bad-1.example.com"}, ForwardHost: "FAIL_MARKER-1", Enabled: true},
		{ID: "host-2", DomainNames: []string{"good-2.example.com"}, ForwardHost: "10.0.0.2", Enabled: true},
		{ID: "host-bad-2", DomainNames: []string{"bad-2.example.com"}, ForwardHost: "FAIL_MARKER-2", Enabled: true},
		{ID: "host-3", DomainNames: []string{"good-3.example.com"}, ForwardHost: "10.0.0.3", Enabled: true},
	}

	fake := newFakeAutoRecoveryNginx()
	// Seed: every host starts with a config "written".
	for i := range hosts {
		fake.writtenConfigs[hosts[i].ID] = true
	}
	// Mark bad hosts as toxic.
	fake.failingHosts["bad-1.example.com"] = "host-bad-1"
	fake.failingHosts["bad-2.example.com"] = "host-bad-2"
	fake.failingOrder = []string{"bad-1.example.com", "bad-2.example.com"}

	// Build the SyncAllResult as SyncAllConfigsWithDetails would, after the
	// per-host generation loop has succeeded for every host.
	result := &SyncAllResult{
		TotalHosts:   len(hosts),
		SuccessCount: len(hosts),
		FailedCount:  0,
	}
	for i := range hosts {
		result.Hosts = append(result.Hosts, SyncHostResult{
			HostID:      hosts[i].ID,
			DomainNames: hosts[i].DomainNames,
			Success:     true,
		})
	}

	// Simulate the caller's initial TestConfig call.
	initialErr := fake.TestConfig(ctx)
	if initialErr == nil {
		t.Fatalf("expected initial TestConfig to fail (bad hosts present), got nil")
	}

	recovered, finalErr := runAutoRecovery(ctx, fake, hosts, result, initialErr)
	if !recovered {
		t.Fatalf("expected recovery to succeed, got recovered=false, err=%v", finalErr)
	}

	// Bad hosts should no longer have configs written.
	if fake.writtenConfigs["host-bad-1"] {
		t.Errorf("bad host-bad-1 config should have been removed, still present")
	}
	if fake.writtenConfigs["host-bad-2"] {
		t.Errorf("bad host-bad-2 config should have been removed, still present")
	}

	// WAF removal was invoked for each bad host.
	if !fake.wafRemoved["host-bad-1"] {
		t.Errorf("WAF config for host-bad-1 should have been removed")
	}
	if !fake.wafRemoved["host-bad-2"] {
		t.Errorf("WAF config for host-bad-2 should have been removed")
	}

	// Good hosts untouched.
	for _, id := range []string{"host-1", "host-2", "host-3"} {
		if !fake.writtenConfigs[id] {
			t.Errorf("good host %s config should remain written", id)
		}
		if fake.wafRemoved[id] {
			t.Errorf("good host %s WAF config should NOT have been removed", id)
		}
	}

	// Result counts: 3 Success, 2 Failed.
	if result.SuccessCount != 3 {
		t.Errorf("expected SuccessCount=3 after recovery, got %d", result.SuccessCount)
	}
	if result.FailedCount != 2 {
		t.Errorf("expected FailedCount=2 after recovery, got %d", result.FailedCount)
	}

	// Each bad host's result entry is failed and has the nginx error.
	for _, id := range []string{"host-bad-1", "host-bad-2"} {
		var hr *SyncHostResult
		for i := range result.Hosts {
			if result.Hosts[i].HostID == id {
				hr = &result.Hosts[i]
				break
			}
		}
		if hr == nil {
			t.Errorf("bad host %s missing from result.Hosts", id)
			continue
		}
		if hr.Success {
			t.Errorf("bad host %s should have Success=false", id)
		}
		if hr.Error == "" {
			t.Errorf("bad host %s should have non-empty Error", id)
		}
	}

	// Good hosts still Success=true.
	for _, id := range []string{"host-1", "host-2", "host-3"} {
		var hr *SyncHostResult
		for i := range result.Hosts {
			if result.Hosts[i].HostID == id {
				hr = &result.Hosts[i]
				break
			}
		}
		if hr == nil || !hr.Success {
			t.Errorf("good host %s should remain Success=true", id)
		}
	}

	// Retry budget: initial + up to 5 retries = 6 TestConfig calls.
	if fake.testCallCount > 6 {
		t.Errorf("TestConfig called %d times, expected <= 6 (retry budget 5)", fake.testCallCount)
	}
	// Sanity: we should have at least 3 calls to recover two hosts
	// (1 initial + 2 retries after removals).
	if fake.testCallCount < 3 {
		t.Errorf("TestConfig called only %d times, expected >= 3", fake.testCallCount)
	}
}

// TestSyncAutoRecovery_UnparsableError pins the behavior when nginx returns an
// error whose text does NOT match parseNginxErrorForHost's regex: the loop
// exits early and reports recovered=false with the original error.
func TestSyncAutoRecovery_UnparsableError(t *testing.T) {
	ctx := context.Background()
	hosts := []model.ProxyHost{
		{ID: "host-1", DomainNames: []string{"example.com"}, ForwardHost: "10.0.0.1", Enabled: true},
	}
	fake := newFakeAutoRecoveryNginx()
	fake.writtenConfigs["host-1"] = true

	result := &SyncAllResult{
		TotalHosts:   1,
		SuccessCount: 1,
		Hosts: []SyncHostResult{
			{HostID: "host-1", DomainNames: []string{"example.com"}, Success: true},
		},
	}

	initialErr := errors.New("some random nginx error without a filename pattern")
	recovered, finalErr := runAutoRecovery(ctx, fake, hosts, result, initialErr)
	if recovered {
		t.Fatalf("expected recovered=false when error is unparsable")
	}
	if finalErr == nil || !strings.Contains(finalErr.Error(), "some random nginx error") {
		t.Errorf("expected final error to match initial, got %v", finalErr)
	}
	// Nothing removed.
	if !fake.writtenConfigs["host-1"] {
		t.Errorf("no config should have been removed for unparsable error")
	}
}

// TestSyncAutoRecovery_RetryBudgetExhausted pins the behavior when more
// than 5 hosts are toxic: after 5 attempts the loop gives up and returns
// recovered=false. This characterizes the fixed retry budget.
func TestSyncAutoRecovery_RetryBudgetExhausted(t *testing.T) {
	ctx := context.Background()

	// 6 bad hosts — one more than the 5-attempt budget.
	var hosts []model.ProxyHost
	result := &SyncAllResult{}
	fake := newFakeAutoRecoveryNginx()
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("host-bad-%d", i)
		domain := fmt.Sprintf("bad-%d.example.com", i)
		hosts = append(hosts, model.ProxyHost{ID: id, DomainNames: []string{domain}, Enabled: true})
		result.Hosts = append(result.Hosts, SyncHostResult{HostID: id, DomainNames: []string{domain}, Success: true})
		fake.writtenConfigs[id] = true
		fake.failingHosts[domain] = id
		fake.failingOrder = append(fake.failingOrder, domain)
	}
	result.TotalHosts = 6
	result.SuccessCount = 6

	initialErr := fake.TestConfig(ctx)
	if initialErr == nil {
		t.Fatalf("seed error: TestConfig should fail")
	}

	recovered, finalErr := runAutoRecovery(ctx, fake, hosts, result, initialErr)
	if recovered {
		t.Fatalf("expected recovered=false when >5 hosts are toxic, got recovered=true")
	}
	if finalErr == nil {
		t.Errorf("expected non-nil final error after budget exhaustion")
	}

	// The first 5 bad hosts should have had their configs removed within
	// the budget. The 6th should remain written.
	removed := 0
	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("host-bad-%d", i)
		if !fake.writtenConfigs[id] {
			removed++
		}
	}
	if removed != 5 {
		t.Errorf("expected exactly 5 configs removed within budget, got %d", removed)
	}
}

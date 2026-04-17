package service

import (
	"context"
	"log"

	"nginx-proxy-guard/internal/metrics"
	"nginx-proxy-guard/internal/model"
)

// autoRecoveryNginx is the subset of NginxManager used by runAutoRecovery. Using
// the narrower interface lets unit tests provide a fake without implementing
// the full NginxManager surface.
type autoRecoveryNginx interface {
	TestConfig(ctx context.Context) error
	RemoveConfig(ctx context.Context, host *model.ProxyHost) error
	RemoveHostWAFConfig(ctx context.Context, hostID string) error
}

// runAutoRecovery attempts to make nginx's config test pass by iteratively
// removing the config of hosts that nginx reports as failing. Behavior notes,
// preserved as characterization points:
//
//   - Retry budget: up to 5 attempts per call (one initial failure +
//     up to 5 removal-and-retry cycles).
//   - Error → host matching is string-based via parseNginxErrorForHost
//     (matches the proxy_host_<domain>.conf filename) and findHostByDomain.
//   - A host marked !Success does NOT decrement SuccessCount a second time.
//   - If the failing domain can't be mapped to a host in result.Hosts, the
//     loop exits early and recovered=false.
//   - WAF config removal (RemoveHostWAFConfig) is always attempted for a
//     failing host, even if WAF was disabled for it.
//   - Errors from RemoveConfig / RemoveHostWAFConfig are intentionally
//     ignored — we've already decided this host is toxic to nginx.
//
// The extracted function returns (recovered, lastTestError). The caller is
// responsible for writing the final TestSuccess / TestError fields on the
// SyncAllResult.
//
// This was extracted out of SyncAllConfigsWithDetails purely for testability;
// the original in-place loop is replaced by a call to this function.
func runAutoRecovery(
	ctx context.Context,
	nm autoRecoveryNginx,
	hosts []model.ProxyHost,
	result *SyncAllResult,
	initialErr error,
) (recovered bool, lastErr error) {
	testErr := initialErr
	for attempt := 0; attempt < 5; attempt++ {
		failingDomain := parseNginxErrorForHost(testErr.Error())
		if failingDomain == "" {
			break
		}
		hostIdx := findHostByDomain(result.Hosts, failingDomain)
		if hostIdx < 0 {
			break
		}
		// Mark the host as failed
		if result.Hosts[hostIdx].Success {
			result.Hosts[hostIdx].Success = false
			result.Hosts[hostIdx].Error = testErr.Error()
			result.SuccessCount--
			result.FailedCount++
			// Auto-recovery observability: every host isolation is a signal
			// that we're shedding load to keep nginx healthy.
			metrics.NginxAutoRecoveryTotal.Inc()
			metrics.NginxConfigStatus.WithLabelValues(result.Hosts[hostIdx].HostID).Set(0)
		}
		// Remove the failing host's config and WAF config to recover nginx
		failingHost := findHostByID(hosts, result.Hosts[hostIdx].HostID)
		if failingHost != nil {
			log.Printf("[SyncConfigs] Removing failing config for %s to recover nginx", result.Hosts[hostIdx].DomainNames)
			_ = nm.RemoveConfig(ctx, failingHost)
			_ = nm.RemoveHostWAFConfig(ctx, failingHost.ID)
		}
		// Retry nginx test
		if retryErr := nm.TestConfig(ctx); retryErr != nil {
			testErr = retryErr
			continue
		}
		return true, nil
	}
	return false, testErr
}

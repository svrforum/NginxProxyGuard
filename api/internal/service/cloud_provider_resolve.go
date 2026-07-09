package service

import (
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

// resolveCloudProviders collapses the global cloud-provider blocking default and
// a host's own settings into the single effective blocking settings the config
// consumes. 3-state, but cloud blocking has no explicit enabled flag — it is
// "active" when BlockedProviders is non-empty:
//
//	override: host blocks its own providers (len(host.BlockedProviders) > 0)
//	disable:  host opted out (host.CloudDisableGlobal) → block nothing
//	inherit:  no host providers, not disabled → use the global blocked list
func resolveCloudProviders(global *model.GlobalCloudProviders, host *repository.CloudProviderBlockingSettings) *repository.CloudProviderBlockingSettings {
	empty := &repository.CloudProviderBlockingSettings{BlockedProviders: []string{}}

	// Override: host runs its own cloud-provider blocking.
	if host != nil && len(host.BlockedProviders) > 0 {
		return host
	}
	// Disable: host opted out of the global default.
	if host != nil && host.CloudDisableGlobal {
		return empty
	}
	// Inherit: use the global default when it blocks anything.
	if global != nil && len(global.BlockedProviders) > 0 {
		return &repository.CloudProviderBlockingSettings{
			BlockedProviders: global.BlockedProviders,
			ChallengeMode:    global.ChallengeMode,
			AllowSearchBots:  global.AllowSearchBots,
		}
	}
	if host != nil {
		return host
	}
	return empty
}

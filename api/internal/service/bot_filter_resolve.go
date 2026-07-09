package service

import "nginx-proxy-guard/internal/model"

// resolveBotFilter collapses the global bot-filter default and a host's own
// bot_filter row into the single effective *model.BotFilter the template reads.
// Same 3-state as resolveGeo (override / disable / inherit). Bot filter has no
// side-reference fields, so inherit builds a fresh BotFilter from the global.
func resolveBotFilter(global *model.GlobalBotFilter, host *model.BotFilter) *model.BotFilter {
	// Override: host runs its own bot filter.
	if host != nil && host.Enabled {
		return host
	}
	// Disable: host opted out of the global default.
	if host != nil && host.DisableGlobal {
		return nil
	}
	// Inherit: use the global default when enabled.
	if global != nil && global.Enabled {
		return &model.BotFilter{
			Enabled:                true,
			BlockBadBots:           global.BlockBadBots,
			BlockAIBots:            global.BlockAIBots,
			AllowSearchEngines:     global.AllowSearchEngines,
			BlockSuspiciousClients: global.BlockSuspiciousClients,
			CustomBlockedAgents:    global.CustomBlockedAgents,
			CustomAllowedAgents:    global.CustomAllowedAgents,
			ChallengeSuspicious:    global.ChallengeSuspicious,
		}
	}
	return nil
}

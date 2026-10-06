package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestResolveBotFilter_Override_UsesHost(t *testing.T) {
	global := &model.GlobalBotFilter{Enabled: true, BlockBadBots: true, BlockAIBots: true}
	host := &model.BotFilter{Enabled: true, BlockBadBots: false, BlockAIBots: false}
	got := resolveBotFilter(global, host)
	if got != host {
		t.Fatalf("override should return the host row unchanged, got %+v", got)
	}
}

func TestResolveBotFilter_Disable_ReturnsNil(t *testing.T) {
	global := &model.GlobalBotFilter{Enabled: true, BlockBadBots: true}
	host := &model.BotFilter{Enabled: false, DisableGlobal: true}
	if got := resolveBotFilter(global, host); got != nil {
		t.Fatalf("disable should return nil, got %+v", got)
	}
}

func TestResolveBotFilter_Inherit_UsesGlobal(t *testing.T) {
	global := &model.GlobalBotFilter{
		Enabled: true, BlockBadBots: true, BlockAIBots: true,
		AllowSearchEngines: true, BlockSuspiciousClients: true,
		CustomBlockedAgents: "EvilBot", ChallengeSuspicious: true,
	}
	host := &model.BotFilter{Enabled: false, DisableGlobal: false}
	got := resolveBotFilter(global, host)
	if got == nil || !got.Enabled {
		t.Fatalf("inherit should return an enabled effective filter, got %+v", got)
	}
	if !got.BlockAIBots || !got.BlockSuspiciousClients || got.CustomBlockedAgents != "EvilBot" || !got.ChallengeSuspicious {
		t.Fatalf("inherit should copy global fields, got %+v", got)
	}
}

func TestResolveBotFilter_Inherit_GlobalOff_ReturnsNil(t *testing.T) {
	global := &model.GlobalBotFilter{Enabled: false, BlockBadBots: true}
	host := &model.BotFilter{Enabled: false, DisableGlobal: false}
	if got := resolveBotFilter(global, host); got != nil {
		t.Fatalf("inherit with global off should return nil, got %+v", got)
	}
}

func TestResolveBotFilter_NoHostRow_Inherits(t *testing.T) {
	global := &model.GlobalBotFilter{Enabled: true, BlockBadBots: true}
	got := resolveBotFilter(global, nil)
	if got == nil || !got.Enabled {
		t.Fatalf("no host row should inherit the enabled global, got %+v", got)
	}
}

func TestResolveBotFilter_NoHostRow_GlobalOff_Nil(t *testing.T) {
	global := &model.GlobalBotFilter{Enabled: false}
	if got := resolveBotFilter(global, nil); got != nil {
		t.Fatalf("no host row + global off should return nil, got %+v", got)
	}
}

// A path-limited allowed agent in the global default (#313) reaches every
// inheriting host as written; a host that overrides keeps only its own list,
// with nothing from the global list merged in.
func TestResolveBotFilter_AllowedAgents_InheritedVerbatim_NotMerged(t *testing.T) {
	global := &model.GlobalBotFilter{Enabled: true, BlockSuspiciousClients: true, CustomAllowedAgents: "okhttp @ /api"}
	if got := resolveBotFilter(global, nil); got == nil || got.CustomAllowedAgents != "okhttp @ /api" {
		t.Fatalf("inherit should carry the global list verbatim, got %+v", got)
	}
	host := &model.BotFilter{Enabled: true, CustomAllowedAgents: "GoodBot"}
	if got := resolveBotFilter(global, host); got.CustomAllowedAgents != "GoodBot" {
		t.Fatalf("override should use only the host list, got %q", got.CustomAllowedAgents)
	}
}

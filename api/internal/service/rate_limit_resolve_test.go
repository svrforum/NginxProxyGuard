package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestResolveRateLimit_Override_UsesHost(t *testing.T) {
	global := &model.GlobalRateLimit{Enabled: true, RequestsPerSecond: 10}
	host := &model.RateLimit{Enabled: true, RequestsPerSecond: 99}
	if got := resolveRateLimit(global, host, "h1"); got != host {
		t.Fatalf("override should return the host row unchanged, got %+v", got)
	}
}

func TestResolveRateLimit_Disable_ReturnsNil(t *testing.T) {
	global := &model.GlobalRateLimit{Enabled: true, RequestsPerSecond: 10}
	host := &model.RateLimit{Enabled: false, DisableGlobal: true}
	if got := resolveRateLimit(global, host, "h1"); got != nil {
		t.Fatalf("disable should return nil, got %+v", got)
	}
}

func TestResolveRateLimit_Inherit_UsesGlobalValuesWithHostZone(t *testing.T) {
	global := &model.GlobalRateLimit{Enabled: true, RequestsPerSecond: 25, BurstSize: 40, ZoneSize: "20m", LimitBy: "ip", LimitResponse: 503}
	host := &model.RateLimit{Enabled: false, DisableGlobal: false}
	got := resolveRateLimit(global, host, "host-xyz")
	if got == nil || !got.Enabled {
		t.Fatalf("inherit should return an enabled effective rate limit, got %+v", got)
	}
	if got.ProxyHostID != "host-xyz" {
		t.Fatalf("inherit must carry the host ID for a per-host zone, got %q", got.ProxyHostID)
	}
	if got.RequestsPerSecond != 25 || got.BurstSize != 40 || got.ZoneSize != "20m" || got.LimitResponse != 503 {
		t.Fatalf("inherit should copy global values, got %+v", got)
	}
}

func TestResolveRateLimit_Inherit_GlobalOff_ReturnsNil(t *testing.T) {
	global := &model.GlobalRateLimit{Enabled: false, RequestsPerSecond: 25}
	host := &model.RateLimit{Enabled: false, DisableGlobal: false}
	if got := resolveRateLimit(global, host, "h1"); got != nil {
		t.Fatalf("inherit with global off should return nil, got %+v", got)
	}
}

func TestResolveRateLimit_NoHostRow_Inherits(t *testing.T) {
	global := &model.GlobalRateLimit{Enabled: true, RequestsPerSecond: 30}
	got := resolveRateLimit(global, nil, "h9")
	if got == nil || !got.Enabled || got.ProxyHostID != "h9" || got.RequestsPerSecond != 30 {
		t.Fatalf("no host row should inherit the enabled global with the host zone, got %+v", got)
	}
}

func TestResolveRateLimit_NoHostRow_GlobalOff_Nil(t *testing.T) {
	if got := resolveRateLimit(&model.GlobalRateLimit{Enabled: false}, nil, "h1"); got != nil {
		t.Fatalf("no host row + global off should return nil, got %+v", got)
	}
}

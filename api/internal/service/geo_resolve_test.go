package service

import (
	"reflect"
	"sort"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func gg(enabled bool) *model.GlobalGeoRestriction {
	return &model.GlobalGeoRestriction{
		Enabled:         enabled,
		Mode:            "blacklist",
		Countries:       []string{"CN"},
		AllowedIPs:      []string{"9.9.9.9"},
		AllowPrivateIPs: true,
	}
}

func TestResolveGeo_Override_UsesHost(t *testing.T) {
	host := &model.GeoRestriction{Enabled: true, Mode: "whitelist", Countries: []string{"KR"}, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(true), host)
	if got == nil || got.Mode != "whitelist" || !reflect.DeepEqual(got.Countries, []string{"KR"}) {
		t.Fatalf("override must use host geo, got %+v", got)
	}
}

func TestResolveGeo_Disable_NoBlock_PreservesAllowedIPs(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: true, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(true), host)
	if got == nil || got.Enabled {
		t.Fatalf("disable must not produce an enabled geo block, got %+v", got)
	}
	if !reflect.DeepEqual(got.AllowedIPs, []string{"1.1.1.1"}) {
		t.Fatalf("disable must preserve host AllowedIPs for cloud/bot priority-allow, got %+v", got.AllowedIPs)
	}
}

func TestResolveGeo_Disable_NoAllowedIPs_Nil(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: true}
	if got := resolveGeo(gg(true), host); got != nil {
		t.Fatalf("disable with no AllowedIPs must be nil, got %+v", got)
	}
}

func TestResolveGeo_Inherit_UsesGlobal_UnionsHostAllowedIPs(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: false, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(true), host)
	if got == nil || !got.Enabled || got.Mode != "blacklist" {
		t.Fatalf("inherit must use enabled global geo, got %+v", got)
	}
	sorted := append([]string{}, got.AllowedIPs...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(sorted, []string{"1.1.1.1", "9.9.9.9"}) {
		t.Fatalf("inherit must union host+global AllowedIPs, got %+v", got.AllowedIPs)
	}
}

func TestResolveGeo_Inherit_GlobalOff_NoBlock(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: false}
	got := resolveGeo(gg(false), host)
	if got != nil && got.Enabled {
		t.Fatalf("global off + inherit must not block, got %+v", got)
	}
}

func TestResolveGeo_Inherit_GlobalOff_KeepsHostAllowedIPs(t *testing.T) {
	host := &model.GeoRestriction{Enabled: false, DisableGlobal: false, AllowedIPs: []string{"1.1.1.1"}}
	got := resolveGeo(gg(false), host)
	if got == nil || got.Enabled || !reflect.DeepEqual(got.AllowedIPs, []string{"1.1.1.1"}) {
		t.Fatalf("global off must keep host AllowedIPs disabled, got %+v", got)
	}
}

func TestResolveGeo_NoHostRow_Inherits(t *testing.T) {
	got := resolveGeo(gg(true), nil)
	if got == nil || !got.Enabled {
		t.Fatalf("no host row must inherit enabled global, got %+v", got)
	}
}

func TestResolveGeo_NoHostRow_GlobalOff_Nil(t *testing.T) {
	if got := resolveGeo(gg(false), nil); got != nil {
		t.Fatalf("no host + global off must be nil, got %+v", got)
	}
}

package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestResolveSecurityHeaders_Override_UsesHost(t *testing.T) {
	global := &model.GlobalSecurityHeaders{Enabled: true, XFrameOptions: "DENY"}
	host := &model.SecurityHeaders{Enabled: true, XFrameOptions: "SAMEORIGIN"}
	if got := resolveSecurityHeaders(global, host); got != host {
		t.Fatalf("override should return the host row unchanged, got %+v", got)
	}
}

func TestResolveSecurityHeaders_Disable_ReturnsNil(t *testing.T) {
	global := &model.GlobalSecurityHeaders{Enabled: true}
	host := &model.SecurityHeaders{Enabled: false, DisableGlobal: true}
	if got := resolveSecurityHeaders(global, host); got != nil {
		t.Fatalf("disable should return nil, got %+v", got)
	}
}

func TestResolveSecurityHeaders_Inherit_UsesGlobal(t *testing.T) {
	global := &model.GlobalSecurityHeaders{
		Enabled: true, HSTSEnabled: true, HSTSMaxAge: 12345, XFrameOptions: "DENY",
		ReferrerPolicy: "no-referrer", ContentSecurityPolicy: "default-src 'self'",
	}
	host := &model.SecurityHeaders{Enabled: false, DisableGlobal: false}
	got := resolveSecurityHeaders(global, host)
	if got == nil || !got.Enabled {
		t.Fatalf("inherit should return an enabled effective config, got %+v", got)
	}
	if got.HSTSMaxAge != 12345 || got.XFrameOptions != "DENY" || got.ContentSecurityPolicy != "default-src 'self'" {
		t.Fatalf("inherit should copy global fields, got %+v", got)
	}
}

func TestResolveSecurityHeaders_Inherit_GlobalOff_ReturnsNil(t *testing.T) {
	global := &model.GlobalSecurityHeaders{Enabled: false}
	host := &model.SecurityHeaders{Enabled: false, DisableGlobal: false}
	if got := resolveSecurityHeaders(global, host); got != nil {
		t.Fatalf("inherit with global off should return nil, got %+v", got)
	}
}

func TestResolveSecurityHeaders_NoHostRow_Inherits(t *testing.T) {
	global := &model.GlobalSecurityHeaders{Enabled: true, XFrameOptions: "DENY"}
	got := resolveSecurityHeaders(global, nil)
	if got == nil || !got.Enabled || got.XFrameOptions != "DENY" {
		t.Fatalf("no host row should inherit the enabled global, got %+v", got)
	}
}

func TestResolveSecurityHeaders_NoHostRow_GlobalOff_Nil(t *testing.T) {
	if got := resolveSecurityHeaders(&model.GlobalSecurityHeaders{Enabled: false}, nil); got != nil {
		t.Fatalf("no host row + global off should return nil, got %+v", got)
	}
}

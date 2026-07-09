package service

import (
	"testing"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/repository"
)

func TestResolveCloudProviders_Override_UsesHost(t *testing.T) {
	global := &model.GlobalCloudProviders{BlockedProviders: []string{"aws"}}
	host := &repository.CloudProviderBlockingSettings{BlockedProviders: []string{"gcp"}, ChallengeMode: true}
	got := resolveCloudProviders(global, host)
	if got != host {
		t.Fatalf("override should return the host settings unchanged, got %+v", got)
	}
}

func TestResolveCloudProviders_Disable_ReturnsEmpty(t *testing.T) {
	global := &model.GlobalCloudProviders{BlockedProviders: []string{"aws"}}
	host := &repository.CloudProviderBlockingSettings{BlockedProviders: []string{}, CloudDisableGlobal: true}
	got := resolveCloudProviders(global, host)
	if len(got.BlockedProviders) != 0 {
		t.Fatalf("disable should block nothing, got %+v", got)
	}
}

func TestResolveCloudProviders_Inherit_UsesGlobal(t *testing.T) {
	global := &model.GlobalCloudProviders{BlockedProviders: []string{"aws", "gcp"}, ChallengeMode: true, AllowSearchBots: true}
	host := &repository.CloudProviderBlockingSettings{BlockedProviders: []string{}}
	got := resolveCloudProviders(global, host)
	if len(got.BlockedProviders) != 2 || !got.ChallengeMode || !got.AllowSearchBots {
		t.Fatalf("inherit should copy the global blocked list + flags, got %+v", got)
	}
}

func TestResolveCloudProviders_Inherit_GlobalEmpty_ReturnsHostEmpty(t *testing.T) {
	global := &model.GlobalCloudProviders{BlockedProviders: []string{}}
	host := &repository.CloudProviderBlockingSettings{BlockedProviders: []string{}}
	got := resolveCloudProviders(global, host)
	if len(got.BlockedProviders) != 0 {
		t.Fatalf("inherit with empty global should block nothing, got %+v", got)
	}
}

func TestResolveCloudProviders_NilHost_InheritsGlobal(t *testing.T) {
	global := &model.GlobalCloudProviders{BlockedProviders: []string{"azure"}}
	got := resolveCloudProviders(global, nil)
	if len(got.BlockedProviders) != 1 || got.BlockedProviders[0] != "azure" {
		t.Fatalf("nil host should inherit the global blocked list, got %+v", got)
	}
}

package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"nginx-proxy-guard/internal/model"
)

type fakeProvRepo struct {
	prov    *model.DNSProvider
	testErr error
	gotType string
}

// Implement the full dnsProviderRepo interface; only GetByID/TestConnection matter here.
func (f *fakeProvRepo) GetByID(context.Context, string) (*model.DNSProvider, error) { return f.prov, nil }
func (f *fakeProvRepo) TestConnection(_ context.Context, providerType string, _ json.RawMessage) error {
	f.gotType = providerType
	return f.testErr
}
func (f *fakeProvRepo) Create(context.Context, *model.CreateDNSProviderRequest) (*model.DNSProvider, error) {
	return nil, nil
}
func (f *fakeProvRepo) GetDefault(context.Context) (*model.DNSProvider, error) { return nil, nil }
func (f *fakeProvRepo) List(context.Context, int, int) ([]model.DNSProvider, int, error) {
	return nil, 0, nil
}
func (f *fakeProvRepo) Update(context.Context, string, *model.UpdateDNSProviderRequest) (*model.DNSProvider, error) {
	return nil, nil
}
func (f *fakeProvRepo) Delete(context.Context, string) error { return nil }

func TestTestConnectionByID_LoadsAndDelegates(t *testing.T) {
	f := &fakeProvRepo{prov: &model.DNSProvider{ProviderType: "duckdns"}, testErr: errors.New("bad token")}
	s := &DNSProviderService{repo: f}
	err := s.TestConnectionByID(context.Background(), "p1")
	if err == nil || f.gotType != "duckdns" {
		t.Fatalf("expected delegated test with type=duckdns and error, got type=%q err=%v", f.gotType, err)
	}
}

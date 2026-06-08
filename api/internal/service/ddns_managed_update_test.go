package service

import (
	"context"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// captureRecRepo returns a fixed record from GetByID and records the request
// passed to Update, so we can assert what DDNSService.Update forwards.
type captureRecRepo struct {
	get    *model.DDNSRecord
	gotReq *model.UpdateDDNSRecordRequest
}

func (c *captureRecRepo) Create(context.Context, *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (c *captureRecRepo) GetByID(context.Context, string) (*model.DDNSRecord, error) { return c.get, nil }
func (c *captureRecRepo) List(context.Context, int, int) ([]model.DDNSRecord, int, error) {
	return nil, 0, nil
}
func (c *captureRecRepo) Update(_ context.Context, _ string, req *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	c.gotReq = req
	return &model.DDNSRecord{}, nil
}
func (c *captureRecRepo) Delete(context.Context, string) error                    { return nil }
func (c *captureRecRepo) ListEnabled(context.Context) ([]model.DDNSRecord, error) { return nil, nil }
func (c *captureRecRepo) ListByProxyHost(context.Context, string) ([]model.DDNSRecord, error) {
	return nil, nil
}
func (c *captureRecRepo) UpdateStatus(context.Context, string, string, string, string, time.Time) error {
	return nil
}

// TestUpdate_ManagedRecordIdentityImmutable pins issue #160: a DDNS record
// managed by a proxy host (ProxyHostID set) must not have its hostname or DNS
// provider changed via Update (that would orphan it on the next reconcile), but
// editable fields like proxied must still pass through. Unmanaged records are
// fully editable.
func TestUpdate_ManagedRecordIdentityImmutable(t *testing.T) {
	hostID := "host-1"
	newName := "evil.example.com"
	newProvider := "p2"
	proxied := true

	// Managed: identity changes stripped, proxied preserved.
	c := &captureRecRepo{get: &model.DDNSRecord{ID: "r1", ProxyHostID: &hostID}}
	svc := NewDDNSService(c, fakeCreds{}, fakeDetector{})
	if _, err := svc.Update(context.Background(), "r1", &model.UpdateDDNSRecordRequest{
		Hostname: &newName, DNSProviderID: &newProvider, Proxied: &proxied,
	}); err != nil {
		t.Fatalf("Update (managed): %v", err)
	}
	if c.gotReq.Hostname != nil {
		t.Errorf("managed record: Hostname change must be stripped, got %q", *c.gotReq.Hostname)
	}
	if c.gotReq.DNSProviderID != nil {
		t.Errorf("managed record: DNSProviderID change must be stripped, got %q", *c.gotReq.DNSProviderID)
	}
	if c.gotReq.Proxied == nil || !*c.gotReq.Proxied {
		t.Errorf("managed record: Proxied must pass through unchanged")
	}

	// Unmanaged: identity changes pass through.
	c2 := &captureRecRepo{get: &model.DDNSRecord{ID: "r2", ProxyHostID: nil}}
	svc2 := NewDDNSService(c2, fakeCreds{}, fakeDetector{})
	if _, err := svc2.Update(context.Background(), "r2", &model.UpdateDDNSRecordRequest{
		Hostname: &newName,
	}); err != nil {
		t.Fatalf("Update (unmanaged): %v", err)
	}
	if c2.gotReq.Hostname == nil || *c2.gotReq.Hostname != newName {
		t.Errorf("unmanaged record: Hostname change must pass through")
	}
}

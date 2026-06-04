package service

import (
	"context"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// fakeRecRepo: only the methods SyncByProxyHost needs.
type fakeRecRepo struct {
	byHost  map[string][]model.DDNSRecord
	updated []string // record IDs that got UpdateStatus
}

func (f *fakeRecRepo) Create(context.Context, *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (f *fakeRecRepo) GetByID(context.Context, string) (*model.DDNSRecord, error) { return nil, nil }
func (f *fakeRecRepo) List(context.Context, int, int) ([]model.DDNSRecord, int, error) {
	return nil, 0, nil
}
func (f *fakeRecRepo) Update(context.Context, string, *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (f *fakeRecRepo) Delete(context.Context, string) error                    { return nil }
func (f *fakeRecRepo) ListEnabled(context.Context) ([]model.DDNSRecord, error) { return nil, nil }
func (f *fakeRecRepo) ListByProxyHost(_ context.Context, id string) ([]model.DDNSRecord, error) {
	return f.byHost[id], nil
}
func (f *fakeRecRepo) UpdateStatus(_ context.Context, id, _, _, _ string, _ time.Time) error {
	f.updated = append(f.updated, id)
	return nil
}

type fakeCreds struct{}

func (fakeCreds) GetByID(context.Context, string) (*model.DNSProvider, error) {
	// provider not found -> syncRecord records error via UpdateStatus, which is what we assert.
	return nil, nil
}

type fakeDetector struct{}

func (fakeDetector) DetectPublicIPv4(context.Context) (string, error) { return "203.0.113.9", nil }

func TestSyncByProxyHost_OnlyHostEnabledRecords(t *testing.T) {
	rec := func(id string, enabled bool) model.DDNSRecord {
		return model.DDNSRecord{ID: id, Hostname: id + ".example", DNSProviderID: "p1", Enabled: enabled}
	}
	f := &fakeRecRepo{byHost: map[string][]model.DDNSRecord{
		"hostA": {rec("a1", true), rec("a2", false)}, // a2 disabled -> skipped
	}}
	svc := NewDDNSService(f, fakeCreds{}, fakeDetector{})

	svc.SyncByProxyHost(context.Background(), "hostA")

	// a1 attempted (provider-not-found path still calls UpdateStatus once); a2 skipped.
	if len(f.updated) != 1 || f.updated[0] != "a1" {
		t.Fatalf("expected only a1 synced, got %v", f.updated)
	}
}

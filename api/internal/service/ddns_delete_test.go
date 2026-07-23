package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"nginx-proxy-guard/internal/model"
)

// deleteRepo records whether the DB row was deleted and serves a fixed record.
type deleteRepo struct {
	rec     *model.DDNSRecord
	deleted bool
}

func (r *deleteRepo) Create(context.Context, *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (r *deleteRepo) GetByID(context.Context, string) (*model.DDNSRecord, error) { return r.rec, nil }
func (r *deleteRepo) List(context.Context, int, int) ([]model.DDNSRecord, int, error) {
	return nil, 0, nil
}
func (r *deleteRepo) Update(context.Context, string, *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (r *deleteRepo) Delete(context.Context, string) error                    { r.deleted = true; return nil }
func (r *deleteRepo) ListEnabled(context.Context) ([]model.DDNSRecord, error) { return nil, nil }
func (r *deleteRepo) ListByProxyHost(context.Context, string) ([]model.DDNSRecord, error) {
	return nil, nil
}
func (r *deleteRepo) UpdateStatus(context.Context, string, string, string, string, time.Time) error {
	return nil
}

// cfProviderRepo always returns a Cloudflare provider (which supports deletion).
type cfProviderRepo struct{}

func (cfProviderRepo) GetByID(context.Context, string) (*model.DNSProvider, error) {
	return &model.DNSProvider{ProviderType: model.DNSProviderCloudflare, Credentials: json.RawMessage(`{}`)}, nil
}

// recordingDeleter implements ddnsUpdater + ddnsDeleter and records the Delete call.
type recordingDeleter struct{ called bool }

func (d *recordingDeleter) Update(context.Context, model.DDNSRecord, json.RawMessage, string) error {
	return nil
}
func (d *recordingDeleter) Delete(context.Context, model.DDNSRecord, json.RawMessage) error {
	d.called = true
	return nil
}

// The user can opt out of provider-side deletion (unchecking "also remove from
// Cloudflare"): the DB row is always removed, but the provider record is only
// deleted when removeProvider is true. (#215)
func TestDelete_RemoveProviderGating(t *testing.T) {
	for _, tc := range []struct {
		name               string
		removeProvider     bool
		wantProviderDelete bool
	}{
		{"remove provider", true, true},
		{"keep provider", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &deleteRepo{rec: &model.DDNSRecord{ID: "r1", Hostname: "h.example.com", DNSProviderID: "p1"}}
			del := &recordingDeleter{}
			svc := NewDDNSService(repo, cfProviderRepo{}, fakeDetector{})
			svc.updaters[model.DNSProviderCloudflare] = del

			if err := svc.Delete(context.Background(), "r1", tc.removeProvider); err != nil {
				t.Fatalf("Delete: %v", err)
			}
			if !repo.deleted {
				t.Fatal("DB row must always be deleted")
			}
			if del.called != tc.wantProviderDelete {
				t.Fatalf("provider delete called=%v, want %v", del.called, tc.wantProviderDelete)
			}
		})
	}
}

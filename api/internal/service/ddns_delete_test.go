package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
// failWith makes the provider deletion fail, so tests can prove the DB cleanup
// still happens on a provider outage.
type recordingDeleter struct {
	called   bool
	hosts    []string
	failWith error
}

func (d *recordingDeleter) Update(context.Context, model.DDNSRecord, json.RawMessage, string) error {
	return nil
}
func (d *recordingDeleter) Delete(_ context.Context, rec model.DDNSRecord, _ json.RawMessage) error {
	d.called = true
	d.hosts = append(d.hosts, rec.Hostname)
	return d.failWith
}

// hostRecordsRepo serves a proxy host's managed records and records which rows
// were deleted, for the host-scoped cleanup path. (#219)
type hostRecordsRepo struct {
	recs    []model.DDNSRecord
	deleted []string
	listErr error
}

func (r *hostRecordsRepo) Create(context.Context, *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (r *hostRecordsRepo) GetByID(context.Context, string) (*model.DDNSRecord, error) { return nil, nil }
func (r *hostRecordsRepo) List(context.Context, int, int) ([]model.DDNSRecord, int, error) {
	return nil, 0, nil
}
func (r *hostRecordsRepo) Update(context.Context, string, *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return nil, nil
}
func (r *hostRecordsRepo) Delete(_ context.Context, id string) error {
	r.deleted = append(r.deleted, id)
	return nil
}
func (r *hostRecordsRepo) ListEnabled(context.Context) ([]model.DDNSRecord, error) { return nil, nil }
func (r *hostRecordsRepo) ListByProxyHost(context.Context, string) ([]model.DDNSRecord, error) {
	return r.recs, r.listErr
}
func (r *hostRecordsRepo) UpdateStatus(context.Context, string, string, string, string, time.Time) error {
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

// A host can hold one managed record per domain, so the host-scoped cleanup must
// iterate all of them; and because deleting live DNS is best-effort, a provider
// failure must never leave the NPG rows behind. (#219)
func TestDeleteManagedByProxyHost(t *testing.T) {
	recs := []model.DDNSRecord{
		{ID: "r1", Hostname: "a.example.com", DNSProviderID: "p1"},
		{ID: "r2", Hostname: "b.example.com", DNSProviderID: "p1"},
	}

	t.Run("removes every record at the provider and in the DB", func(t *testing.T) {
		repo := &hostRecordsRepo{recs: recs}
		del := &recordingDeleter{}
		svc := NewDDNSService(repo, cfProviderRepo{}, fakeDetector{})
		svc.updaters[model.DNSProviderCloudflare] = del

		if err := svc.DeleteManagedByProxyHost(context.Background(), "host-1"); err != nil {
			t.Fatalf("DeleteManagedByProxyHost: %v", err)
		}
		if got, want := strings.Join(del.hosts, ","), "a.example.com,b.example.com"; got != want {
			t.Fatalf("provider delete called for %q, want %q", got, want)
		}
		if got, want := strings.Join(repo.deleted, ","), "r1,r2"; got != want {
			t.Fatalf("deleted rows %q, want %q", got, want)
		}
	})

	t.Run("provider failure still deletes the rows", func(t *testing.T) {
		repo := &hostRecordsRepo{recs: recs}
		del := &recordingDeleter{failWith: errors.New("cloudflare unreachable")}
		svc := NewDDNSService(repo, cfProviderRepo{}, fakeDetector{})
		svc.updaters[model.DNSProviderCloudflare] = del

		if err := svc.DeleteManagedByProxyHost(context.Background(), "host-1"); err != nil {
			t.Fatalf("provider failure must not surface as an error: %v", err)
		}
		if got, want := strings.Join(repo.deleted, ","), "r1,r2"; got != want {
			t.Fatalf("deleted rows %q, want %q despite the provider error", got, want)
		}
	})

	t.Run("no managed records is a no-op", func(t *testing.T) {
		repo := &hostRecordsRepo{}
		del := &recordingDeleter{}
		svc := NewDDNSService(repo, cfProviderRepo{}, fakeDetector{})
		svc.updaters[model.DNSProviderCloudflare] = del

		if err := svc.DeleteManagedByProxyHost(context.Background(), "host-1"); err != nil {
			t.Fatalf("DeleteManagedByProxyHost: %v", err)
		}
		if del.called || len(repo.deleted) != 0 {
			t.Fatal("nothing should have been deleted")
		}
	})
}

package service

import (
	"context"
	"errors"
	"testing"

	"nginx-proxy-guard/internal/model"
)

// provCheckRecRepo counts the writes that reach the record repository.
type provCheckRecRepo struct {
	fakeRecRepo
	existing *model.DDNSRecord
	created  int
	updated  int
}

func (f *provCheckRecRepo) Create(context.Context, *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	f.created++
	return &model.DDNSRecord{}, nil
}

func (f *provCheckRecRepo) GetByID(context.Context, string) (*model.DDNSRecord, error) {
	return f.existing, nil
}

func (f *provCheckRecRepo) Update(context.Context, string, *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	f.updated++
	return &model.DDNSRecord{}, nil
}

// oneProvider knows a single DNS provider.
type oneProvider struct{ id string }

func (p oneProvider) GetByID(_ context.Context, id string) (*model.DNSProvider, error) {
	if id == p.id {
		return &model.DNSProvider{ID: id}, nil
	}
	return nil, nil
}

// A dns_provider_id that names no DNS provider is invalid input (400), not
// a foreign-key or uuid error from the database (500) (#344).
func TestDDNSProviderMustExist(t *testing.T) {
	const known = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	const unknown = "123e4567-e89b-12d3-a456-426614174000"
	str := func(s string) *string { return &s }
	managed := &model.DDNSRecord{ProxyHostID: str("host-1")}

	tests := []struct {
		name     string
		create   *model.CreateDDNSRecordRequest
		update   *model.UpdateDDNSRecordRequest
		existing *model.DDNSRecord
		invalid  bool
	}{
		{name: "create, known provider", create: &model.CreateDDNSRecordRequest{Hostname: "a.example.com", DNSProviderID: known}},
		{name: "create, unknown provider", create: &model.CreateDDNSRecordRequest{Hostname: "a.example.com", DNSProviderID: unknown}, invalid: true},
		{name: "create, not a uuid", create: &model.CreateDDNSRecordRequest{Hostname: "a.example.com", DNSProviderID: "not-a-uuid"}, invalid: true},
		{name: "update, unknown provider", update: &model.UpdateDDNSRecordRequest{DNSProviderID: str(unknown)}, existing: &model.DDNSRecord{}, invalid: true},
		{name: "update, provider unchanged", update: &model.UpdateDDNSRecordRequest{TTL: new(int)}, existing: &model.DDNSRecord{}},
		// A host-managed record ignores dns_provider_id (#160), so it is not checked.
		{name: "update, host-managed record", update: &model.UpdateDDNSRecordRequest{DNSProviderID: str(unknown)}, existing: managed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recs := &provCheckRecRepo{existing: tt.existing}
			svc := NewDDNSService(recs, oneProvider{id: known}, fakeDetector{})
			var err error
			if tt.create != nil {
				_, err = svc.Create(context.Background(), tt.create)
			} else {
				_, err = svc.Update(context.Background(), "rec-1", tt.update)
			}
			if got := errors.Is(err, model.ErrInvalidInput); got != tt.invalid {
				t.Fatalf("invalid input = %v (err %v), want %v", got, err, tt.invalid)
			}
			writes := recs.created + recs.updated
			if tt.invalid && writes != 0 {
				t.Fatalf("rejected request reached the repository (%d writes)", writes)
			}
			if !tt.invalid && writes != 1 {
				t.Fatalf("accepted request made %d writes, want 1", writes)
			}
		})
	}
}

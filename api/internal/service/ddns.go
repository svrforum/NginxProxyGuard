package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"nginx-proxy-guard/internal/model"
)

// ddnsUpdater applies the public IP to a single record via its provider.
type ddnsUpdater interface {
	Update(ctx context.Context, rec model.DDNSRecord, creds json.RawMessage, ip string) error
}

// ddnsRecordRepo is the narrow record-repo dependency (interface for testability).
type ddnsRecordRepo interface {
	Create(ctx context.Context, req *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error)
	GetByID(ctx context.Context, id string) (*model.DDNSRecord, error)
	List(ctx context.Context, page, perPage int) ([]model.DDNSRecord, int, error)
	Update(ctx context.Context, id string, req *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error)
	Delete(ctx context.Context, id string) error
	ListEnabled(ctx context.Context) ([]model.DDNSRecord, error)
	ListByProxyHost(ctx context.Context, proxyHostID string) ([]model.DDNSRecord, error)
	UpdateStatus(ctx context.Context, id, ip, status, errMsg string, syncedAt time.Time) error
}

// ddnsCredsRepo provides DNS-provider credentials by ID.
type ddnsCredsRepo interface {
	GetByID(ctx context.Context, id string) (*model.DNSProvider, error)
}

// publicIPDetector resolves the server's current public IPv4.
type publicIPDetector interface {
	DetectPublicIPv4(ctx context.Context) (string, error)
}

// DDNSService orchestrates DDNS record CRUD and syncing the public IP to the
// configured provider (Cloudflare/DuckDNS in v1). (#154)
type DDNSService struct {
	records   ddnsRecordRepo
	providers ddnsCredsRepo
	detector  publicIPDetector
	updaters  map[string]ddnsUpdater
	now       func() time.Time
}

func NewDDNSService(records ddnsRecordRepo, providers ddnsCredsRepo, detector publicIPDetector) *DDNSService {
	return &DDNSService{
		records:   records,
		providers: providers,
		detector:  detector,
		updaters: map[string]ddnsUpdater{
			model.DNSProviderCloudflare: newCloudflareUpdater(),
			model.DNSProviderDuckDNS:    newDuckDNSUpdater(),
		},
		now: time.Now,
	}
}

// needsUpdate decides whether a record must be (re)synced for the detected IP.
func needsUpdate(rec model.DDNSRecord, ip string) bool {
	if rec.LastStatus != model.DDNSStatusOK {
		return true // never synced ok, or last attempt errored -> (re)try
	}
	return rec.LastIP != ip
}

// SyncAll detects the public IP once and syncs every enabled record.
func (s *DDNSService) SyncAll(ctx context.Context) {
	ip, err := s.detector.DetectPublicIPv4(ctx)
	if err != nil {
		log.Printf("[DDNS] public IP detection failed, skipping run: %v", err)
		return
	}
	recs, err := s.records.ListEnabled(ctx)
	if err != nil {
		log.Printf("[DDNS] list enabled records failed: %v", err)
		return
	}
	for _, rec := range recs {
		if !needsUpdate(rec, ip) {
			continue
		}
		s.syncRecord(ctx, rec, ip)
	}
}

// SyncByProxyHost immediately syncs the managed records of a single proxy host
// (used right after a host opts into DDNS, instead of waiting for the scheduler).
// Graceful: per-record failures are recorded as last_status='error' (no panic/return). (#157 follow-up)
func (s *DDNSService) SyncByProxyHost(ctx context.Context, proxyHostID string) {
	ip, err := s.detector.DetectPublicIPv4(ctx)
	if err != nil {
		log.Printf("[DDNS] public IP detection failed for host %s, skipping immediate sync: %v", proxyHostID, err)
		return
	}
	recs, err := s.records.ListByProxyHost(ctx, proxyHostID)
	if err != nil {
		log.Printf("[DDNS] list managed records failed for host %s: %v", proxyHostID, err)
		return
	}
	for _, rec := range recs {
		if !rec.Enabled {
			continue
		}
		s.syncRecord(ctx, rec, ip) // force sync (first sync after enabling), no needsUpdate gate
	}
}

// SyncOne forces a sync of a single record (manual "update now").
func (s *DDNSService) SyncOne(ctx context.Context, id string) error {
	rec, err := s.records.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if rec == nil {
		return model.ErrNotFound
	}
	ip, err := s.detector.DetectPublicIPv4(ctx)
	if err != nil {
		return fmt.Errorf("public IP detection failed: %w", err)
	}
	return s.syncRecord(ctx, *rec, ip)
}

func (s *DDNSService) syncRecord(ctx context.Context, rec model.DDNSRecord, ip string) error {
	prov, err := s.providers.GetByID(ctx, rec.DNSProviderID)
	if err != nil {
		s.records.UpdateStatus(ctx, rec.ID, rec.LastIP, model.DDNSStatusError, "provider not found: "+err.Error(), s.now())
		return err
	}
	if prov == nil {
		msg := "provider not found"
		s.records.UpdateStatus(ctx, rec.ID, rec.LastIP, model.DDNSStatusError, msg, s.now())
		return fmt.Errorf("%s", msg)
	}
	updater, ok := s.updaters[prov.ProviderType]
	if !ok {
		msg := fmt.Sprintf("provider %q not supported for DDNS", prov.ProviderType)
		s.records.UpdateStatus(ctx, rec.ID, rec.LastIP, model.DDNSStatusError, msg, s.now())
		return fmt.Errorf("%s", msg)
	}
	if err := updater.Update(ctx, rec, prov.Credentials, ip); err != nil {
		log.Printf("[DDNS] %s update failed for %s: %v", prov.ProviderType, rec.Hostname, err)
		s.records.UpdateStatus(ctx, rec.ID, rec.LastIP, model.DDNSStatusError, err.Error(), s.now())
		return err
	}
	log.Printf("[DDNS] %s -> %s (%s)", rec.Hostname, ip, prov.ProviderType)
	return s.records.UpdateStatus(ctx, rec.ID, ip, model.DDNSStatusOK, "", s.now())
}

// --- CRUD delegation (handler -> service -> records repo) ---

// Create persists a new DDNS record.
func (s *DDNSService) Create(ctx context.Context, req *model.CreateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return s.records.Create(ctx, req)
}

// GetByID retrieves a single DDNS record.
func (s *DDNSService) GetByID(ctx context.Context, id string) (*model.DDNSRecord, error) {
	return s.records.GetByID(ctx, id)
}

// List retrieves DDNS records with pagination.
func (s *DDNSService) List(ctx context.Context, page, perPage int) (*model.DDNSRecordListResponse, error) {
	records, total, err := s.records.List(ctx, page, perPage)
	if err != nil {
		return nil, err
	}
	if records == nil {
		records = []model.DDNSRecord{}
	}
	totalPages := 0
	if perPage > 0 {
		totalPages = (total + perPage - 1) / perPage
	}
	return &model.DDNSRecordListResponse{
		Data:       records,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: totalPages,
	}, nil
}

// Update applies a partial update to a DDNS record.
func (s *DDNSService) Update(ctx context.Context, id string, req *model.UpdateDDNSRecordRequest) (*model.DDNSRecord, error) {
	return s.records.Update(ctx, id, req)
}

// Delete removes a DDNS record.
func (s *DDNSService) Delete(ctx context.Context, id string) error {
	return s.records.Delete(ctx, id)
}

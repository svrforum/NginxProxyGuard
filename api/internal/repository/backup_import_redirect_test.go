package repository

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/model"
)

func TestImportRedirectHostSkipsInvalidLegacyRowBeforeDatabaseWrite(t *testing.T) {
	repo := &BackupRepository{}
	exported := &model.RedirectHostExport{}
	exported.RedirectHost.DomainNames = []string{"legacy.example.com"}
	exported.RedirectHost.ForwardScheme = "https"
	exported.RedirectHost.ForwardDomainName = "target.example.com"
	exported.RedirectHost.ForwardPath = "/$http_authorization"
	exported.RedirectHost.RedirectCode = 301
	exported.RedirectHost.Enabled = true

	// A nil transaction is intentional: an unsafe row must be skipped before
	// any DB call, allowing the surrounding backup transaction to continue.
	if err := repo.importRedirectHost(context.Background(), nil, exported); err != nil {
		t.Fatalf("invalid legacy redirect aborted backup import: %v", err)
	}
}

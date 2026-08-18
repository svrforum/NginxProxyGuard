package repository

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/lib/pq"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// Guards #253: certificates were shipped with their private key material
// silently emptied. Two independent mechanisms did it, and neither had a test:
//
//  1. Create's RETURNING list omitted the PEM columns, so UploadCustom's
//     `cert, err = repo.Create(...)` replaced the struct that held the uploaded
//     key with one that did not — and the follow-up write put those empty
//     values back into the row. Every custom certificate upload since v1.0.1.
//  2. Update rewrote all four secret columns from whatever struct it was
//     handed, so any caller that only meant to change a status (mark renewing,
//     record a renewal error) wiped the material.
//
// TestCertificateWriteStatementsNeverBlankMaterial is the always-on guard on
// the statements themselves; TestCertificateMaterialRoundTrip exercises the
// real thing when a database is available (NPG_TEST_DATABASE_URL, e.g.
// postgres://postgres:...@npg-test-db:5432/nginx_guard_test?sslmode=disable).

func TestCertificateWriteStatementsNeverBlankMaterial(t *testing.T) {
	src, err := os.ReadFile("certificate.go")
	if err != nil {
		t.Fatalf("read certificate.go: %v", err)
	}
	body := string(src)

	createBody := funcBody(t, body, "func (r *CertificateRepository) Create(")
	// The RETURNING list only, so a comment mentioning a column further down
	// cannot satisfy the check.
	returning := createBody[strings.Index(createBody, "RETURNING"):]
	if end := strings.Index(returning, "`"); end > 0 {
		returning = returning[:end]
	}
	for _, col := range []string{"certificate_pem", "private_key_pem", "issuer_certificate_pem", "acme_account"} {
		if !strings.Contains(returning, col) {
			t.Errorf("Create must RETURN %s: a partial RETURNING hands the caller a certificate with no key material (#253)", col)
		}
	}

	updateBody := funcBody(t, body, "func (r *CertificateRepository) Update(")
	for _, col := range []string{"certificate_pem", "private_key_pem", "issuer_certificate_pem", "acme_account"} {
		if strings.Contains(updateBody, col) {
			t.Errorf("Update must not write %s — metadata-only writers would destroy key material (#253); use UpdateWithMaterial", col)
		}
	}
}

// funcBody returns the source of the function starting at prefix, up to the
// closing brace in column 0.
func funcBody(t *testing.T, src, prefix string) string {
	t.Helper()
	start := strings.Index(src, prefix)
	if start < 0 {
		t.Fatalf("function %q not found in certificate.go", prefix)
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("end of function %q not found", prefix)
	}
	return src[start : start+end]
}

func TestCertificateMaterialRoundTrip(t *testing.T) {
	dsn := os.Getenv("NPG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NPG_TEST_DATABASE_URL not set; skipping live database round-trip")
	}

	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping database: %v", err)
	}

	repo := NewCertificateRepository(&database.DB{DB: sqlDB})
	ctx := context.Background()

	const (
		certPEM   = "-----BEGIN CERTIFICATE-----\nROUNDTRIP-CERT\n-----END CERTIFICATE-----\n"
		keyPEM    = "-----BEGIN PRIVATE KEY-----\nROUNDTRIP-KEY\n-----END PRIVATE KEY-----\n"
		issuerPEM = "-----BEGIN CERTIFICATE-----\nROUNDTRIP-ISSUER\n-----END CERTIFICATE-----\n"
	)

	created, err := repo.Create(ctx, &model.Certificate{
		DomainNames:          pq.StringArray{"roundtrip.test.example.com"},
		Provider:             model.CertProviderCustom,
		Status:               model.CertStatusIssued,
		CertificatePEM:       certPEM,
		PrivateKeyPEM:        keyPEM,
		IssuerCertificatePEM: issuerPEM,
		AcmeAccount:          []byte(`{"account":"roundtrip"}`),
	})
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	defer func() {
		if _, err := sqlDB.Exec(`DELETE FROM certificates WHERE id = $1`, created.ID); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()

	// (1) Create must hand the material back, or callers that reassign the
	// struct lose it.
	if created.CertificatePEM != certPEM || created.PrivateKeyPEM != keyPEM {
		t.Errorf("Create returned a certificate without its material: pem=%d key=%d",
			len(created.CertificatePEM), len(created.PrivateKeyPEM))
	}

	// (2) A re-read must find it stored.
	reread, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get certificate: %v", err)
	}
	if reread == nil {
		t.Fatal("certificate disappeared after create")
	}
	if reread.CertificatePEM != certPEM {
		t.Errorf("stored certificate_pem = %q, want the uploaded certificate", reread.CertificatePEM)
	}
	if reread.PrivateKeyPEM != keyPEM {
		t.Errorf("stored private_key_pem = %q, want the uploaded key", reread.PrivateKeyPEM)
	}
	if len(reread.AcmeAccount) == 0 || string(reread.AcmeAccount) == "{}" {
		t.Errorf("GetByID must load acme_account (got %q): without it every renewal registers a new ACME account", reread.AcmeAccount)
	}

	// (3) A metadata-only writer holding a PEM-less struct — exactly what the
	// cache used to hand out — must not touch the material.
	blank := &model.Certificate{ID: created.ID, Status: model.CertStatusRenewing, AutoRenew: false}
	if err := repo.Update(ctx, blank); err != nil {
		t.Fatalf("update certificate: %v", err)
	}
	afterUpdate, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get certificate after update: %v", err)
	}
	if afterUpdate.CertificatePEM != certPEM || afterUpdate.PrivateKeyPEM != keyPEM {
		t.Errorf("Update destroyed key material: pem=%d key=%d",
			len(afterUpdate.CertificatePEM), len(afterUpdate.PrivateKeyPEM))
	}
	if string(afterUpdate.AcmeAccount) != `{"account": "roundtrip"}` && string(afterUpdate.AcmeAccount) != `{"account":"roundtrip"}` {
		t.Errorf("Update changed acme_account to %q", afterUpdate.AcmeAccount)
	}
	if afterUpdate.Status != model.CertStatusRenewing {
		t.Errorf("Update did not apply the status change: %q", afterUpdate.Status)
	}

	// (4) The material writer refuses to store emptiness.
	if err := repo.UpdateWithMaterial(ctx, blank); err == nil {
		t.Error("UpdateWithMaterial accepted a certificate with no material")
	}
	if err := repo.RestoreMaterial(ctx, created.ID, "", "", ""); err == nil {
		t.Error("RestoreMaterial accepted empty material")
	}

	// (5) Self-heal writes only the material back.
	if err := repo.RestoreMaterial(ctx, created.ID, certPEM+"v2", keyPEM+"v2", issuerPEM); err != nil {
		t.Fatalf("restore material: %v", err)
	}
	restored, err := repo.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get certificate after restore: %v", err)
	}
	if restored.CertificatePEM != certPEM+"v2" || restored.PrivateKeyPEM != keyPEM+"v2" {
		t.Error("RestoreMaterial did not persist the recovered material")
	}
	if restored.Status != model.CertStatusRenewing {
		t.Errorf("RestoreMaterial changed status to %q", restored.Status)
	}
}

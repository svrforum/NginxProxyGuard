package repository

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// A certificate keeps the key type it was created with (#364), and a row
// written without one, as every row before, is RSA 2048.
func TestCertificateKeepsItsKeyType(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE dns_providers (
			id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
			name character varying(100) NOT NULL,
			provider_type character varying(50) NOT NULL,
			is_default boolean DEFAULT false NOT NULL,
			created_at timestamp with time zone DEFAULT now(),
			updated_at timestamp with time zone DEFAULT now()
		)`,
		`CREATE TABLE certificates (
		    id uuid DEFAULT gen_random_uuid() NOT NULL,
		    domain_names text[] NOT NULL,
		    expires_at timestamp with time zone,
		    certificate_path character varying(512),
		    private_key_path character varying(512),
		    provider character varying(50) DEFAULT 'letsencrypt'::character varying,
		    created_at timestamp with time zone DEFAULT now(),
		    updated_at timestamp with time zone DEFAULT now(),
		    dns_provider_id uuid,
		    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
		    acme_account jsonb DEFAULT '{}'::jsonb,
		    auto_renew boolean DEFAULT true NOT NULL,
		    renewal_attempted_at timestamp with time zone,
		    issued_at timestamp with time zone,
		    error_message text,
		    certificate_pem text,
		    private_key_pem text,
		    issuer_certificate_pem text,
		    key_type character varying(10) DEFAULT 'rsa2048'::character varying NOT NULL
		)`,
	)
	repo := NewCertificateRepository(&database.DB{DB: db})
	ctx := context.Background()

	for keyType, want := range map[string]string{
		model.CertKeyTypeEC384: model.CertKeyTypeEC384,
		"":                     model.CertKeyTypeRSA2048,
	} {
		created, err := repo.Create(ctx, &model.Certificate{
			DomainNames: []string{"key-" + want + ".example.com"},
			Provider:    model.CertProviderLetsEncrypt,
			Status:      model.CertStatusPending,
			KeyType:     keyType,
		})
		if err != nil {
			t.Fatalf("create with %q: %v", keyType, err)
		}
		if created.KeyType != want {
			t.Errorf("create with %q returned %q, want %q", keyType, created.KeyType, want)
		}
		got, err := repo.GetByID(ctx, created.ID)
		if err != nil || got == nil {
			t.Fatalf("get: %v", err)
		}
		if got.KeyType != want {
			t.Errorf("read back %q, want %q", got.KeyType, want)
		}
	}
}

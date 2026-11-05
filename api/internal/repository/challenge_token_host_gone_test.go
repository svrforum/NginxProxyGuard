package repository

import (
	"context"
	"errors"
	"testing"
)

// A proxy host deleted between VerifyCaptcha's lookup and the token insert
// used to come back as a bare foreign-key failure, a 500 (#356). CreateToken
// now names it, so the service can answer 404.
func TestCreateTokenNamesAProxyHostThatIsGone(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE proxy_hosts (id uuid PRIMARY KEY)`,
		`CREATE TABLE challenge_tokens (
			id uuid DEFAULT gen_random_uuid() NOT NULL,
			proxy_host_id uuid REFERENCES proxy_hosts(id) ON DELETE CASCADE,
			token_hash character varying(64) NOT NULL,
			client_ip character varying(45) NOT NULL,
			user_agent text,
			challenge_reason character varying(255),
			issued_at timestamp with time zone DEFAULT now(),
			expires_at timestamp with time zone NOT NULL,
			use_count integer DEFAULT 0,
			last_used_at timestamp with time zone,
			revoked boolean DEFAULT false,
			revoked_at timestamp with time zone,
			revoked_reason character varying(255)
		)`,
		`INSERT INTO proxy_hosts (id) VALUES ('00000000-0000-4000-8000-000000000001')`,
	)
	repo := NewChallengeRepository(db)
	ctx := context.Background()

	live := "00000000-0000-4000-8000-000000000001"
	if _, err := repo.CreateToken(ctx, &live, "token-live", "192.0.2.10", "test", "geo", 60); err != nil {
		t.Fatalf("token for an existing host: %v", err)
	}

	gone := "00000000-0000-4000-8000-000000000002"
	if _, err := repo.CreateToken(ctx, &gone, "token-gone", "192.0.2.10", "test", "geo", 60); !errors.Is(err, ErrTokenHostGone) {
		t.Fatalf("token for a deleted host: err = %v, want ErrTokenHostGone", err)
	}

	// A global token names no host, so the foreign key never refuses it.
	if _, err := repo.CreateToken(ctx, nil, "token-global", "192.0.2.10", "test", "geo", 60); err != nil {
		t.Fatalf("global token: %v", err)
	}
}

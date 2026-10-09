package repository

import (
	"context"
	"testing"
)

// Expired challenge tokens were never deleted: the cleanup had no caller. It
// now runs from the session cleanup and deletes in 5000-row batches, and it
// must remove exactly the tokens that expired more than a day ago — across
// several batches — and nothing else.
func TestCleanupExpiredTokensDeletesOnlyLongExpiredTokens(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE challenge_tokens (
			id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
			proxy_host_id uuid,
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
		`CREATE INDEX idx_challenge_tokens_expires ON challenge_tokens USING btree (expires_at)`,
		// More than two full batches expired over a day ago: all go.
		`INSERT INTO challenge_tokens (token_hash, client_ip, expires_at)
		 SELECT md5('old' || i), '192.0.2.1', now() - interval '2 days' - make_interval(secs => i)
		 FROM generate_series(1, 11000) i`,
		// Expired less than a day ago, and still valid: both stay.
		`INSERT INTO challenge_tokens (token_hash, client_ip, expires_at)
		 SELECT md5('recent' || i), '192.0.2.2', now() - interval '12 hours'
		 FROM generate_series(1, 500) i`,
		`INSERT INTO challenge_tokens (token_hash, client_ip, expires_at)
		 SELECT md5('valid' || i), '192.0.2.3', now() + interval '1 hour'
		 FROM generate_series(1, 500) i`,
	)
	repo := NewChallengeRepository(db)

	count := func() (all, longExpired int) {
		t.Helper()
		if err := db.QueryRow(`
			SELECT count(*), count(*) FILTER (WHERE expires_at < now() - interval '1 day')
			FROM challenge_tokens`).Scan(&all, &longExpired); err != nil {
			t.Fatalf("count tokens: %v", err)
		}
		return all, longExpired
	}

	// A run whose context has already ended deletes nothing and says so.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := repo.CleanupExpiredTokens(cancelled); err == nil || n != 0 {
		t.Fatalf("cancelled run = (%d, %v), want (0, an error)", n, err)
	}
	if all, _ := count(); all != 12000 {
		t.Fatalf("cancelled run left %d tokens, want all 12000", all)
	}

	n, err := repo.CleanupExpiredTokens(context.Background())
	if err != nil {
		t.Fatalf("CleanupExpiredTokens: %v", err)
	}
	if n != 11000 {
		t.Errorf("removed %d tokens, want 11000", n)
	}
	if all, longExpired := count(); all != 1000 || longExpired != 0 {
		t.Errorf("left %d tokens (%d expired over a day ago), want 1000 (0)", all, longExpired)
	}

	if n, err := repo.CleanupExpiredTokens(context.Background()); err != nil || n != 0 {
		t.Errorf("second run = (%d, %v), want (0, nil)", n, err)
	}
}

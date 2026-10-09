package repository

import (
	"strings"
	"testing"
)

// The banned-IP traffic window is on timestamp, which the hypertable is not
// partitioned on. The created_at bound is what lets TimescaleDB leave out the
// chunks before the window, and it must stay a day wider than the window so no
// row inside it is lost.
func TestBannedIPTrafficQueryBoundsCreatedAt(t *testing.T) {
	for _, want := range []string{
		"timestamp > now() - make_interval(days => $2)",
		"created_at > now() - make_interval(days => $2 + 1)",
	} {
		if !strings.Contains(bannedIPTrafficQuery, want) {
			t.Errorf("bannedIPTrafficQuery lost %q", want)
		}
	}
}

// Every row inside the timestamp window is still counted, including one whose
// insert time trails its timestamp (clock skew between the proxy and the
// database), and nothing outside it.
func TestBannedIPTrafficQueryKeepsTheWindow(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE logs_partitioned (
			client_ip inet, host text, request_uri text, block_reason text DEFAULT 'none',
			geo_country text, geo_country_code text,
			"timestamp" timestamptz NOT NULL, created_at timestamptz NOT NULL)`,
		`INSERT INTO logs_partitioned (client_ip, host, request_uri, "timestamp", created_at) VALUES
			('192.0.2.10', 'a.example.com', '/x', now() - interval '2 days', now() - interval '2 days' + interval '5 seconds'),
			('192.0.2.10', 'a.example.com', '/x', now() - interval '6 days 23 hours', now() - interval '6 days 23 hours' + interval '30 seconds'),
			('192.0.2.10', 'a.example.com', '/y', now() - interval '1 hour', now() - interval '2 hours'),
			('192.0.2.10', 'a.example.com', '/old', now() - interval '8 days', now() - interval '8 days'),
			('192.0.2.10', 'a.example.com', '/__npg_canary?n=1', now() - interval '1 hour', now() - interval '1 hour'),
			('192.0.2.11', 'b.example.com', '/z', now() - interval '1 hour', now() - interval '1 hour')`,
	)
	var total, blocked int
	var a, b, c, d, e, f interface{}
	if err := db.QueryRow(bannedIPTrafficQuery, "192.0.2.10", 7).Scan(&total, &blocked, &a, &b, &c, &d, &e, &f); err != nil {
		t.Fatalf("run bannedIPTrafficQuery: %v", err)
	}
	if total != 3 {
		t.Errorf("counted %d requests for the 7-day window, want 3", total)
	}
}

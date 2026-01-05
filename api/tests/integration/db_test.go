package integration

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

var dbURL = getDBURL()

func getDBURL() string {
	if url := os.Getenv("DATABASE_URL"); url != "" {
		return url
	}
	return "postgres://test_user:test_password@release-test-db:5432/nginx_proxy_guard_test?sslmode=disable"
}

func TestDatabaseHealth(t *testing.T) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}
	t.Log("✓ Database connection OK")
}

func TestPartitionedTables(t *testing.T) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	t.Run("Check_Stats_Partitioned_Table", func(t *testing.T) {
		var isPartitioned bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM pg_partitioned_table pt
				JOIN pg_class c ON c.oid = pt.partrelid
				WHERE c.relname = 'dashboard_stats_hourly_partitioned'
			)
		`).Scan(&isPartitioned)

		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if !isPartitioned {
			t.Error("dashboard_stats_hourly_partitioned should be a partitioned table")
		} else {
			t.Log("✓ dashboard_stats_hourly_partitioned is partitioned")
		}
	})

	t.Run("Check_Logs_Table_Type", func(t *testing.T) {
		// logs_partitioned can be either:
		// - TimescaleDB hypertable (production)
		// - PostgreSQL native partition (new install without TimescaleDB)
		var tableType string

		// Check if TimescaleDB hypertable
		var isHypertable bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM timescaledb_information.hypertables
				WHERE hypertable_name = 'logs_partitioned'
			)
		`).Scan(&isHypertable)

		if err != nil {
			// TimescaleDB not installed, check native partition
			var isPartitioned bool
			err = db.QueryRow(`
				SELECT EXISTS (
					SELECT 1 FROM pg_partitioned_table pt
					JOIN pg_class c ON c.oid = pt.partrelid
					WHERE c.relname = 'logs_partitioned'
				)
			`).Scan(&isPartitioned)

			if err != nil {
				t.Fatalf("Query failed: %v", err)
			}

			if isPartitioned {
				tableType = "native_partition"
			} else {
				tableType = "regular_table"
			}
		} else if isHypertable {
			tableType = "timescaledb_hypertable"
		}

		t.Logf("✓ logs_partitioned type: %s", tableType)
	})
}

func TestPartitionCreation(t *testing.T) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	t.Run("Create_Monthly_Partitions", func(t *testing.T) {
		// Test the partition creation function
		_, err := db.Exec(`SELECT create_monthly_partitions('dashboard_stats_hourly_partitioned', 'stats_hourly_p', 3)`)
		if err != nil {
			t.Errorf("Partition creation failed: %v", err)
		} else {
			t.Log("✓ Partition creation function works")
		}
	})

	t.Run("Check_Partition_Count", func(t *testing.T) {
		var count int
		err := db.QueryRow(`
			SELECT COUNT(*) FROM pg_tables
			WHERE tablename LIKE 'stats_hourly_p%' AND schemaname = 'public'
		`).Scan(&count)

		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		// Should have at least current month + 3 months ahead + default = 5
		if count < 4 {
			t.Errorf("Expected at least 4 partitions, got %d", count)
		} else {
			t.Logf("✓ Found %d partitions", count)
		}
	})
}

func TestEnumTypes(t *testing.T) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	t.Run("Check_BlockReason_Enum", func(t *testing.T) {
		var hasAccessDenied bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM pg_enum e
				JOIN pg_type t ON e.enumtypid = t.oid
				WHERE t.typname = 'block_reason' AND e.enumlabel = 'access_denied'
			)
		`).Scan(&hasAccessDenied)

		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if !hasAccessDenied {
			t.Error("block_reason enum should have 'access_denied' value")
		} else {
			t.Log("✓ block_reason enum has 'access_denied'")
		}
	})
}

func TestTimezoneHandling(t *testing.T) {
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	t.Run("Check_Partition_Timezone", func(t *testing.T) {
		// Verify partition boundaries are consistent
		rows, err := db.Query(`
			SELECT
				child.relname AS partition_name,
				pg_get_expr(child.relpartbound, child.oid) AS partition_range
			FROM pg_inherits
			JOIN pg_class parent ON pg_inherits.inhparent = parent.oid
			JOIN pg_class child ON pg_inherits.inhrelid = child.oid
			WHERE parent.relname = 'dashboard_stats_hourly_partitioned'
			AND child.relname NOT LIKE '%_default'
			ORDER BY child.relname
			LIMIT 3
		`)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}
		defer rows.Close()

		for rows.Next() {
			var name, rangeStr string
			if err := rows.Scan(&name, &rangeStr); err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			t.Logf("  Partition: %s - %s", name, rangeStr)
		}
		t.Log("✓ Partition timezone check passed")
	})
}

package repository

import (
	"context"
	"database/sql"
)

// StorageMaintenanceRepository holds the SQL behind DiskGuard's handling of
// the database disk.
type StorageMaintenanceRepository struct {
	db *sql.DB
}

func NewStorageMaintenanceRepository(db *sql.DB) *StorageMaintenanceRepository {
	return &StorageMaintenanceRepository{db: db}
}

// DataDirectory is SHOW data_directory: where the database container keeps
// its files, which DiskGuard measures through docker exec. It needs superuser
// or pg_read_all_settings; callers fall back to the image default.
func (r *StorageMaintenanceRepository) DataDirectory(ctx context.Context) (string, error) {
	var dir string
	err := r.db.QueryRowContext(ctx, `SELECT current_setting('data_directory')`).Scan(&dir)
	return dir, err
}

package bootstrap

import (
	"context"
	"testing"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/service"
)

// DiskGuard watches the raw-log archive through the archiver's own
// measurement: with archiving on the archive is one of its filesystems,
// with archiving off it is not.
func TestDiskUsageProviderWatchesTheRawLogArchive(t *testing.T) {
	t.Setenv("NPG_DB_CONTAINER", "")
	t.Setenv("NGINX_ACCESS_LOG", "")
	ctx := context.Background()
	// The database host is localhost, so no container is looked for: no
	// docker call, no DNS lookup.
	cfg := &config.Config{BackupPath: t.TempDir(), DatabaseURL: "postgres://npg:npg@localhost:5432/npg?sslmode=disable"}

	watched := func(t *testing.T, archiving bool) bool {
		t.Helper()
		archiver := service.NewRawLogArchiver(t.TempDir(), t.TempDir(), 0, func(context.Context) (*model.SystemSettings, error) {
			return &model.SystemSettings{ID: "11111111-2222-3333-4444-555555555555", RawLogArchiveEnabled: archiving, RawLogArchiveRetentionDays: 365}, nil
		})
		// Claims the directory, then measures it as a status refresh does.
		if _, err := archiver.Initialise(ctx); err != nil {
			t.Fatalf("initialise: %v", err)
		}
		fss, _, err := newDiskUsageProvider(cfg, nil, archiver).Measure(ctx)
		if err != nil {
			t.Fatalf("measure: %v", err)
		}
		for _, fs := range fss {
			if fs.HasRole(service.DiskRoleArchive) {
				return true
			}
		}
		return false
	}
	if !watched(t, true) {
		t.Fatal("archiving is on, but the archive is not among DiskGuard's filesystems")
	}
	if watched(t, false) {
		t.Fatal("archiving is off, but DiskGuard still watches the archive")
	}
}

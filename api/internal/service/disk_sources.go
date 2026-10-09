package service

import (
	"context"

	"github.com/shirou/gopsutil/v3/disk"

	"nginx-proxy-guard/internal/model"
)

// How the dashboard's Disk tile and system_health read DiskGuard (D1).

// diskPrimarySource is DiskGuard as the stats collector sees it.
type diskPrimarySource interface {
	Primary() (FSUsage, bool)
}

// diskStatusSource is DiskGuard as the dashboard sees it.
type diskStatusSource interface {
	diskPrimarySource
	Status(ctx context.Context) *model.StorageStatus
}

// primaryDiskUsage returns what NPG's single Disk figure describes: the
// database's filesystem when DiskGuard measures it — the disk whose filling
// takes NPG down — else this container's "/", Docker's storage, which is all
// it described before DiskGuard. On a single-disk install both are the same
// disk, so the numbers do not change; on a split install the history chart,
// the digest's Disk line and the growth estimate now follow the database.
func primaryDiskUsage(src diskPrimarySource) (pct float64, total, used uint64, path string, ok bool) {
	if src != nil {
		if fs, found := src.Primary(); found {
			if !fs.HasRole(DiskRoleDB) {
				// Docker's storage: the numbers are this container's "/",
				// whichever role happens to name the shared filesystem.
				return fs.UsedPercent, fs.Total, fs.Used, "/", true
			}
			return fs.UsedPercent, fs.Total, fs.Used, fs.Path, true
		}
	}
	if d, err := disk.Usage("/"); err == nil {
		return d.UsedPercent, d.Total, d.Used, "/", true
	}
	return 0, 0, 0, "", false
}

// SetDiskSource wires DiskGuard into the stats collector, which writes
// system_health's disk_* columns. Call before Start.
func (sc *StatsCollector) SetDiskSource(d diskPrimarySource) { sc.diskSource = d }

// SetDiskSource wires DiskGuard into the dashboard: the Disk tile and the
// storage object of GET /dashboard.
func (s *SettingsService) SetDiskSource(d diskStatusSource) { s.diskSource = d }

// storageStatus is GET /dashboard's live storage object; nil without DiskGuard
// or before its first measurement.
func (s *SettingsService) storageStatus(ctx context.Context) *model.StorageStatus {
	if s.diskSource == nil {
		return nil
	}
	return s.diskSource.Status(ctx)
}

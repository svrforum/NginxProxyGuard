package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Disk metrics (DiskGuard, D1-D3). Kept out of metrics.go and registered by
// their own RegisterDiskMetrics, called where DiskGuard is wired, so a
// disabled guard exports nothing.
//
// The fs label is the filesystem's key — its most important role (db,
// nginx_logs, archive, backups, docker) — never a path, so the label set stays
// small and says nothing about the host's layout.
var (
	// DiskUsedRatio is used/(used+avail), as df prints it, from 0 to 1.
	DiskUsedRatio = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "npg_disk_used_ratio",
		Help: "Used share of a filesystem NPG writes to (used/(used+avail), as df computes it).",
	}, []string{"fs"})

	// DiskLevel is the alert level: 0 ok, 1 low, 2 critical.
	DiskLevel = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "npg_disk_level",
		Help: "Disk alert level of a filesystem NPG writes to: 0 ok, 1 low, 2 critical.",
	}, []string{"fs"})
)

var registerDiskOnce sync.Once

// RegisterDiskMetrics adds the disk metrics to the default registry. Safe to
// call more than once.
func RegisterDiskMetrics() {
	registerDiskOnce.Do(func() {
		prometheus.MustRegister(DiskUsedRatio, DiskLevel)
	})
}

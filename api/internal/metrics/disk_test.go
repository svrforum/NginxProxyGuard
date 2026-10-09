package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRegisterDiskMetricsIsIdempotent(t *testing.T) {
	RegisterDiskMetrics()
	RegisterDiskMetrics() // must not panic on double registration
}

func TestDiskGaugesCarryOnlyTheFilesystemKey(t *testing.T) {
	DiskUsedRatio.WithLabelValues("db").Set(0.91)
	DiskLevel.WithLabelValues("db").Set(2)
	if got := testutil.ToFloat64(DiskUsedRatio.WithLabelValues("db")); got != 0.91 {
		t.Fatalf("npg_disk_used_ratio = %v", got)
	}
	if got := testutil.ToFloat64(DiskLevel.WithLabelValues("db")); got != 2 {
		t.Fatalf("npg_disk_level = %v", got)
	}
	DiskUsedRatio.DeleteLabelValues("db")
	DiskLevel.DeleteLabelValues("db")
	if n := testutil.CollectAndCount(DiskUsedRatio); n != 0 {
		t.Fatalf("%d series left after delete", n)
	}
}

package cache

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// The in-process cache takes a slice of the memory the API is allowed to use,
// so that an install without Valkey cannot grow the cache into an OOM kill.
//
// The ceiling is the tightest of GOMEMLIMIT, the cgroup limit (v2, then v1)
// and the machine's MemTotal. The cache gets 1/32 of it, kept between 4 MiB
// and 64 MiB. Measured on a live install, everything NPG caches (settings,
// rules, dashboard, autocomplete lists) is well under 1 MiB; the largest
// values are subscription blocklists, a few MiB at most. 64 MiB therefore
// leaves room for those while staying a small fraction of the API's footprint,
// and a 128 MiB container still gets 4 MiB. NPG_LOCAL_CACHE_MAX_MB overrides
// the result.
const (
	localBudgetDivisor = 32
	localBudgetMin     = 4 << 20
	localBudgetMax     = 64 << 20
	// localBudgetUnknown is used when no ceiling can be read (not Linux, no
	// /proc). It is the midpoint of the range above.
	localBudgetUnknown = 32 << 20
)

// memorySources are the files the ceiling is read from. Tests point them at
// temporary files.
var memorySources = struct {
	cgroupV2Max string
	cgroupV1Max string
	meminfo     string
}{
	cgroupV2Max: "/sys/fs/cgroup/memory.max",
	cgroupV1Max: "/sys/fs/cgroup/memory/memory.limit_in_bytes",
	meminfo:     "/proc/meminfo",
}

// memoryCeiling returns the tightest memory limit the process runs under and
// where it came from, or 0 when none could be read.
func memoryCeiling() (uint64, string) {
	var limit uint64
	var source string
	consider := func(v uint64, from string) {
		if v > 0 && (limit == 0 || v < limit) {
			limit, source = v, from
		}
	}

	if v := debug.SetMemoryLimit(-1); v > 0 && v < math.MaxInt64 {
		consider(uint64(v), "GOMEMLIMIT")
	}
	if v, ok := readCgroupLimit(memorySources.cgroupV2Max); ok {
		consider(v, "cgroup memory.max")
	}
	if v, ok := readCgroupLimit(memorySources.cgroupV1Max); ok {
		consider(v, "cgroup memory.limit_in_bytes")
	}
	if v, ok := readMemTotal(memorySources.meminfo); ok {
		consider(v, "MemTotal")
	}
	return limit, source
}

// readCgroupLimit parses a cgroup memory limit file. "max" (v2) and the
// page-rounded MaxInt64 that v1 reports for "no limit" both mean unlimited.
func readCgroupLimit(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 || v >= 1<<62 {
		return 0, false
	}
	return v, true
}

func readMemTotal(path string) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil || kb == 0 {
				return 0, false
			}
			return kb * 1024, true
		}
	}
	return 0, false
}

// LocalCacheBudget returns how many bytes the in-process cache may hold and a
// human-readable account of how that was decided. overrideMB is
// NPG_LOCAL_CACHE_MAX_MB: negative means "decide", 0 turns the cache off.
func LocalCacheBudget(overrideMB int) (uint64, string) {
	if overrideMB == 0 {
		return 0, "disabled by NPG_LOCAL_CACHE_MAX_MB=0"
	}
	if overrideMB > 0 {
		return uint64(overrideMB) << 20, fmt.Sprintf("NPG_LOCAL_CACHE_MAX_MB=%d", overrideMB)
	}
	ceiling, source := memoryCeiling()
	if ceiling == 0 {
		return localBudgetUnknown, "no memory limit readable; default"
	}
	budget := ceiling / localBudgetDivisor
	if budget < localBudgetMin {
		budget = localBudgetMin
	}
	if budget > localBudgetMax {
		budget = localBudgetMax
	}
	return budget, fmt.Sprintf("1/%d of %s %s, kept within %s-%s",
		localBudgetDivisor, formatBytes(ceiling), source, formatBytes(localBudgetMin), formatBytes(localBudgetMax))
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", b>>10)
	}
}

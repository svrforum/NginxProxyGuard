package bootstrap

import (
	"log"
	"os"
	"strings"
	"time"

	"nginx-proxy-guard/internal/service"
)

// rawLogReclaimOptions reads NPG_RAW_RECLAIM_PAUSE: the pause between two days
// of the raw log reclaim, so ingest and queries get the disk back (default
// 30s; 0 turns it off). Like DiskGuard's knobs it is environment only.
func rawLogReclaimOptions() service.RawLogReclaimOptions {
	opts := service.DefaultRawLogReclaimOptions()
	if v := strings.TrimSpace(os.Getenv("NPG_RAW_RECLAIM_PAUSE")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			opts.Pause = d
		} else {
			log.Printf("[RawLogReclaim] ignoring NPG_RAW_RECLAIM_PAUSE=%q: not a duration", v)
		}
	}
	return opts
}
